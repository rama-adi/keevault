package client

import (
	"context"

	"github.com/coder/websocket"

	"github.com/ramaadi/env-vault/apps/env-client/internal/protocol"
	"github.com/ramaadi/env-vault/apps/env-client/internal/run"
	"github.com/ramaadi/env-vault/apps/env-client/internal/vaultcrypto"
)

// handleApproved opens the key envelope, decrypts every secret and
// acknowledges the payload. frame must be the exact bytes received, because
// payloadDigest covers them.
func (s *Session) handleApproved(ctx context.Context, conn *websocket.Conn, frame []byte, m protocol.Approved) error {
	if s.bootID == "" {
		s.bootID = m.BootID
	}
	if m.BootID != s.bootID {
		return exitf(ExitProtocol, "approval is for a different boot request")
	}
	if s.approvedEnvironmentID != "" && m.EnvironmentID != s.approvedEnvironmentID {
		return exitf(ExitProtocol, "approval environmentId changed from %s to %s", s.approvedEnvironmentID, m.EnvironmentID)
	}
	digest := vaultcrypto.SHA256Hex(frame)
	if s.approvedDigest != "" && digest != s.approvedDigest {
		return exitf(ExitProtocol, "vault resent boot.approved with a different payload for the same boot")
	}
	s.log.Infof("approval received")

	secrets, err := s.decrypt(m)
	if err != nil {
		return err
	}
	s.wipeSecrets()
	s.secrets = secrets
	s.approvedEnvironmentID = m.EnvironmentID
	s.approvedDigest = digest
	s.log.Infof("environment decrypted (%d values)", len(secrets))

	if err := s.send(ctx, conn, protocol.Received{
		Type:          protocol.TypeReceived,
		BootID:        s.bootID,
		PayloadDigest: digest,
	}); err != nil {
		return err
	}
	s.acked = true
	return nil
}

func (s *Session) decrypt(m protocol.Approved) ([]run.Secret, error) {
	serverPub, err := vaultcrypto.DecodeB64uLen(m.KeyEnvelope.ServerPublicKey, 32)
	if err != nil {
		return nil, exitf(ExitProtocol, "keyEnvelope.serverPublicKey: %v", err)
	}
	salt, err := vaultcrypto.DecodeB64uLen(m.KeyEnvelope.Salt, 32)
	if err != nil {
		return nil, exitf(ExitProtocol, "keyEnvelope.salt: %v", err)
	}
	nonce, err := vaultcrypto.DecodeB64uLen(m.KeyEnvelope.Nonce, 12)
	if err != nil {
		return nil, exitf(ExitProtocol, "keyEnvelope.nonce: %v", err)
	}
	wrapped, err := vaultcrypto.DecodeB64uLen(m.KeyEnvelope.Ciphertext, 48)
	if err != nil {
		return nil, exitf(ExitProtocol, "keyEnvelope.ciphertext: %v", err)
	}
	serverFP, err := vaultcrypto.Fingerprint(serverPub)
	if err != nil {
		return nil, exitf(ExitProtocol, "%v", err)
	}

	info := vaultcrypto.BootEnvelopeInfo(s.bootID, m.EnvironmentID, m.EnvironmentKeyVersion, s.clientFP, serverFP)
	dek, err := vaultcrypto.OpenBootEnvelope(s.encPriv, vaultcrypto.KeyEnvelope{
		ServerPublicKey: serverPub,
		Salt:            salt,
		Nonce:           nonce,
		Ciphertext:      wrapped,
	}, info)
	if err != nil {
		return nil, exitf(ExitProtocol, "cannot open the environment key envelope: %v", err)
	}
	defer vaultcrypto.Zero(dek)

	secrets := make([]run.Secret, 0, len(m.Secrets))
	seen := make(map[string]struct{}, len(m.Secrets))
	for i, record := range m.Secrets {
		if record.EnvKeyVersion != m.EnvironmentKeyVersion {
			zeroAll(secrets)
			return nil, exitf(ExitProtocol, "secret %d was encrypted under environment key version %d, envelope carries version %d", i, record.EnvKeyVersion, m.EnvironmentKeyVersion)
		}
		if !run.ValidName(record.Name) {
			zeroAll(secrets)
			return nil, exitf(ExitProtocol, "secret %d has a name that is not a POSIX environment name", i)
		}
		if _, dup := seen[record.Name]; dup {
			zeroAll(secrets)
			return nil, exitf(ExitProtocol, "secret %d repeats a name already present in this payload", i)
		}
		seen[record.Name] = struct{}{}

		secretNonce, err := vaultcrypto.DecodeB64uLen(record.Nonce, 12)
		if err != nil {
			zeroAll(secrets)
			return nil, exitf(ExitProtocol, "secret %d nonce: %v", i, err)
		}
		ciphertext, err := vaultcrypto.DecodeB64u(record.Ciphertext)
		if err != nil {
			zeroAll(secrets)
			return nil, exitf(ExitProtocol, "secret %d ciphertext: %v", i, err)
		}
		aad := vaultcrypto.SecretAAD(m.ProjectID, m.EnvironmentID, record.ID, record.Name, record.Version, record.EnvKeyVersion)
		plaintext, err := vaultcrypto.Open(dek, secretNonce, ciphertext, aad)
		if err != nil {
			zeroAll(secrets)
			return nil, exitf(ExitProtocol, "secret %d failed authentication", i)
		}
		secrets = append(secrets, run.Secret{Name: record.Name, Value: plaintext})
	}
	return secrets, nil
}

func zeroAll(secrets []run.Secret) {
	for _, s := range secrets {
		vaultcrypto.Zero(s.Value)
	}
}

func (s *Session) wipeSecrets() {
	zeroAll(s.secrets)
	s.secrets = nil
}

func (s *Session) wipeKeys() {
	if s.signPriv != nil {
		vaultcrypto.Zero(s.signPriv)
		s.signPriv = nil
	}
	s.encPriv = nil
}

// launch builds the child environment, wipes the plaintext buffers and
// replaces this process with the target command.
func (s *Session) launch() error {
	if !s.consumed {
		return exitf(ExitProtocol, "vault never confirmed the acknowledgement")
	}
	path, err := run.LookPath(s.cfg.Command[0])
	if err != nil {
		s.wipeSecrets()
		return exitf(ExitConfig, "%v", err)
	}
	env, err := run.BuildEnv(s.cfg.Environ, s.secrets)
	if err != nil {
		s.wipeSecrets()
		return exitf(ExitProtocol, "cannot build the child environment: %v", err)
	}
	s.wipeSecrets()
	s.wipeKeys()
	s.log.Infof("starting application")
	if err := s.cfg.Exec(path, s.cfg.Command, env); err != nil {
		return exitf(ExitProtocol, "%v", err)
	}
	return nil
}
