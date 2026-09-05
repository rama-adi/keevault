package client_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ramaadi/env-vault/apps/env-client/internal/protocol"
	vc "github.com/ramaadi/env-vault/apps/env-client/internal/vaultcrypto"
)

// mode selects how the fake vault behaves after the first hello.
type mode int

const (
	// modeApprove drops the first connection, then approves on the resumed one.
	modeApprove mode = iota
	// modeDecline declines on the first connection.
	modeDecline
	// modeWrongSignature verifies the resume proof against another key, so the
	// proof fails and the connection is closed with 4401.
	modeWrongSignature
)

const (
	testToken         = "vlt_boot_01K4M4X31X2Z5G9C7Q8D3E6F4G.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	testBootID        = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4G"
	testProjectID     = "proj_01K4M4X2ZQ0V3E9A7N6B5C4D3E"
	testEnvironmentID = "env_01K4M4X30W1Y4F8B6P7C2D5E3F"
	testEnvKeyVersion = 4
)

type plainSecret struct {
	id      string
	name    string
	value   string
	version int
}

var testSecrets = []plainSecret{
	{id: "sec_01K4M4X3A0000000000000001", name: "DATABASE_URL", value: "postgres://vault:hunter2@db/app", version: 3},
	{id: "sec_01K4M4X3A0000000000000002", name: "API_KEY", value: "sk-live-4f8b6p7c2d5e3f", version: 1},
}

// fakeVault is a minimal server side of the bootstrap protocol. It does real
// crypto so the client is exercised end to end.
type fakeVault struct {
	t    *testing.T
	mode mode

	mu             sync.Mutex
	connections    int
	signingPub     ed25519.PublicKey
	clientEncPub   []byte
	approvedDigest string
	receivedDigest string
	consumed       bool
	proofAccepted  bool
	unauthorized   int
}

func newFakeVault(t *testing.T, m mode) (*fakeVault, *httptest.Server) {
	t.Helper()
	f := &fakeVault{t: t, mode: m}
	server := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/bootstrap/v1" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		f.mu.Lock()
		f.unauthorized++
		f.mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	f.mu.Lock()
	f.connections++
	n := f.connections
	f.mu.Unlock()

	if n == 1 {
		f.first(ctx, conn)
		return
	}
	f.resumed(ctx, conn)
}

func (f *fakeVault) first(ctx context.Context, conn *websocket.Conn) {
	msg, _, err := f.read(ctx, conn)
	if err != nil {
		f.t.Errorf("fake vault: read hello: %v", err)
		return
	}
	hello, ok := msg.(protocol.Hello)
	if !ok {
		f.t.Errorf("fake vault: first frame was %s, want boot.hello", msg.MessageType())
		return
	}
	signing, err := vc.DecodeB64uLen(hello.SigningPublicKey, 32)
	if err != nil {
		f.t.Errorf("fake vault: signing key: %v", err)
		return
	}
	encryption, err := vc.DecodeB64uLen(hello.EncryptionPublicKey, 32)
	if err != nil {
		f.t.Errorf("fake vault: encryption key: %v", err)
		return
	}
	f.mu.Lock()
	f.signingPub = signing
	f.clientEncPub = encryption
	if f.mode == modeWrongSignature {
		other, _, err := vc.GenerateEd25519()
		if err != nil {
			f.mu.Unlock()
			f.t.Errorf("fake vault: %v", err)
			return
		}
		f.signingPub = other
	}
	f.mu.Unlock()

	if err := f.send(ctx, conn, protocol.Pending{
		Type:      protocol.TypePending,
		BootID:    testBootID,
		ExpiresAt: time.Now().Add(30 * time.Minute).UTC().Format(rfc3339Milli),
	}); err != nil {
		return
	}

	if f.mode == modeDecline {
		if err := f.send(ctx, conn, protocol.Declined{
			Type:   protocol.TypeDeclined,
			BootID: testBootID,
			Reason: "not this deployment",
		}); err != nil {
			return
		}
		conn.Close(protocol.CloseTerminal, "declined")
		return
	}

	// Drop the connection while the boot is still pending.
	conn.CloseNow()
}

func (f *fakeVault) resumed(ctx context.Context, conn *websocket.Conn) {
	msg, _, err := f.read(ctx, conn)
	if err != nil {
		return
	}
	resume, ok := msg.(protocol.Resume)
	if !ok {
		f.t.Errorf("fake vault: frame was %s, want boot.resume", msg.MessageType())
		return
	}
	if resume.BootID != testBootID {
		f.t.Errorf("fake vault: resume carried boot id %s", resume.BootID)
		return
	}

	challengeBytes, err := vc.RandomBytes(32)
	if err != nil {
		f.t.Errorf("fake vault: %v", err)
		return
	}
	challenge := vc.EncodeB64u(challengeBytes)
	if err := f.send(ctx, conn, protocol.Challenge{
		Type:      protocol.TypeChallenge,
		BootID:    testBootID,
		Challenge: challenge,
	}); err != nil {
		return
	}

	msg, _, err = f.read(ctx, conn)
	if err != nil {
		return
	}
	response, ok := msg.(protocol.ChallengeResponse)
	if !ok {
		f.t.Errorf("fake vault: frame was %s, want boot.challenge-response", msg.MessageType())
		return
	}
	signature, err := vc.DecodeB64uLen(response.Signature, 64)
	if err != nil {
		f.t.Errorf("fake vault: signature: %v", err)
		return
	}
	f.mu.Lock()
	signingPub := f.signingPub
	clientEncPub := f.clientEncPub
	f.mu.Unlock()

	if !vc.VerifyResume(signingPub, testBootID, challenge, signature) {
		_ = f.send(ctx, conn, protocol.Error{
			Type:    protocol.TypeError,
			Code:    protocol.CloseBadToken,
			Message: "resume proof did not verify",
		})
		conn.Close(protocol.CloseBadToken, "bad proof")
		return
	}
	f.mu.Lock()
	f.proofAccepted = true
	f.mu.Unlock()

	if err := f.send(ctx, conn, protocol.Resumed{
		Type:      protocol.TypeResumed,
		BootID:    testBootID,
		Status:    protocol.StatusApproved,
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(rfc3339Milli),
	}); err != nil {
		return
	}

	approved, err := f.buildApproved(clientEncPub)
	if err != nil {
		f.t.Errorf("fake vault: build approval: %v", err)
		return
	}
	frame, err := protocol.Encode(approved)
	if err != nil {
		f.t.Errorf("fake vault: encode approval: %v", err)
		return
	}
	f.mu.Lock()
	f.approvedDigest = vc.SHA256Hex(frame)
	f.mu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = conn.Write(writeCtx, websocket.MessageText, frame)
	cancel()
	if err != nil {
		return
	}

	msg, _, err = f.read(ctx, conn)
	if err != nil {
		return
	}
	received, ok := msg.(protocol.Received)
	if !ok {
		f.t.Errorf("fake vault: frame was %s, want boot.received", msg.MessageType())
		return
	}
	f.mu.Lock()
	f.receivedDigest = received.PayloadDigest
	match := received.PayloadDigest == f.approvedDigest
	f.mu.Unlock()
	if !match {
		_ = f.send(ctx, conn, protocol.Error{
			Type:    protocol.TypeError,
			Code:    protocol.CloseProtocolError,
			Message: "payload digest mismatch",
		})
		conn.Close(protocol.CloseProtocolError, "digest mismatch")
		return
	}

	if err := f.send(ctx, conn, protocol.Consumed{Type: protocol.TypeConsumed, BootID: testBootID}); err != nil {
		return
	}
	f.mu.Lock()
	f.consumed = true
	f.mu.Unlock()
	conn.Close(websocket.StatusNormalClosure, "")
}

const rfc3339Milli = "2006-01-02T15:04:05.000Z"

// buildApproved encrypts a real environment for the client's X25519 key.
func (f *fakeVault) buildApproved(clientEncPub []byte) (protocol.Approved, error) {
	var out protocol.Approved
	clientPub, err := vc.X25519PublicKey(clientEncPub)
	if err != nil {
		return out, err
	}
	serverPriv, err := vc.GenerateX25519()
	if err != nil {
		return out, err
	}
	clientFP, err := vc.Fingerprint(clientEncPub)
	if err != nil {
		return out, err
	}
	serverFP, err := vc.Fingerprint(serverPriv.PublicKey().Bytes())
	if err != nil {
		return out, err
	}
	dek, err := vc.RandomBytes(32)
	if err != nil {
		return out, err
	}
	salt, err := vc.RandomBytes(32)
	if err != nil {
		return out, err
	}
	nonce, err := vc.RandomBytes(12)
	if err != nil {
		return out, err
	}
	info := vc.BootEnvelopeInfo(testBootID, testEnvironmentID, testEnvKeyVersion, clientFP, serverFP)
	envelope, err := vc.SealBootEnvelope(serverPriv, clientPub, salt, nonce, dek, info)
	if err != nil {
		return out, err
	}

	records := make([]protocol.SecretRecord, 0, len(testSecrets))
	for _, s := range testSecrets {
		secretNonce, err := vc.RandomBytes(12)
		if err != nil {
			return out, err
		}
		aad := vc.SecretAAD(testProjectID, testEnvironmentID, s.id, s.name, s.version, testEnvKeyVersion)
		ciphertext, err := vc.Seal(dek, secretNonce, []byte(s.value), aad)
		if err != nil {
			return out, err
		}
		records = append(records, protocol.SecretRecord{
			ID:            s.id,
			Name:          s.name,
			Version:       s.version,
			EnvKeyVersion: testEnvKeyVersion,
			Nonce:         vc.EncodeB64u(secretNonce),
			Ciphertext:    vc.EncodeB64u(ciphertext),
		})
	}

	return protocol.Approved{
		Type:                  protocol.TypeApproved,
		BootID:                testBootID,
		EnvironmentID:         testEnvironmentID,
		ProjectID:             testProjectID,
		EnvironmentKeyVersion: testEnvKeyVersion,
		PayloadExpiresAt:      time.Now().Add(5 * time.Minute).UTC().Format(rfc3339Milli),
		KeyEnvelope: protocol.KeyEnvelope{
			ServerPublicKey: vc.EncodeB64u(envelope.ServerPublicKey),
			Salt:            vc.EncodeB64u(envelope.Salt),
			Nonce:           vc.EncodeB64u(envelope.Nonce),
			Ciphertext:      vc.EncodeB64u(envelope.Ciphertext),
		},
		Secrets: records,
	}, nil
}

func (f *fakeVault) read(ctx context.Context, conn *websocket.Conn) (protocol.Message, []byte, error) {
	kind, frame, err := conn.Read(ctx)
	if err != nil {
		return nil, nil, err
	}
	if kind != websocket.MessageText {
		f.t.Error("fake vault: client sent a binary frame")
	}
	msg, err := protocol.Decode(frame)
	if err != nil {
		f.t.Errorf("fake vault: %v", err)
		return nil, nil, err
	}
	return msg, frame, nil
}

func (f *fakeVault) send(ctx context.Context, conn *websocket.Conn, m protocol.Message) error {
	frame, err := protocol.Encode(m)
	if err != nil {
		f.t.Errorf("fake vault: encode %s: %v", m.MessageType(), err)
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, frame)
}

func (f *fakeVault) state() (connections int, consumed, proofAccepted bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connections, f.consumed, f.proofAccepted
}
