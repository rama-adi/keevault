package client_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ramaadi/env-vault/apps/env-client/internal/client"
	"github.com/ramaadi/env-vault/apps/env-client/internal/protocol"
	vc "github.com/ramaadi/env-vault/apps/env-client/internal/vaultcrypto"
)

// A vault the client trusts for transport but not for content.
//
// The fake vault next door plays the protocol honestly and exercises the happy
// path. This one is the same server after somebody took it over: it still holds
// a valid TLS session and the client's own bootstrap token, and it answers with
// frames that are well formed but wrong. Every case here must end with the
// client refusing to exec, because a compromised control plane must not be able
// to feed the workload an environment of its choosing.

// approvalMutation edits the approval the hostile server is about to send, and
// may hand back replacement raw frame bytes. Returning nil means "encode the
// message as it now stands".
type approvalMutation func(t *testing.T, m *mutable) []byte

// mutable is everything a hostile response can be rebuilt from: the approval as
// it stands, the environment key it was sealed with, and the client's X25519
// public key so a test can rebuild the envelope under a different identity.
type mutable struct {
	approved     *protocol.Approved
	dek          []byte
	clientEncPub []byte
}

// hostileVault approves on the first connection, with no pending frame and no
// resume dance, so each test is one request and one response.
type hostileVault struct {
	t      *testing.T
	mutate approvalMutation

	mu    sync.Mutex
	acked bool
}

func newHostileVault(t *testing.T, mutate approvalMutation) (*hostileVault, *httptest.Server) {
	t.Helper()
	h := &hostileVault{t: t, mutate: mutate}
	server := httptest.NewServer(http.HandlerFunc(h.handle))
	t.Cleanup(server.Close)
	return h, server
}

// acknowledged reports whether the client ever answered with boot.received,
// which is the client saying it opened the envelope and trusted the payload.
func (h *hostileVault) acknowledged() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.acked
}

func (h *hostileVault) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/bootstrap/v1" {
		http.NotFound(w, r)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 20)

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	kind, frame, err := conn.Read(ctx)
	if err != nil || kind != websocket.MessageText {
		return
	}
	msg, err := protocol.Decode(frame)
	if err != nil {
		h.t.Errorf("hostile vault: decode hello: %v", err)
		return
	}
	hello, ok := msg.(protocol.Hello)
	if !ok {
		h.t.Errorf("hostile vault: first frame was %s, want boot.hello", msg.MessageType())
		return
	}
	clientEncPub, err := vc.DecodeB64uLen(hello.EncryptionPublicKey, 32)
	if err != nil {
		h.t.Errorf("hostile vault: encryption key: %v", err)
		return
	}

	if err := writeJSON(ctx, conn, protocol.Pending{
		Type:      protocol.TypePending,
		BootID:    testBootID,
		ExpiresAt: time.Now().Add(30 * time.Minute).UTC().Format(rfc3339Milli),
	}); err != nil {
		return
	}

	approved, dek, err := buildHostileApproval(clientEncPub)
	if err != nil {
		h.t.Errorf("hostile vault: build approval: %v", err)
		return
	}
	raw := h.mutate(h.t, &mutable{approved: &approved, dek: dek, clientEncPub: clientEncPub})
	if raw == nil {
		raw, err = protocol.Encode(approved)
		if err != nil {
			h.t.Errorf("hostile vault: encode approval: %v", err)
			return
		}
	}
	writeCtx, cancelWrite := context.WithTimeout(ctx, 10*time.Second)
	err = conn.Write(writeCtx, websocket.MessageText, raw)
	cancelWrite()
	if err != nil {
		return
	}
	// Give the client room to answer or hang up on its own.
	_, reply, err := conn.Read(ctx)
	if err != nil {
		return
	}
	answer, err := protocol.Decode(reply)
	if err != nil {
		return
	}
	if _, ok := answer.(protocol.Received); ok {
		h.mu.Lock()
		h.acked = true
		h.mu.Unlock()
		_ = writeJSON(ctx, conn, protocol.Consumed{Type: protocol.TypeConsumed, BootID: testBootID})
	}
}

func writeJSON(ctx context.Context, conn *websocket.Conn, m protocol.Message) error {
	frame, err := protocol.Encode(m)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageText, frame)
}

// buildHostileApproval seals a real environment for the client's key and hands
// the DEK back so a test can reseal one record under a different identity.
func buildHostileApproval(clientEncPub []byte) (protocol.Approved, []byte, error) {
	var out protocol.Approved
	clientPub, err := vc.X25519PublicKey(clientEncPub)
	if err != nil {
		return out, nil, err
	}
	serverPriv, err := vc.GenerateX25519()
	if err != nil {
		return out, nil, err
	}
	dek, err := vc.RandomBytes(32)
	if err != nil {
		return out, nil, err
	}
	approved, err := sealApproval(serverPriv, clientPub, clientEncPub, dek, testBootID, testEnvironmentID)
	if err != nil {
		return out, nil, err
	}
	return approved, dek, nil
}

// sealApproval builds one boot.approved with the envelope bound to bootID and
// envelopeEnvironmentID, and every secret bound to testEnvironmentID.
func sealApproval(
	serverPriv *ecdh.PrivateKey,
	clientPub *ecdh.PublicKey,
	clientEncPubRaw []byte,
	dek []byte,
	bootID string,
	envelopeEnvironmentID string,
) (protocol.Approved, error) {
	var out protocol.Approved
	clientFP, err := vc.Fingerprint(clientEncPubRaw)
	if err != nil {
		return out, err
	}
	serverFP, err := vc.Fingerprint(serverPriv.PublicKey().Bytes())
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
	info := vc.BootEnvelopeInfo(bootID, envelopeEnvironmentID, testEnvKeyVersion, clientFP, serverFP)
	envelope, err := vc.SealBootEnvelope(serverPriv, clientPub, salt, nonce, dek, info)
	if err != nil {
		return out, err
	}
	records, err := sealSecrets(dek, testEnvironmentID, testSecrets)
	if err != nil {
		return out, err
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

func sealSecrets(dek []byte, environmentID string, plain []plainSecret) ([]protocol.SecretRecord, error) {
	records := make([]protocol.SecretRecord, 0, len(plain))
	for _, s := range plain {
		nonce, err := vc.RandomBytes(12)
		if err != nil {
			return nil, err
		}
		aad := vc.SecretAAD(testProjectID, environmentID, s.id, s.name, s.version, testEnvKeyVersion)
		ciphertext, err := vc.Seal(dek, nonce, []byte(s.value), aad)
		if err != nil {
			return nil, err
		}
		records = append(records, protocol.SecretRecord{
			ID:            s.id,
			Name:          s.name,
			Version:       s.version,
			EnvKeyVersion: testEnvKeyVersion,
			Nonce:         vc.EncodeB64u(nonce),
			Ciphertext:    vc.EncodeB64u(ciphertext),
		})
	}
	return records, nil
}

// runAgainst drives one session against a hostile server and returns the error
// the client ended with plus whether it ever reached exec.
func runAgainst(t *testing.T, serverURL string) (error, *execRecorder, string) {
	t.Helper()
	logs := &bytes.Buffer{}
	recorder := &execRecorder{}
	cfg := testConfig(t, serverURL, logs, recorder)
	cfg.PendingTimeout = 10 * time.Second
	session, err := client.New(cfg)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return session.Run(ctx), recorder, logs.String()
}

func assertRefused(t *testing.T, err error, recorder *execRecorder, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("the client accepted the payload, want a refusal")
	}
	if recorder.called {
		t.Fatal("the client exec'd the target command with a payload it should have refused")
	}
	if client.ExitCode(err) != client.ExitProtocol {
		t.Errorf("exit code = %d, want %d", client.ExitCode(err), client.ExitProtocol)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to mention %q", err.Error(), want)
	}
}

func TestClientRefusesDuplicateSecretNames(t *testing.T) {
	_, server := newHostileVault(t, func(_ *testing.T, m *mutable) []byte {
		// Both records decrypt, but they claim the same environment variable.
		// The second must not be allowed to shadow the first.
		second := m.approved.Secrets[1]
		second.Name = m.approved.Secrets[0].Name
		m.approved.Secrets[1] = second
		return nil
	})

	err, recorder, _ := runAgainst(t, server.URL)

	// The AAD binds the name, so the reseal is not possible without also
	// changing the ciphertext; either way the client stops before exec.
	assertRefused(t, err, recorder, "")
}

func TestClientRefusesDuplicateSecretNamesThatBothAuthenticate(t *testing.T) {
	_, server := newHostileVault(t, func(t *testing.T, m *mutable) []byte {
		t.Helper()
		// Seal both records under the same name so each one passes AES-GCM on
		// its own. Only the duplicate-name check can catch this.
		doubled := []plainSecret{
			{id: testSecrets[0].id, name: "DATABASE_URL", value: "postgres://real/app", version: 1},
			{id: testSecrets[1].id, name: "DATABASE_URL", value: "postgres://attacker/app", version: 1},
		}
		records, err := sealSecrets(m.dek, testEnvironmentID, doubled)
		if err != nil {
			t.Fatalf("reseal: %v", err)
		}
		m.approved.Secrets = records
		return nil
	})

	err, recorder, _ := runAgainst(t, server.URL)

	assertRefused(t, err, recorder, "repeats a name")
}

func TestClientRefusesSecretSealedForAnotherEnvironment(t *testing.T) {
	_, server := newHostileVault(t, func(t *testing.T, m *mutable) []byte {
		t.Helper()
		// A record lifted out of the staging environment and dropped into the
		// production payload. The value is real, the environment is not.
		records, err := sealSecrets(m.dek, "env_01K4M4X30W1Y4F8B6P7C2D5E9Z", testSecrets)
		if err != nil {
			t.Fatalf("reseal: %v", err)
		}
		m.approved.Secrets = records
		return nil
	})

	err, recorder, _ := runAgainst(t, server.URL)

	assertRefused(t, err, recorder, "failed authentication")
}

func resealEnvelopeFor(t *testing.T, m *mutable, bootID, environmentID string) []byte {
	t.Helper()
	clientPub, err := vc.X25519PublicKey(m.clientEncPub)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	serverPriv, err := vc.GenerateX25519()
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	rebuilt, err := sealApproval(serverPriv, clientPub, m.clientEncPub, m.dek, bootID, environmentID)
	if err != nil {
		t.Fatalf("reseal envelope: %v", err)
	}
	*m.approved = rebuilt
	return nil
}

func TestClientRefusesEnvelopeBoundToAnotherBoot(t *testing.T) {
	// The frame names this boot, but the envelope was derived for another one,
	// which is what a replayed approval looks like from the client's side.
	_, server := newHostileVault(t, func(t *testing.T, m *mutable) []byte {
		return resealEnvelopeFor(t, m, "boot_01K4M4X31X2Z5G9C7Q8D3E6F4H", testEnvironmentID)
	})

	err, recorder, _ := runAgainst(t, server.URL)

	assertRefused(t, err, recorder, "cannot open the environment key envelope")
}

func TestClientRefusesEnvelopeBoundToAnotherEnvironment(t *testing.T) {
	_, server := newHostileVault(t, func(t *testing.T, m *mutable) []byte {
		return resealEnvelopeFor(t, m, testBootID, "env_01K4M4X30W1Y4F8B6P7C2D5E9Z")
	})

	err, recorder, _ := runAgainst(t, server.URL)

	assertRefused(t, err, recorder, "cannot open the environment key envelope")
}

func TestClientRefusesAnApprovalForAnotherBoot(t *testing.T) {
	_, server := newHostileVault(t, func(_ *testing.T, m *mutable) []byte {
		// boot.pending named one boot; boot.approved names another.
		m.approved.BootID = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4H"
		return nil
	})

	err, recorder, _ := runAgainst(t, server.URL)

	assertRefused(t, err, recorder, "different boot request")
}

func TestClientRefusesASecretNameThatIsNotAPosixVariable(t *testing.T) {
	_, server := newHostileVault(t, func(t *testing.T, m *mutable) []byte {
		t.Helper()
		// A name the shell would treat as more than a variable assignment.
		injected := []plainSecret{
			{id: testSecrets[0].id, name: "PATH=/tmp/evil:", value: "x", version: 1},
		}
		records, err := sealSecrets(m.dek, testEnvironmentID, injected)
		if err != nil {
			t.Fatalf("reseal: %v", err)
		}
		m.approved.Secrets = records
		return nil
	})

	err, recorder, _ := runAgainst(t, server.URL)

	assertRefused(t, err, recorder, "")
}

// Finding 5 in docs/security-review-v1.md, now fixed. The protocol document
// caps a frame at 1 MiB and the server enforces that on the way in. The client
// reads at most that plus 64 KiB of slack, so an oversized frame is a protocol
// error instead of 32 MiB the workload buffers on every reconnect.
func TestClientRefusesAFrameLargerThanTheProtocolLimit(t *testing.T) {
	vault, server := newHostileVault(t, func(t *testing.T, m *mutable) []byte {
		t.Helper()
		frame, err := protocol.Encode(*m.approved)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		// Unknown fields are ignored by the decoder, so padding one in keeps the
		// frame valid while pushing it past the protocol's 1 MiB limit.
		padding := `,"padding":"` + strings.Repeat("a", 1<<21) + `"}`
		return append(frame[:len(frame)-1], padding...)
	})

	_, recorder, _ := runAgainst(t, server.URL)

	if vault.acknowledged() {
		t.Error("the client opened and acknowledged a frame larger than the protocol allows")
	}
	if recorder.called {
		t.Error("the client exec'd on a frame larger than the protocol allows")
	}
}
