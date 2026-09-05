package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ramaadi/env-vault/apps/env-client/internal/protocol"
	vc "github.com/ramaadi/env-vault/apps/env-client/internal/vaultcrypto"
)

func b64u(n int) string { return vc.EncodeB64u(make([]byte, n)) }

func TestEncodeHasNoTrailingNewlineAndNoHTMLEscaping(t *testing.T) {
	frame, err := protocol.Encode(protocol.Canceled{
		Type:   protocol.TypeCanceled,
		BootID: "boot_01",
		Reason: "token revoked <by> admin & ops",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.HasSuffix(string(frame), "\n") {
		t.Fatal("a frame must not end with a newline")
	}
	if !strings.Contains(string(frame), "<by> admin & ops") {
		t.Fatalf("HTML escaping must be off, got %s", frame)
	}
	if !json.Valid(frame) {
		t.Fatal("a frame must be valid json")
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	messages := []protocol.Message{
		protocol.Hello{
			Type:                protocol.TypeHello,
			Protocol:            1,
			BootNonce:           b64u(16),
			SigningPublicKey:    b64u(32),
			EncryptionPublicKey: b64u(32),
			Claims: protocol.Claims{
				Git:      &protocol.GitClaim{Repository: "github.com/acme/app", Commit: "abc"},
				OCI:      &protocol.OCIClaim{Repository: "ghcr.io/acme/app", Digest: "sha256:aa"},
				Provider: &protocol.ProviderClaim{Name: "zeabur", DeploymentID: "dep_1"},
			},
			Evidence: []protocol.Evidence{},
		},
		protocol.Resume{Type: protocol.TypeResume, Protocol: 1, BootID: "boot_01"},
		protocol.ChallengeResponse{Type: protocol.TypeChallengeResponse, BootID: "boot_01", Signature: b64u(64)},
		protocol.Received{Type: protocol.TypeReceived, BootID: "boot_01", PayloadDigest: strings.Repeat("a", 64)},
		protocol.Pending{Type: protocol.TypePending, BootID: "boot_01", ExpiresAt: "2026-09-05T10:00:00.000Z"},
		protocol.Challenge{Type: protocol.TypeChallenge, BootID: "boot_01", Challenge: b64u(32)},
		protocol.Resumed{Type: protocol.TypeResumed, BootID: "boot_01", Status: protocol.StatusDelivered, ExpiresAt: "2026-09-05T10:00:00.000Z"},
		protocol.Approved{
			Type:                  protocol.TypeApproved,
			BootID:                "boot_01",
			EnvironmentID:         "env_01",
			ProjectID:             "proj_01",
			EnvironmentKeyVersion: 4,
			PayloadExpiresAt:      "2026-09-05T10:05:00.000Z",
			KeyEnvelope: protocol.KeyEnvelope{
				ServerPublicKey: b64u(32),
				Salt:            b64u(32),
				Nonce:           b64u(12),
				Ciphertext:      b64u(48),
			},
			Secrets: []protocol.SecretRecord{{
				ID:            "sec_01",
				Name:          "DATABASE_URL",
				Version:       1,
				EnvKeyVersion: 4,
				Nonce:         b64u(12),
				Ciphertext:    b64u(20),
			}},
		},
		protocol.Declined{Type: protocol.TypeDeclined, BootID: "boot_01", Reason: "not this one"},
		protocol.Expired{Type: protocol.TypeExpired, BootID: "boot_01"},
		protocol.Canceled{Type: protocol.TypeCanceled, BootID: "boot_01", Reason: "token revoked"},
		protocol.Consumed{Type: protocol.TypeConsumed, BootID: "boot_01"},
		protocol.Error{Type: protocol.TypeError, Code: protocol.CloseConflict, Message: "too many pending boots"},
	}
	for _, want := range messages {
		t.Run(want.MessageType(), func(t *testing.T) {
			frame, err := protocol.Encode(want)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := protocol.Decode(frame)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.MessageType() != want.MessageType() {
				t.Fatalf("type = %s, want %s", got.MessageType(), want.MessageType())
			}
			again, err := protocol.Encode(got)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if string(again) != string(frame) {
				t.Fatalf("round trip changed the frame\n got: %s\nwant: %s", again, frame)
			}
		})
	}
}

func TestDecodeRejectsBadFrames(t *testing.T) {
	cases := map[string]string{
		"not json":            `{`,
		"trailing data":       `{"type":"boot.expired","bootId":"boot_01"} {"type":"boot.expired"}`,
		"unknown type":        `{"type":"boot.whatever"}`,
		"missing boot id":     `{"type":"boot.expired"}`,
		"wrong protocol":      `{"type":"boot.resume","protocol":2,"bootId":"boot_01"}`,
		"short challenge":     `{"type":"boot.challenge","bootId":"boot_01","challenge":"` + b64u(31) + `"}`,
		"padded challenge":    `{"type":"boot.challenge","bootId":"boot_01","challenge":"AAAA===="}`,
		"short signature":     `{"type":"boot.challenge-response","bootId":"boot_01","signature":"` + b64u(63) + `"}`,
		"short signing key":   `{"type":"boot.hello","protocol":1,"bootNonce":"` + b64u(16) + `","signingPublicKey":"` + b64u(31) + `","encryptionPublicKey":"` + b64u(32) + `"}`,
		"short boot nonce":    `{"type":"boot.hello","protocol":1,"bootNonce":"` + b64u(15) + `","signingPublicKey":"` + b64u(32) + `","encryptionPublicKey":"` + b64u(32) + `"}`,
		"bad resumed status":  `{"type":"boot.resumed","bootId":"boot_01","status":"DECLINED"}`,
		"short digest":        `{"type":"boot.received","bootId":"boot_01","payloadDigest":"aa"}`,
		"upper case digest":   `{"type":"boot.received","bootId":"boot_01","payloadDigest":"` + strings.Repeat("A", 64) + `"}`,
		"envelope wrong size": approvedFrame(b64u(32), b64u(32), b64u(12), b64u(47)),
		"envelope short salt": approvedFrame(b64u(32), b64u(31), b64u(12), b64u(48)),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := protocol.Decode([]byte(frame)); err == nil {
				t.Fatalf("frame must be rejected: %s", frame)
			}
		})
	}
}

func approvedFrame(serverKey, salt, nonce, ciphertext string) string {
	return `{"type":"boot.approved","bootId":"boot_01","environmentId":"env_01","projectId":"proj_01",` +
		`"environmentKeyVersion":1,"payloadExpiresAt":"2026-09-05T10:05:00.000Z","keyEnvelope":{` +
		`"serverPublicKey":"` + serverKey + `","salt":"` + salt + `","nonce":"` + nonce + `","ciphertext":"` + ciphertext + `"},"secrets":[]}`
}

func TestDecodeAcceptsMinimalApproved(t *testing.T) {
	msg, err := protocol.Decode([]byte(approvedFrame(b64u(32), b64u(32), b64u(12), b64u(48))))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	approved, ok := msg.(protocol.Approved)
	if !ok {
		t.Fatalf("decoded %T, want protocol.Approved", msg)
	}
	if len(approved.Secrets) != 0 {
		t.Fatal("an approval may carry no secrets")
	}
}

func TestDecodeAcceptsConsumedResumedStatus(t *testing.T) {
	frame := `{"type":"boot.resumed","bootId":"boot_01","status":"CONSUMED","expiresAt":"2026-09-05T10:00:00.000Z"}`
	msg, err := protocol.Decode([]byte(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	resumed, ok := msg.(protocol.Resumed)
	if !ok {
		t.Fatalf("decoded %T, want protocol.Resumed", msg)
	}
	if resumed.Status != protocol.StatusConsumed {
		t.Fatalf("status = %s, want %s", resumed.Status, protocol.StatusConsumed)
	}
}

func TestDecodeRejectsB64uWithNonZeroSlackBits(t *testing.T) {
	// b64u(32) ends in "A", which carries zero slack bits. Changing the last
	// character to "B" keeps the string 43 characters long but sets a slack
	// bit the encoder would never produce, so a strict decoder must reject
	// it even though a lenient one would accept it.
	valid := b64u(32)
	if !strings.HasSuffix(valid, "A") {
		t.Fatalf("test fixture assumption broke: b64u(32) = %s", valid)
	}
	tampered := strings.TrimSuffix(valid, "A") + "B"
	challengeFrame := `{"type":"boot.challenge","bootId":"boot_01","challenge":"` + tampered + `"}`
	if _, err := protocol.Decode([]byte(challengeFrame)); err == nil {
		t.Fatalf("a base64url string with non-zero slack bits must be rejected: %s", tampered)
	}
}

func TestCloseCodes(t *testing.T) {
	want := map[string]int{
		"normal":       1000,
		"protocol":     4400,
		"bad token":    4401,
		"forbidden":    4403,
		"unknown boot": 4404,
		"conflict":     4409,
		"terminal":     4410,
		"rate limited": 4429,
	}
	got := map[string]int{
		"normal":       protocol.CloseNormal,
		"protocol":     protocol.CloseProtocolError,
		"bad token":    protocol.CloseBadToken,
		"forbidden":    protocol.CloseForbidden,
		"unknown boot": protocol.CloseUnknownBoot,
		"conflict":     protocol.CloseConflict,
		"terminal":     protocol.CloseTerminal,
		"rate limited": protocol.CloseRateLimited,
	}
	for name, code := range want {
		if got[name] != code {
			t.Errorf("%s close code = %d, want %d", name, got[name], code)
		}
	}
}
