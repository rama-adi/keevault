package vaultcrypto_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	vc "github.com/ramaadi/env-vault/apps/env-client/internal/vaultcrypto"
)

func TestB64uRoundTrip(t *testing.T) {
	in := []byte{0x00, 0xff, 0x3e, 0x3f, 0x7a}
	encoded := vc.EncodeB64u(in)
	if strings.ContainsAny(encoded, "=+/") {
		t.Fatalf("encoding must be unpadded base64url, got %q", encoded)
	}
	out, err := vc.DecodeB64u(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(in, out) {
		t.Fatal("round trip changed the bytes")
	}
}

func TestDecodeB64uRejectsPadding(t *testing.T) {
	if _, err := vc.DecodeB64u("AAAA===="); err == nil {
		t.Fatal("padded input must be rejected")
	}
}

func TestDecodeB64uLen(t *testing.T) {
	if _, err := vc.DecodeB64uLen(vc.EncodeB64u(make([]byte, 31)), 32); err == nil {
		t.Fatal("a short field must be rejected")
	}
	if _, err := vc.DecodeB64uLen(vc.EncodeB64u(make([]byte, 32)), 32); err != nil {
		t.Fatalf("exact length must be accepted: %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	key := make([]byte, 32)
	got, err := vc.Fingerprint(key)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	// SHA-256 of 32 zero bytes.
	want := "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
	if got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
	if _, err := vc.Fingerprint(make([]byte, 31)); err == nil {
		t.Fatal("a 31 byte key must be rejected")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	vc.Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not cleared", i)
		}
	}
}

func TestAADStrings(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{
			"project key",
			vc.ProjectKeyAAD("proj_01", 2, 1),
			"vault:project-key:v1\nproject=proj_01\nversion=2\nmaster=1",
		},
		{
			"environment key",
			vc.EnvironmentKeyAAD("proj_01", "env_01", 4, 2),
			"vault:environment-key:v1\nproject=proj_01\nenvironment=env_01\nversion=4\nproject_key_version=2",
		},
		{
			"secret",
			vc.SecretAAD("proj_01", "env_01", "sec_01", "DATABASE_URL", 3, 4),
			"vault:secret:v1\nproject=proj_01\nenvironment=env_01\nsecret=sec_01\nname=DATABASE_URL\nversion=3\nenv_key_version=4",
		},
		{
			"boot envelope",
			vc.BootEnvelopeInfo("boot_01", "env_01", 4, "aa", "bb"),
			"vault:boot-envelope:v1\nboot=boot_01\nenvironment=env_01\nenv_key_version=4\nclient=aa\nserver=bb",
		},
		{
			"resume",
			vc.ResumeMessage("boot_01", "Q0hBTExFTkdF"),
			"vault-resume:v1\nboot_01\nQ0hBTExFTkdF",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if string(c.got) != c.want {
				t.Fatalf("canonical string mismatch\n got: %q\nwant: %q", c.got, c.want)
			}
			if bytes.HasSuffix(c.got, []byte("\n")) {
				t.Fatal("canonical strings must not end with a newline")
			}
			if bytes.Contains(c.got, []byte("\r")) {
				t.Fatal("canonical strings must not contain CR")
			}
		})
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := vc.RandomBytes(32)
	nonce, _ := vc.RandomBytes(12)
	aad := vc.SecretAAD("p", "e", "s", "NAME", 1, 1)
	plaintext := []byte("postgres://user:pass@host/db")

	ciphertext, err := vc.Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(ciphertext) != len(plaintext)+vc.TagSize {
		t.Fatalf("ciphertext must be plaintext plus a %d byte tag", vc.TagSize)
	}
	out, err := vc.Open(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatal("round trip changed the plaintext")
	}
}

func TestOpenTamperCases(t *testing.T) {
	key, _ := vc.RandomBytes(32)
	otherKey, _ := vc.RandomBytes(32)
	nonce, _ := vc.RandomBytes(12)
	aad := vc.SecretAAD("p", "e", "s", "NAME", 1, 1)
	ciphertext, err := vc.Seal(key, nonce, []byte("value"), aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := bytes.Clone(ciphertext)
		bad[0] ^= 0x01
		if _, err := vc.Open(key, nonce, bad, aad); err == nil {
			t.Fatal("a flipped ciphertext byte must fail authentication")
		}
	})
	t.Run("flipped tag byte", func(t *testing.T) {
		bad := bytes.Clone(ciphertext)
		bad[len(bad)-1] ^= 0x01
		if _, err := vc.Open(key, nonce, bad, aad); err == nil {
			t.Fatal("a flipped tag byte must fail authentication")
		}
	})
	t.Run("wrong aad name", func(t *testing.T) {
		other := vc.SecretAAD("p", "e", "s", "OTHER", 1, 1)
		if _, err := vc.Open(key, nonce, ciphertext, other); err == nil {
			t.Fatal("a renamed secret must fail authentication")
		}
	})
	t.Run("wrong aad environment", func(t *testing.T) {
		other := vc.SecretAAD("p", "e2", "s", "NAME", 1, 1)
		if _, err := vc.Open(key, nonce, ciphertext, other); err == nil {
			t.Fatal("a ciphertext moved between environments must fail authentication")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		if _, err := vc.Open(otherKey, nonce, ciphertext, aad); err == nil {
			t.Fatal("the wrong key must fail authentication")
		}
	})
	t.Run("wrong nonce", func(t *testing.T) {
		other, _ := vc.RandomBytes(12)
		if _, err := vc.Open(key, other, ciphertext, aad); err == nil {
			t.Fatal("the wrong nonce must fail authentication")
		}
	})
	t.Run("short key", func(t *testing.T) {
		if _, err := vc.Open(make([]byte, 16), nonce, ciphertext, aad); err == nil {
			t.Fatal("a 128 bit key must be rejected")
		}
	})
	t.Run("short nonce", func(t *testing.T) {
		if _, err := vc.Open(key, make([]byte, 8), ciphertext, aad); err == nil {
			t.Fatal("a short nonce must be rejected")
		}
	})
}

func TestBootEnvelopeRoundTrip(t *testing.T) {
	clientPriv, err := vc.GenerateX25519()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	serverPriv, err := vc.GenerateX25519()
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	clientFP, _ := vc.Fingerprint(clientPriv.PublicKey().Bytes())
	serverFP, _ := vc.Fingerprint(serverPriv.PublicKey().Bytes())
	info := vc.BootEnvelopeInfo("boot_01", "env_01", 4, clientFP, serverFP)
	salt, _ := vc.RandomBytes(32)
	nonce, _ := vc.RandomBytes(12)
	dek, _ := vc.RandomBytes(32)

	envelope, err := vc.SealBootEnvelope(serverPriv, clientPriv.PublicKey(), salt, nonce, dek, info)
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	if len(envelope.Ciphertext) != 48 {
		t.Fatalf("wrapped dek must be 48 bytes, got %d", len(envelope.Ciphertext))
	}
	out, err := vc.OpenBootEnvelope(clientPriv, envelope, info)
	if err != nil {
		t.Fatalf("open envelope: %v", err)
	}
	if !bytes.Equal(out, dek) {
		t.Fatal("round trip changed the environment key")
	}

	t.Run("wrong info", func(t *testing.T) {
		other := vc.BootEnvelopeInfo("boot_02", "env_01", 4, clientFP, serverFP)
		if _, err := vc.OpenBootEnvelope(clientPriv, envelope, other); err == nil {
			t.Fatal("a different boot id in the info string must fail")
		}
	})
	t.Run("wrong recipient", func(t *testing.T) {
		attacker, _ := vc.GenerateX25519()
		if _, err := vc.OpenBootEnvelope(attacker, envelope, info); err == nil {
			t.Fatal("a copied envelope must not open under another key")
		}
	})
	t.Run("flipped ciphertext byte", func(t *testing.T) {
		bad := envelope
		bad.Ciphertext = bytes.Clone(envelope.Ciphertext)
		bad.Ciphertext[3] ^= 0x01
		if _, err := vc.OpenBootEnvelope(clientPriv, bad, info); err == nil {
			t.Fatal("a flipped envelope byte must fail")
		}
	})
	t.Run("changed salt", func(t *testing.T) {
		bad := envelope
		bad.Salt = bytes.Clone(envelope.Salt)
		bad.Salt[0] ^= 0x01
		if _, err := vc.OpenBootEnvelope(clientPriv, bad, info); err == nil {
			t.Fatal("a changed salt must derive a different key and fail")
		}
	})
}

func TestLowOrderPointRejected(t *testing.T) {
	clientPriv, err := vc.GenerateX25519()
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	// The all-zero X25519 public key is a low-order point and produces an
	// all-zero shared secret.
	pub, err := vc.X25519PublicKey(make([]byte, 32))
	if err != nil {
		// Go refuses the point at parse time, which is also correct.
		return
	}
	if _, err := vc.DeriveWrapKey(clientPriv, pub, make([]byte, 32), []byte("info")); err == nil {
		t.Fatal("an all-zero shared secret must be rejected")
	}
}

func TestResumeSignature(t *testing.T) {
	pub, priv, err := vc.GenerateEd25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const bootID = "boot_01K4ABCDEFGHJKMNPQRSTVWXYZ"
	challenge := vc.EncodeB64u(bytes.Repeat([]byte{7}, 32))

	sig := vc.SignResume(priv, bootID, challenge)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !vc.VerifyResume(pub, bootID, challenge, sig) {
		t.Fatal("a fresh signature must verify")
	}
	if vc.VerifyResume(pub, "boot_01K4ABCDEFGHJKMNPQRSTVWXY0", challenge, sig) {
		t.Fatal("a signature must not verify against another boot id")
	}
	if vc.VerifyResume(pub, bootID, vc.EncodeB64u(bytes.Repeat([]byte{8}, 32)), sig) {
		t.Fatal("a signature must not verify against another challenge")
	}
	otherPub, _, _ := vc.GenerateEd25519()
	if vc.VerifyResume(otherPub, bootID, challenge, sig) {
		t.Fatal("a signature must not verify under another key")
	}
	bad := bytes.Clone(sig)
	bad[0] ^= 0x01
	if vc.VerifyResume(pub, bootID, challenge, bad) {
		t.Fatal("a flipped signature byte must not verify")
	}
	if vc.VerifyResume(pub, bootID, challenge, bad[:63]) {
		t.Fatal("a truncated signature must not verify")
	}
}

func TestParseBootstrapToken(t *testing.T) {
	id := "01K4ABCDEFGHJKMNPQRSTVWXYZ"
	secret := vc.EncodeB64u(bytes.Repeat([]byte{9}, 32))
	if len(secret) != 43 {
		t.Fatalf("a 32 byte secret must encode to 43 characters, got %d", len(secret))
	}
	token := "vlt_boot_" + id + "." + secret
	parsed, err := vc.ParseBootstrapToken(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.TokenID != id || parsed.Secret != secret {
		t.Fatal("parse returned the wrong parts")
	}

	bad := []string{
		"",
		"vlt_boot_" + id,
		"vlt_boot_" + id + "." + secret[:42],
		"vlt_boot_" + id + "." + secret + "A",
		// I is not part of Crockford base32.
		"vlt_boot_01K4ABCDEFGHIJKMNPQRSTVWXY." + secret,
		"vlt_boot_" + strings.ToLower(id) + "." + secret,
		"boot_" + id + "." + secret,
		"vlt_boot_" + id + "." + strings.Replace(secret, "C", "+", 1),
	}
	for _, token := range bad {
		if _, err := vc.ParseBootstrapToken(token); err == nil {
			t.Fatalf("token of length %d must be rejected", len(token))
		}
	}
}

func TestBootstrapTokenSecretHash(t *testing.T) {
	// SHA-256 over the UTF-8 bytes of the secret string, not the decoded bytes.
	got := vc.BootstrapTokenSecretHash("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("hash = %s, want %s", got, want)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("hash must be hex: %v", err)
	}
}

func TestCanonicalManifestJSON(t *testing.T) {
	raw := []byte(`{
	  "issuedAt": "2026-09-05T10:00:00.000Z",
	  "builder": "acme-ci",
	  "artifact": {"type": "oci", "repository": "ghcr.io/acme/foo", "digest": "sha256:aa"},
	  "version": 1,
	  "source": {"repository": "github.com/acme/foo", "commit": "abc"}
	}`)
	got, err := vc.CanonicalManifestJSON(raw)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"artifact":{"digest":"sha256:aa","repository":"ghcr.io/acme/foo","type":"oci"},"builder":"acme-ci","issuedAt":"2026-09-05T10:00:00.000Z","source":{"commit":"abc","repository":"github.com/acme/foo"},"version":1}`
	if string(got) != want {
		t.Fatalf("canonical json mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestCanonicalManifestEscaping(t *testing.T) {
	got, err := vc.CanonicalManifestJSON([]byte(`{"a":"<b>&\"x\\y\nz\t"}`))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := "{\"a\":\"<b>&\\\"x\\\\y\\nz\\t\"}"
	if string(got) != want {
		t.Fatalf("escaping mismatch\n got: %s\nwant: %s", got, want)
	}

	// JSON.stringify leaves U+2028 alone. Go's encoding/json does not, so the
	// canonical writer must not use it.
	sep := string(rune(0x2028))
	raw, err := vc.CanonicalManifestJSON([]byte(`{"a":" é"}`))
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(raw) != `{"a":"`+sep+`é"}` {
		t.Fatalf("non-ascii must stay raw utf-8, got %q", raw)
	}
}

func TestCanonicalManifestKeyOrderIsUTF16(t *testing.T) {
	// U+10000 encodes as the surrogate pair D800 DC00, so in UTF-16 code unit
	// order it sorts before U+FF00. Plain UTF-8 byte order puts it after, so
	// this fails if the comparator sorts bytes.
	high := string(rune(0xFF00))
	astral := string(rune(0x10000))
	raw := []byte(`{"` + high + `":"b","` + astral + `":"a"}`)
	got, err := vc.CanonicalManifestJSON(raw)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"` + astral + `":"a","` + high + `":"b"}`
	if string(got) != want {
		t.Fatalf("key order mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestCanonicalManifestRejectsOtherValues(t *testing.T) {
	for _, raw := range []string{`{"a":2}`, `{"a":true}`, `{"a":null}`, `{"a":1.0}`, `{"a":0}`} {
		if _, err := vc.CanonicalManifestJSON([]byte(raw)); err == nil {
			t.Fatalf("%s must be rejected", raw)
		}
	}
}

func TestManifestSignature(t *testing.T) {
	pub, priv, err := vc.GenerateEd25519()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	raw := []byte(`{"version":1,"builder":"acme-ci"}`)
	sig, err := vc.SignManifest(priv, raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	ok, err := vc.VerifyManifest(pub, raw, sig)
	if err != nil || !ok {
		t.Fatalf("verify = %v, %v; want true, nil", ok, err)
	}

	// Key order must not matter.
	ok, err = vc.VerifyManifest(pub, []byte(`{"builder":"acme-ci","version":1}`), sig)
	if err != nil || !ok {
		t.Fatal("reordering keys must not break the signature")
	}

	ok, _ = vc.VerifyManifest(pub, []byte(`{"version":1,"builder":"other-ci"}`), sig)
	if ok {
		t.Fatal("a changed manifest must not verify")
	}
	bad := bytes.Clone(sig)
	bad[10] ^= 0x01
	ok, _ = vc.VerifyManifest(pub, raw, bad)
	if ok {
		t.Fatal("a flipped signature byte must not verify")
	}
	if _, err := vc.VerifyManifest(pub, raw, bad[:10]); err == nil {
		t.Fatal("a short signature must be an error")
	}
	if _, err := vc.VerifyManifest(ed25519.PublicKey(make([]byte, 16)), raw, sig); err == nil {
		t.Fatal("a short public key must be an error")
	}
}

func TestManifestSignedMessagePrefix(t *testing.T) {
	msg := vc.ManifestSignedMessage([]byte(`{}`))
	if string(msg) != "vault:signed-build-manifest:v1\n{}" {
		t.Fatalf("signed message = %q", msg)
	}
}
