package vaultcrypto_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	vc "github.com/ramaadi/keevault/apps/env-client/internal/vaultcrypto"
)

// The shared vectors live at crypto/test-vectors in the repository root. The
// test binary runs in the package directory, so the directory is found by
// walking up.
const vectorDirRelative = "crypto/test-vectors"

var vectorFiles = []string{
	"aes-gcm-secret.json",
	"key-wrap.json",
	"boot-envelope.json",
	"resume-signature.json",
	"bootstrap-token.json",
	"manifest-canonical.json",
	"fingerprint.json",
}

// item is one vector with its field names kept as written, so a name mismatch
// can be reported instead of silently decoding to zero values.
type item map[string]json.RawMessage

type vectorFile struct {
	Description string `json:"description"`
	Vectors     []item `json:"vectors"`
}

func findVectorDir() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		candidate := filepath.Join(dir, filepath.FromSlash(vectorDirRelative))
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func loadVectors(t *testing.T, dir, name string) []item {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Skipf("%s is not present yet: %v", name, err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(file.Vectors) == 0 {
		t.Fatalf("%s has no vectors", name)
	}
	t.Logf("%s: %s (%d vectors)", name, file.Description, len(file.Vectors))
	return file.Vectors
}

// keysOf lists the field names an item actually carries, for mismatch reports.
func keysOf(v item) string {
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

var errNoField = errors.New("no matching field")

func lookup(v item, candidates ...string) (json.RawMessage, error) {
	for _, name := range candidates {
		if raw, ok := v[name]; ok {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("%w for %s; the vector carries: %s", errNoField, strings.Join(candidates, " or "), keysOf(v))
}

func str(v item, candidates ...string) (string, error) {
	raw, err := lookup(v, candidates...)
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("field %s is not a string: %w", candidates[0], err)
	}
	return s, nil
}

func optionalStr(v item, candidates ...string) string {
	s, err := str(v, candidates...)
	if err != nil {
		return ""
	}
	return s
}

func num(v item, candidates ...string) (int, error) {
	raw, err := lookup(v, candidates...)
	if err != nil {
		return 0, err
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("field %s is not an integer: %w", candidates[0], err)
	}
	return n, nil
}

func b64u(t *testing.T, v item, candidates ...string) []byte {
	t.Helper()
	s, err := str(v, candidates...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	decoded, err := vc.DecodeB64u(s)
	if err != nil {
		t.Fatalf("field %s is not base64url: %v", candidates[0], err)
	}
	return decoded
}

func requireVectorDir(t *testing.T) string {
	t.Helper()
	dir, ok := findVectorDir()
	if !ok {
		t.Skipf("shared vectors not found: no %s directory above %s", vectorDirRelative, mustGetwd(t))
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Skipf("shared vectors not generated yet: %s is empty", dir)
	}
	return dir
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

func TestVectorFilesPresent(t *testing.T) {
	dir := requireVectorDir(t)
	for _, name := range vectorFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is missing from %s", name, dir)
		}
	}
}

func TestVectorFingerprint(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "fingerprint.json") {
		key := b64u(t, v, "publicKey", "key", "input", "publicKeyB64u")
		want, err := str(v, "fingerprint", "expected", "expectedFingerprint", "output")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		got, err := vc.Fingerprint(key)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if got != strings.ToLower(want) {
			t.Errorf("vector %d: fingerprint = %s, want %s", i, got, want)
		}
		if keyHex := optionalStr(v, "keyHex"); keyHex != "" && hex.EncodeToString(key) != strings.ToLower(keyHex) {
			t.Errorf("vector %d: keyHex does not describe the same key", i)
		}
	}
}

func TestVectorBootstrapToken(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "bootstrap-token.json") {
		token, err := str(v, "token", "input", "bootstrapToken")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		valid := true
		if raw, err := lookup(v, "valid", "isValid"); err == nil {
			if err := json.Unmarshal(raw, &valid); err != nil {
				t.Fatalf("vector %d: valid is not a boolean: %v", i, err)
			}
		}
		parsed, parseErr := vc.ParseBootstrapToken(token)
		if !valid {
			if parseErr == nil {
				t.Errorf("vector %d: an invalid token was accepted", i)
			}
			continue
		}
		if parseErr != nil {
			t.Errorf("vector %d: %v", i, parseErr)
			continue
		}
		if want := optionalStr(v, "tokenId", "id"); want != "" && parsed.TokenID != want {
			t.Errorf("vector %d: tokenId = %s, want %s", i, parsed.TokenID, want)
		}
		if want := optionalStr(v, "secret", "tokenSecret"); want != "" && parsed.Secret != want {
			t.Errorf("vector %d: secret does not match the vector", i)
		}
		want, err := str(v, "tokenHash", "secretHash", "hash", "expectedHash")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if got := vc.BootstrapTokenSecretHash(parsed.Secret); got != strings.ToLower(want) {
			t.Errorf("vector %d: token hash = %s, want %s", i, got, want)
		}
	}
}

func TestVectorAESGCMSecret(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "aes-gcm-secret.json") {
		key := b64u(t, v, "key", "environmentKey", "envKey", "dek")
		nonce := b64u(t, v, "nonce", "iv")
		plaintext := b64u(t, v, "plaintext", "value", "secretValue")
		ciphertext := b64u(t, v, "ciphertext", "expectedCiphertext", "output")

		aad, err := secretAADFromVector(v)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		got, err := vc.Seal(key, nonce, plaintext, aad)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(got, ciphertext) {
			t.Errorf("vector %d: ciphertext does not match the vector", i)
		}
		opened, err := vc.Open(key, nonce, ciphertext, aad)
		if err != nil {
			t.Errorf("vector %d: open failed: %v", i, err)
			continue
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("vector %d: decrypted plaintext does not match the vector", i)
		}
	}
}

// secretAADFromVector rebuilds the secret AAD from the identity fields and
// checks it against the aad string the vector carries.
func secretAADFromVector(v item) ([]byte, error) {
	projectID, err := str(v, "projectId", "project")
	if err != nil {
		return nil, err
	}
	environmentID, err := str(v, "environmentId", "environment")
	if err != nil {
		return nil, err
	}
	secretID, err := str(v, "secretId", "secret", "id")
	if err != nil {
		return nil, err
	}
	name, err := str(v, "secretName")
	if err != nil {
		return nil, err
	}
	version, err := num(v, "secretVersion", "version")
	if err != nil {
		return nil, err
	}
	envKeyVersion, err := num(v, "environmentKeyVersion", "envKeyVersion")
	if err != nil {
		return nil, err
	}
	built := vc.SecretAAD(projectID, environmentID, secretID, name, version, envKeyVersion)
	if want := optionalStr(v, "aad", "additionalData"); want != "" && string(built) != want {
		return nil, fmt.Errorf("secret aad mismatch\n got: %q\nwant: %q", built, want)
	}
	return built, nil
}

func TestVectorKeyWrap(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "key-wrap.json") {
		key := b64u(t, v, "key", "wrappingKey", "masterKey", "projectKey")
		nonce := b64u(t, v, "nonce", "iv")
		plaintext := b64u(t, v, "plaintext", "wrappedKey", "key material", "unwrappedKey")
		ciphertext := b64u(t, v, "ciphertext", "expectedCiphertext", "wrapped", "output")

		aad, err := wrapAADFromVector(v)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		got, err := vc.Seal(key, nonce, plaintext, aad)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if !bytes.Equal(got, ciphertext) {
			t.Errorf("vector %d: wrapped key does not match the vector", i)
		}
		opened, err := vc.Open(key, nonce, ciphertext, aad)
		if err != nil {
			t.Errorf("vector %d: unwrap failed: %v", i, err)
			continue
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("vector %d: unwrapped key does not match the vector", i)
		}
	}
}

// wrapAADFromVector rebuilds either the project key AAD or the environment key
// AAD and checks it against the aad string the vector carries.
func wrapAADFromVector(v item) ([]byte, error) {
	projectID, err := str(v, "projectId", "project")
	if err != nil {
		return nil, err
	}
	projectKeyVersion, err := num(v, "projectKeyVersion")
	if err != nil {
		return nil, err
	}
	var built []byte
	if environmentID := optionalStr(v, "environmentId", "environment"); environmentID != "" {
		envKeyVersion, err := num(v, "environmentKeyVersion", "envKeyVersion")
		if err != nil {
			return nil, err
		}
		built = vc.EnvironmentKeyAAD(projectID, environmentID, envKeyVersion, projectKeyVersion)
	} else {
		masterKeyVersion, err := num(v, "masterKeyVersion")
		if err != nil {
			return nil, err
		}
		built = vc.ProjectKeyAAD(projectID, projectKeyVersion, masterKeyVersion)
	}
	if want := optionalStr(v, "aad", "additionalData"); want != "" && string(built) != want {
		return nil, fmt.Errorf("key wrap aad mismatch\n got: %q\nwant: %q", built, want)
	}
	return built, nil
}

func TestVectorBootEnvelope(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "boot-envelope.json") {
		clientPrivRaw := b64u(t, v, "clientPrivateKey", "clientEncryptionPrivateKey", "clientPriv")
		serverPubRaw := b64u(t, v, "serverPublicKey", "serverEncryptionPublicKey", "serverPub")
		salt := b64u(t, v, "salt", "hkdfSalt")
		nonce := b64u(t, v, "nonce", "iv")
		ciphertext := b64u(t, v, "ciphertext", "wrappedEnvironmentKey", "wrappedKey")
		dek := b64u(t, v, "environmentKey", "envKey", "dek", "plaintext")

		clientPriv, err := vc.X25519PrivateKey(clientPrivRaw)
		if err != nil {
			t.Fatalf("vector %d: client private key: %v", i, err)
		}
		clientFP, err := vc.Fingerprint(clientPriv.PublicKey().Bytes())
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		serverFP, err := vc.Fingerprint(serverPubRaw)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}

		info, err := envelopeInfoFromVector(v, clientFP, serverFP)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		opened, err := vc.OpenBootEnvelope(clientPriv, vc.KeyEnvelope{
			ServerPublicKey: serverPubRaw,
			Salt:            salt,
			Nonce:           nonce,
			Ciphertext:      ciphertext,
		}, info)
		if err != nil {
			t.Errorf("vector %d: %v", i, err)
			continue
		}
		if !bytes.Equal(opened, dek) {
			t.Errorf("vector %d: environment key does not match the vector", i)
		}
		if want := optionalStr(v, "wrapKey"); want != "" {
			serverPub, err := vc.X25519PublicKey(serverPubRaw)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			got, err := vc.DeriveWrapKey(clientPriv, serverPub, salt, info)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			if vc.EncodeB64u(got) != want {
				t.Errorf("vector %d: derived wrap key does not match the vector", i)
			}
		}
		if serverPrivRaw, err := str(v, "serverPrivateKey"); err == nil {
			raw, err := vc.DecodeB64u(serverPrivRaw)
			if err != nil {
				t.Fatalf("vector %d: server private key: %v", i, err)
			}
			serverPriv, err := vc.X25519PrivateKey(raw)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			envelope, err := vc.SealBootEnvelope(serverPriv, clientPriv.PublicKey(), salt, nonce, dek, info)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			if !bytes.Equal(envelope.Ciphertext, ciphertext) {
				t.Errorf("vector %d: re-sealed envelope does not match the vector", i)
			}
			if !bytes.Equal(envelope.ServerPublicKey, serverPubRaw) {
				t.Errorf("vector %d: server public key does not match its private key", i)
			}
		}
	}
}

// envelopeInfoFromVector rebuilds the HKDF info string and checks it against
// the info the vector carries.
func envelopeInfoFromVector(v item, clientFP, serverFP string) ([]byte, error) {
	bootID, err := str(v, "bootId", "boot")
	if err != nil {
		return nil, err
	}
	environmentID, err := str(v, "environmentId", "environment")
	if err != nil {
		return nil, err
	}
	envKeyVersion, err := num(v, "environmentKeyVersion", "envKeyVersion")
	if err != nil {
		return nil, err
	}
	if want := optionalStr(v, "clientPublicKeyFingerprint"); want != "" && want != clientFP {
		return nil, fmt.Errorf("client fingerprint = %s, want %s", clientFP, want)
	}
	if want := optionalStr(v, "serverPublicKeyFingerprint"); want != "" && want != serverFP {
		return nil, fmt.Errorf("server fingerprint = %s, want %s", serverFP, want)
	}
	built := vc.BootEnvelopeInfo(bootID, environmentID, envKeyVersion, clientFP, serverFP)
	if want := optionalStr(v, "info", "hkdfInfo"); want != "" && string(built) != want {
		return nil, fmt.Errorf("boot envelope info mismatch\n got: %q\nwant: %q", built, want)
	}
	return built, nil
}

func TestVectorResumeSignature(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "resume-signature.json") {
		bootID, err := str(v, "bootId", "boot")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		challenge, err := str(v, "challenge", "challengeB64u")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		signature := b64u(t, v, "signature", "expectedSignature")
		pub := b64u(t, v, "publicKey", "signingPublicKey")

		if want := optionalStr(v, "message", "signedMessage", "canonicalMessage"); want != "" {
			got := vc.ResumeMessage(bootID, challenge)
			if string(got) != want {
				if decoded, err := vc.DecodeB64u(want); err != nil || !bytes.Equal(got, decoded) {
					t.Errorf("vector %d: resume message mismatch\n got: %q\nwant: %q", i, got, want)
				}
			}
		}
		if seed, err := str(v, "privateKey", "signingPrivateKey", "seed"); err == nil {
			raw, err := vc.DecodeB64u(seed)
			if err != nil {
				t.Fatalf("vector %d: private key is not base64url: %v", i, err)
			}
			priv, err := ed25519PrivateFrom(raw)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			if got := vc.SignResume(priv, bootID, challenge); !bytes.Equal(got, signature) {
				t.Errorf("vector %d: signature does not match the vector", i)
			}
		}
		if !vc.VerifyResume(pub, bootID, challenge, signature) {
			t.Errorf("vector %d: the vector signature does not verify", i)
		}
	}
}

func ed25519PrivateFrom(raw []byte) (ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("ed25519 private key must be %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

func TestVectorManifestCanonical(t *testing.T) {
	dir := requireVectorDir(t)
	for i, v := range loadVectors(t, dir, "manifest-canonical.json") {
		manifest, err := lookup(v, "manifest", "input", "document")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		canonical, err := str(v, "canonical", "canonicalJson", "canonicalJSON", "expected")
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		got, err := vc.CanonicalManifestJSON(manifest)
		if err != nil {
			t.Errorf("vector %d: %v", i, err)
			continue
		}
		if string(got) != canonical {
			t.Errorf("vector %d: canonical json mismatch\n got: %s\nwant: %s", i, got, canonical)
		}
		signature := optionalStr(v, "signature")
		publicKey := optionalStr(v, "signingPublicKey", "publicKey", "signerPublicKey")
		if signature == "" || publicKey == "" {
			continue
		}
		sig, err := vc.DecodeB64u(signature)
		if err != nil {
			t.Fatalf("vector %d: signature is not base64url: %v", i, err)
		}
		pub, err := vc.DecodeB64uLen(publicKey, ed25519.PublicKeySize)
		if err != nil {
			t.Fatalf("vector %d: public key: %v", i, err)
		}
		ok, err := vc.VerifyManifest(pub, manifest, sig)
		if err != nil {
			t.Errorf("vector %d: %v", i, err)
			continue
		}
		if !ok {
			t.Errorf("vector %d: the vector manifest signature does not verify", i)
		}
		if want := optionalStr(v, "signerFingerprint"); want != "" {
			got, err := vc.Fingerprint(pub)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			if got != strings.ToLower(want) {
				t.Errorf("vector %d: signerFingerprint = %s, want %s", i, got, want)
			}
		}
		if want := optionalStr(v, "signedMessage"); want != "" {
			if string(vc.ManifestSignedMessage(got)) != want {
				t.Errorf("vector %d: signed message does not match the vector", i)
			}
		}
		if seed := optionalStr(v, "signingSeed", "seed"); seed != "" {
			raw, err := vc.DecodeB64u(seed)
			if err != nil {
				t.Fatalf("vector %d: signing seed: %v", i, err)
			}
			priv, err := ed25519PrivateFrom(raw)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			produced, err := vc.SignManifest(priv, manifest)
			if err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			if !bytes.Equal(produced, sig) {
				t.Errorf("vector %d: manifest signature does not match the vector", i)
			}
		}
	}
}
