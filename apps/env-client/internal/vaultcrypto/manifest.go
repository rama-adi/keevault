package vaultcrypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf16"
)

// ManifestSignaturePrefix is prepended to the canonical manifest bytes before
// signing. The trailing newline is part of the prefix.
const ManifestSignaturePrefix = "vault:signed-build-manifest:v1\n"

// ErrManifestValue is returned when a manifest contains a value that the
// canonical form does not allow.
var ErrManifestValue = errors.New("manifest value must be a string or the integer 1")

// CanonicalManifestJSON rewrites a signed build manifest into its canonical
// bytes: object keys sorted by UTF-16 code unit order at every level, no
// whitespace, and no HTML escaping. Scalar values may only be strings or the
// integer 1. Objects and arrays may nest.
func CanonicalManifestJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case string:
		writeJSONString(buf, v)
		return nil
	case json.Number:
		if v.String() != "1" {
			return fmt.Errorf("%w: found number %s", ErrManifestValue, v.String())
		}
		buf.WriteByte('1')
		return nil
	default:
		return fmt.Errorf("%w: found %T", ErrManifestValue, value)
	}
}

// lessUTF16 compares two strings by UTF-16 code unit, which is the order
// JavaScript uses for string comparison and property sorting.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

// writeJSONString writes a JSON string literal the same way JSON.stringify
// does: escape the quote, the backslash and the C0 controls, and pass every
// other code point through as UTF-8. Go's encoding/json also escapes U+2028
// and U+2029, which JSON.stringify does not, so this does not use it.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[(r>>4)&0xf])
				buf.WriteByte(hexDigits[r&0xf])
				continue
			}
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// ManifestSignedMessage returns the exact bytes covered by a manifest
// signature.
func ManifestSignedMessage(canonical []byte) []byte {
	out := make([]byte, 0, len(ManifestSignaturePrefix)+len(canonical))
	out = append(out, ManifestSignaturePrefix...)
	out = append(out, canonical...)
	return out
}

// VerifyManifest canonicalises raw and checks the Ed25519 signature over it.
func VerifyManifest(pub ed25519.PublicKey, raw, signature []byte) (bool, error) {
	canonical, err := CanonicalManifestJSON(raw)
	if err != nil {
		return false, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return false, fmt.Errorf("manifest: signer key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("manifest: signature must be %d bytes, got %d", ed25519.SignatureSize, len(signature))
	}
	return ed25519.Verify(pub, ManifestSignedMessage(canonical), signature), nil
}

// SignManifest canonicalises raw and signs it. The client never calls it. It
// exists for tests and for the fake vault server.
func SignManifest(priv ed25519.PrivateKey, raw []byte) ([]byte, error) {
	canonical, err := CanonicalManifestJSON(raw)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, ManifestSignedMessage(canonical)), nil
}
