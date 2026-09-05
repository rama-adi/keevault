// Package vaultcrypto implements the env-vault key hierarchy, envelopes,
// tokens and canonical strings for the Go bootstrap client. Every encoding
// here must match the TypeScript implementation byte for byte.
package vaultcrypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// B64u is base64url without padding (RFC 4648 section 5).
var B64u = base64.RawURLEncoding

// EncodeB64u encodes bytes as unpadded base64url.
func EncodeB64u(b []byte) string {
	return B64u.EncodeToString(b)
}

// DecodeB64u decodes unpadded base64url. Padded input is rejected.
func DecodeB64u(s string) ([]byte, error) {
	b, err := B64u.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url: %w", err)
	}
	return b, nil
}

// DecodeB64uLen decodes unpadded base64url and requires an exact byte length.
func DecodeB64uLen(s string, want int) ([]byte, error) {
	b, err := DecodeB64u(s)
	if err != nil {
		return nil, err
	}
	if len(b) != want {
		return nil, fmt.Errorf("expected %d bytes, got %d", want, len(b))
	}
	return b, nil
}

// Fingerprint is the lowercase hex SHA-256 of a raw 32-byte public key.
func Fingerprint(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(publicKey))
	}
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:]), nil
}

// SHA256Hex is the lowercase hex SHA-256 of the given bytes.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Zero overwrites b with zero bytes. Best effort only: the Go runtime may have
// copied the buffer during a stack or heap move.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
