package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// NonceSize is the AES-GCM nonce length in bytes (96 bits).
const NonceSize = 12

// TagSize is the AES-GCM authentication tag length in bytes (128 bits).
const TagSize = 16

// KeySize is the AES-256 key length in bytes.
const KeySize = 32

// ErrOpen is returned when AES-GCM authentication fails. It deliberately
// carries no detail about the key, nonce or data.
var ErrOpen = errors.New("aes-gcm: authentication failed")

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("aes-gcm: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	return gcm, nil
}

// Open decrypts ciphertext (ct||tag) with the given key, nonce and additional
// data.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("aes-gcm: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	out, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}

// Seal encrypts plaintext and returns ct||tag. The client never calls it
// during a boot. It exists for tests and for the fake vault server.
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("aes-gcm: nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}
