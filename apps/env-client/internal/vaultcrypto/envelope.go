package vaultcrypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// ErrZeroSharedSecret is returned when X25519 produces an all-zero shared
// secret, which means the peer sent a low-order point.
var ErrZeroSharedSecret = errors.New("x25519: all-zero shared secret")

// KeyEnvelope is the wire form of the environment DEK delivery, with every
// b64u field already decoded.
type KeyEnvelope struct {
	ServerPublicKey []byte
	Salt            []byte
	Nonce           []byte
	Ciphertext      []byte
}

// GenerateX25519 returns a fresh X25519 keypair.
func GenerateX25519() (*ecdh.PrivateKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	return key, nil
}

// X25519PublicKey parses a raw 32-byte X25519 public key.
func X25519PublicKey(raw []byte) (*ecdh.PublicKey, error) {
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	return pub, nil
}

// X25519PrivateKey parses a raw 32-byte X25519 private key.
func X25519PrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	return priv, nil
}

func sharedSecret(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	zero := make([]byte, len(shared))
	if subtle.ConstantTimeCompare(shared, zero) == 1 {
		Zero(shared)
		return nil, ErrZeroSharedSecret
	}
	return shared, nil
}

// DeriveWrapKey derives the 32-byte AES key that protects the environment DEK.
func DeriveWrapKey(priv *ecdh.PrivateKey, peer *ecdh.PublicKey, salt, info []byte) ([]byte, error) {
	shared, err := sharedSecret(priv, peer)
	if err != nil {
		return nil, err
	}
	defer Zero(shared)
	key, err := hkdf.Key(sha256.New, shared, salt, string(info), KeySize)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

// OpenBootEnvelope recovers the environment DEK from an approval envelope.
// info must be the exact bytes returned by BootEnvelopeInfo, built from the
// fingerprints of the two public keys actually used.
func OpenBootEnvelope(clientPriv *ecdh.PrivateKey, envelope KeyEnvelope, info []byte) ([]byte, error) {
	serverPub, err := X25519PublicKey(envelope.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	wrapKey, err := DeriveWrapKey(clientPriv, serverPub, envelope.Salt, info)
	if err != nil {
		return nil, err
	}
	defer Zero(wrapKey)
	dek, err := Open(wrapKey, envelope.Nonce, envelope.Ciphertext, info)
	if err != nil {
		return nil, err
	}
	if len(dek) != KeySize {
		Zero(dek)
		return nil, fmt.Errorf("boot envelope: dek must be %d bytes, got %d", KeySize, len(dek))
	}
	return dek, nil
}

// SealBootEnvelope builds an approval envelope. The client never calls it.
// It exists for tests and for the fake vault server.
func SealBootEnvelope(serverPriv *ecdh.PrivateKey, clientPub *ecdh.PublicKey, salt, nonce, dek, info []byte) (KeyEnvelope, error) {
	wrapKey, err := DeriveWrapKey(serverPriv, clientPub, salt, info)
	if err != nil {
		return KeyEnvelope{}, err
	}
	defer Zero(wrapKey)
	ciphertext, err := Seal(wrapKey, nonce, dek, info)
	if err != nil {
		return KeyEnvelope{}, err
	}
	return KeyEnvelope{
		ServerPublicKey: serverPriv.PublicKey().Bytes(),
		Salt:            salt,
		Nonce:           nonce,
		Ciphertext:      ciphertext,
	}, nil
}
