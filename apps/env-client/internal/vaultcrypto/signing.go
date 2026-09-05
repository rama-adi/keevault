package vaultcrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// GenerateEd25519 returns a fresh Ed25519 keypair for reconnect proofs.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519: %w", err)
	}
	return pub, priv, nil
}

// SignResume signs the canonical resume message for one boot and challenge.
// challenge is the b64u string exactly as received from the server.
func SignResume(priv ed25519.PrivateKey, bootID, challenge string) []byte {
	return ed25519.Sign(priv, ResumeMessage(bootID, challenge))
}

// VerifyResume checks a resume signature. The client never calls it. It exists
// for tests and for the fake vault server.
func VerifyResume(pub ed25519.PublicKey, bootID, challenge string, signature []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, ResumeMessage(bootID, challenge), signature)
}
