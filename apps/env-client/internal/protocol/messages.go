// Package protocol defines the bootstrap WebSocket protocol v1 messages, their
// JSON encoding and a decoder that returns a typed message.
package protocol

import "encoding/json"

// Version is the protocol version sent in boot.hello and boot.resume.
const Version = 1

// Message types.
const (
	TypeHello             = "boot.hello"
	TypeResume            = "boot.resume"
	TypeChallengeResponse = "boot.challenge-response"
	TypeReceived          = "boot.received"

	TypePending   = "boot.pending"
	TypeChallenge = "boot.challenge"
	TypeResumed   = "boot.resumed"
	TypeApproved  = "boot.approved"
	TypeDeclined  = "boot.declined"
	TypeExpired   = "boot.expired"
	TypeCanceled  = "boot.canceled"
	TypeConsumed  = "boot.consumed"
	TypeError     = "boot.error"
)

// Boot states reported by boot.resumed.
const (
	StatusPending   = "PENDING"
	StatusApproved  = "APPROVED"
	StatusDelivered = "DELIVERED"
)

// WebSocket close codes.
const (
	CloseNormal        = 1000
	CloseProtocolError = 4400
	CloseBadToken      = 4401
	CloseForbidden     = 4403
	CloseUnknownBoot   = 4404
	CloseConflict      = 4409
	CloseTerminal      = 4410
	CloseRateLimited   = 4429
)

// Message is one decoded protocol frame. The set of implementations is closed:
// only this package can add one.
type Message interface {
	MessageType() string
	sealedMessage()
}

// GitClaim is the untrusted git provenance claim from the workload.
type GitClaim struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
}

// OCIClaim is the untrusted container image claim from the workload.
type OCIClaim struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

// ProviderClaim is the untrusted hosting provider claim from the workload.
type ProviderClaim struct {
	Name         string `json:"name"`
	DeploymentID string `json:"deploymentId,omitempty"`
	Region       string `json:"region,omitempty"`
}

// Claims is the whole untrusted claim block.
type Claims struct {
	Git      *GitClaim      `json:"git,omitempty"`
	OCI      *OCIClaim      `json:"oci,omitempty"`
	Provider *ProviderClaim `json:"provider,omitempty"`
}

// Evidence is one evidence item. The manifest stays as raw JSON because the
// signature covers its canonical form, not a re-serialised struct.
type Evidence struct {
	Type              string          `json:"type"`
	Manifest          json.RawMessage `json:"manifest,omitempty"`
	Signature         string          `json:"signature,omitempty"`
	SignerFingerprint string          `json:"signerFingerprint,omitempty"`
}

// Hello is the first client frame.
type Hello struct {
	Type                string     `json:"type"`
	Protocol            int        `json:"protocol"`
	BootNonce           string     `json:"bootNonce"`
	SigningPublicKey    string     `json:"signingPublicKey"`
	EncryptionPublicKey string     `json:"encryptionPublicKey"`
	Claims              Claims     `json:"claims"`
	Evidence            []Evidence `json:"evidence"`
}

// Resume asks the server to reattach this connection to an existing boot.
type Resume struct {
	Type     string `json:"type"`
	Protocol int    `json:"protocol"`
	BootID   string `json:"bootId"`
}

// ChallengeResponse carries the Ed25519 proof of possession.
type ChallengeResponse struct {
	Type      string `json:"type"`
	BootID    string `json:"bootId"`
	Signature string `json:"signature"`
}

// Received acknowledges a successfully decrypted approval payload.
type Received struct {
	Type          string `json:"type"`
	BootID        string `json:"bootId"`
	PayloadDigest string `json:"payloadDigest"`
}

// Pending tells the client the boot is waiting for a human.
type Pending struct {
	Type      string `json:"type"`
	BootID    string `json:"bootId"`
	ExpiresAt string `json:"expiresAt"`
}

// Challenge carries the random resume challenge.
type Challenge struct {
	Type      string `json:"type"`
	BootID    string `json:"bootId"`
	Challenge string `json:"challenge"`
}

// Resumed confirms the connection is attached to the boot again.
type Resumed struct {
	Type      string `json:"type"`
	BootID    string `json:"bootId"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expiresAt"`
}

// KeyEnvelope is the wire form of the environment DEK delivery.
type KeyEnvelope struct {
	ServerPublicKey string `json:"serverPublicKey"`
	Salt            string `json:"salt"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// SecretRecord is one encrypted secret value.
type SecretRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       int    `json:"version"`
	EnvKeyVersion int    `json:"envKeyVersion"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

// Approved is the approval payload.
type Approved struct {
	Type                  string         `json:"type"`
	BootID                string         `json:"bootId"`
	EnvironmentID         string         `json:"environmentId"`
	ProjectID             string         `json:"projectId"`
	EnvironmentKeyVersion int            `json:"environmentKeyVersion"`
	PayloadExpiresAt      string         `json:"payloadExpiresAt"`
	KeyEnvelope           KeyEnvelope    `json:"keyEnvelope"`
	Secrets               []SecretRecord `json:"secrets"`
}

// Declined means an administrator refused the boot.
type Declined struct {
	Type   string `json:"type"`
	BootID string `json:"bootId"`
	Reason string `json:"reason,omitempty"`
}

// Expired means a TTL ran out.
type Expired struct {
	Type   string `json:"type"`
	BootID string `json:"bootId"`
}

// Canceled means the boot was revoked or the environment went away.
type Canceled struct {
	Type   string `json:"type"`
	BootID string `json:"bootId"`
	Reason string `json:"reason"`
}

// Consumed confirms the server recorded the acknowledgement.
type Consumed struct {
	Type   string `json:"type"`
	BootID string `json:"bootId"`
}

// Error is a protocol or policy failure. Code matches the close code that
// follows.
type Error struct {
	Type    string `json:"type"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (Hello) sealedMessage()             {}
func (Resume) sealedMessage()            {}
func (ChallengeResponse) sealedMessage() {}
func (Received) sealedMessage()          {}
func (Pending) sealedMessage()           {}
func (Challenge) sealedMessage()         {}
func (Resumed) sealedMessage()           {}
func (Approved) sealedMessage()          {}
func (Declined) sealedMessage()          {}
func (Expired) sealedMessage()           {}
func (Canceled) sealedMessage()          {}
func (Consumed) sealedMessage()          {}
func (Error) sealedMessage()             {}

// MessageType returns the type discriminator.
func (Hello) MessageType() string             { return TypeHello }
func (Resume) MessageType() string            { return TypeResume }
func (ChallengeResponse) MessageType() string { return TypeChallengeResponse }
func (Received) MessageType() string          { return TypeReceived }
func (Pending) MessageType() string           { return TypePending }
func (Challenge) MessageType() string         { return TypeChallenge }
func (Resumed) MessageType() string           { return TypeResumed }
func (Approved) MessageType() string          { return TypeApproved }
func (Declined) MessageType() string          { return TypeDeclined }
func (Expired) MessageType() string           { return TypeExpired }
func (Canceled) MessageType() string          { return TypeCanceled }
func (Consumed) MessageType() string          { return TypeConsumed }
func (Error) MessageType() string             { return TypeError }
