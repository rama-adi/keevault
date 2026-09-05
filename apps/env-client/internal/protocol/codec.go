package protocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrUnknownType is returned for a frame whose type is not part of v1.
var ErrUnknownType = errors.New("unknown message type")

// b64u decodes strictly: a string whose trailing slack bits are non-zero is
// rejected, matching the TypeScript parser.
var b64u = base64.RawURLEncoding.Strict()

type envelopeType struct {
	Type string `json:"type"`
}

// Encode serialises a message as one text frame. HTML escaping is off so the
// bytes match what the TypeScript side produces.
func Encode(m Message) ([]byte, error) {
	var buf bytes.Buffer
	enc := newEncoder(&buf)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("encode %s: %w", m.MessageType(), err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Decode parses one text frame into a typed message and validates the length
// of every base64url field it carries.
func Decode(frame []byte) (Message, error) {
	var head envelopeType
	if err := unmarshalStrict(frame, &head); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	switch head.Type {
	case TypeHello:
		return decodeInto[Hello](frame, validateHello)
	case TypeResume:
		return decodeInto[Resume](frame, validateResume)
	case TypeChallengeResponse:
		return decodeInto[ChallengeResponse](frame, validateChallengeResponse)
	case TypeReceived:
		return decodeInto[Received](frame, validateReceived)
	case TypePending:
		return decodeInto[Pending](frame, validatePending)
	case TypeChallenge:
		return decodeInto[Challenge](frame, validateChallenge)
	case TypeResumed:
		return decodeInto[Resumed](frame, validateResumed)
	case TypeApproved:
		return decodeInto[Approved](frame, validateApproved)
	case TypeDeclined:
		return decodeInto[Declined](frame, requireBootID(func(m Declined) string { return m.BootID }))
	case TypeExpired:
		return decodeInto[Expired](frame, requireBootID(func(m Expired) string { return m.BootID }))
	case TypeCanceled:
		return decodeInto[Canceled](frame, requireBootID(func(m Canceled) string { return m.BootID }))
	case TypeConsumed:
		return decodeInto[Consumed](frame, requireBootID(func(m Consumed) string { return m.BootID }))
	case TypeError:
		return decodeInto[Error](frame, validateError)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, head.Type)
	}
}

func decodeInto[T Message](frame []byte, validate func(T) error) (Message, error) {
	var m T
	if err := unmarshalStrict(frame, &m); err != nil {
		return nil, fmt.Errorf("decode %s: %w", m.MessageType(), err)
	}
	if err := validate(m); err != nil {
		return nil, fmt.Errorf("decode %s: %w", m.MessageType(), err)
	}
	return m, nil
}

func requireBootID[T Message](get func(T) string) func(T) error {
	return func(m T) error {
		if get(m) == "" {
			return errors.New("bootId is missing")
		}
		return nil
	}
}

func checkLen(field, value string, want int) error {
	raw, err := b64u.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s is not unpadded base64url", field)
	}
	if len(raw) != want {
		return fmt.Errorf("%s must decode to %d bytes, got %d", field, want, len(raw))
	}
	return nil
}

func checkMinLen(field, value string, min int) error {
	raw, err := b64u.DecodeString(value)
	if err != nil {
		return fmt.Errorf("%s is not unpadded base64url", field)
	}
	if len(raw) < min {
		return fmt.Errorf("%s must decode to at least %d bytes, got %d", field, min, len(raw))
	}
	return nil
}

func validateHello(m Hello) error {
	if m.Protocol != Version {
		return fmt.Errorf("protocol must be %d, got %d", Version, m.Protocol)
	}
	if err := checkMinLen("bootNonce", m.BootNonce, 16); err != nil {
		return err
	}
	if err := checkLen("signingPublicKey", m.SigningPublicKey, 32); err != nil {
		return err
	}
	return checkLen("encryptionPublicKey", m.EncryptionPublicKey, 32)
}

func validateResume(m Resume) error {
	if m.Protocol != Version {
		return fmt.Errorf("protocol must be %d, got %d", Version, m.Protocol)
	}
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	return nil
}

func validateChallengeResponse(m ChallengeResponse) error {
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	return checkLen("signature", m.Signature, 64)
}

func validateReceived(m Received) error {
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	if len(m.PayloadDigest) != 64 {
		return fmt.Errorf("payloadDigest must be 64 hex characters, got %d", len(m.PayloadDigest))
	}
	for _, c := range m.PayloadDigest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errors.New("payloadDigest must be lowercase hex")
		}
	}
	return nil
}

func validatePending(m Pending) error {
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	if m.ExpiresAt == "" {
		return errors.New("expiresAt is missing")
	}
	return nil
}

func validateChallenge(m Challenge) error {
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	return checkLen("challenge", m.Challenge, 32)
}

func validateResumed(m Resumed) error {
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	switch m.Status {
	case StatusPending, StatusApproved, StatusDelivered, StatusConsumed:
		return nil
	default:
		return fmt.Errorf("status %q is not a resumable state", m.Status)
	}
}

func validateApproved(m Approved) error {
	if m.BootID == "" {
		return errors.New("bootId is missing")
	}
	if m.EnvironmentID == "" || m.ProjectID == "" {
		return errors.New("environmentId and projectId are required")
	}
	if m.EnvironmentKeyVersion < 1 {
		return fmt.Errorf("environmentKeyVersion must be at least 1, got %d", m.EnvironmentKeyVersion)
	}
	if err := checkLen("keyEnvelope.serverPublicKey", m.KeyEnvelope.ServerPublicKey, 32); err != nil {
		return err
	}
	if err := checkLen("keyEnvelope.salt", m.KeyEnvelope.Salt, 32); err != nil {
		return err
	}
	if err := checkLen("keyEnvelope.nonce", m.KeyEnvelope.Nonce, 12); err != nil {
		return err
	}
	if err := checkLen("keyEnvelope.ciphertext", m.KeyEnvelope.Ciphertext, 48); err != nil {
		return err
	}
	if len(m.Secrets) > MaxSecretsPerPayload {
		return fmt.Errorf("payload carries %d secrets, over the limit of %d", len(m.Secrets), MaxSecretsPerPayload)
	}
	for i, s := range m.Secrets {
		if s.ID == "" || s.Name == "" {
			return fmt.Errorf("secrets[%d] is missing id or name", i)
		}
		if s.Version < 1 {
			return fmt.Errorf("secrets[%d].version must be at least 1, got %d", i, s.Version)
		}
		if s.EnvKeyVersion < 1 {
			return fmt.Errorf("secrets[%d].envKeyVersion must be at least 1, got %d", i, s.EnvKeyVersion)
		}
		if err := checkLen(fmt.Sprintf("secrets[%d].nonce", i), s.Nonce, 12); err != nil {
			return err
		}
		if err := checkMinLen(fmt.Sprintf("secrets[%d].ciphertext", i), s.Ciphertext, 16); err != nil {
			return err
		}
	}
	return nil
}

func validateError(m Error) error {
	if m.Code == 0 {
		return errors.New("code is missing")
	}
	return nil
}
