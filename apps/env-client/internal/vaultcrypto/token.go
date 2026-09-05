package vaultcrypto

import (
	"errors"
	"regexp"
)

// ErrBadToken is returned when a bootstrap token does not match the wire
// format. The token itself is never included in the error.
var ErrBadToken = errors.New("bootstrap token has the wrong format")

var tokenPattern = regexp.MustCompile(`^vlt_boot_([0-9A-HJKMNP-TV-Z]{26})\.([A-Za-z0-9_-]{43})$`)

// BootstrapToken is a parsed bootstrap token. Secret is the 43-character b64u
// string, not the decoded bytes, because the stored hash is taken over those
// characters.
type BootstrapToken struct {
	TokenID string
	Secret  string
}

// ParseBootstrapToken splits and validates a token of the form
// vlt_boot_<26 char ULID>.<43 char b64u secret>.
func ParseBootstrapToken(token string) (BootstrapToken, error) {
	m := tokenPattern.FindStringSubmatch(token)
	if m == nil {
		return BootstrapToken{}, ErrBadToken
	}
	return BootstrapToken{TokenID: m[1], Secret: m[2]}, nil
}

// BootstrapTokenSecretHash is the lowercase hex SHA-256 over the UTF-8 bytes
// of the token secret string, which is what the vault stores.
func BootstrapTokenSecretHash(secret string) string {
	return SHA256Hex([]byte(secret))
}
