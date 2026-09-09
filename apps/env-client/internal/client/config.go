// Package client runs one boot session: it authenticates, waits for approval,
// decrypts the environment and replaces the process with the target command.
package client

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ramaadi/keevault/apps/env-client/internal/protocol"
	"github.com/ramaadi/keevault/apps/env-client/internal/run"
)

// Process exit codes. Zero never happens because a successful boot replaces
// the process with the target command.
const (
	// ExitConfig means the configuration is unusable.
	ExitConfig = 2
	// ExitDeclined means an administrator refused the boot.
	ExitDeclined = 3
	// ExitExpired means the boot expired, was canceled, or the pending
	// timeout ran out.
	ExitExpired = 4
	// ExitProtocol means an unrecoverable transport or protocol failure.
	ExitProtocol = 5
)

// ExitError carries the process exit code for a failed boot.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }

// Unwrap returns the underlying cause.
func (e *ExitError) Unwrap() error { return e.Err }

func exitf(code int, format string, args ...any) *ExitError {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// ExitCode returns the exit code for err, or ExitProtocol if err carries none.
func ExitCode(err error) int {
	var e *ExitError
	if errors.As(err, &e) {
		return e.Code
	}
	return ExitProtocol
}

// Config is everything one boot session needs.
type Config struct {
	// URL is the vault endpoint. https, http, wss and ws are accepted.
	URL string
	// EnvironmentID pins the environment authorized by the bootstrap token.
	EnvironmentID string
	// RequiredSecrets must all be delivered before acknowledging approval.
	RequiredSecrets []string
	// Token is the bootstrap token sent as a bearer credential.
	Token string
	// Claims is the untrusted provenance claim block.
	Claims protocol.Claims
	// Evidence is attached to boot.hello unchanged.
	Evidence []protocol.Evidence
	// PendingTimeout bounds the whole session.
	PendingTimeout time.Duration
	// Command is the target argv. Command[0] is looked up on PATH.
	Command []string
	// Logger receives status lines. Required.
	Logger *Logger
	// Exec replaces this process. Tests inject a recorder here.
	Exec run.ExecFunc
	// Environ is the base environment for the child. Defaults to os.Environ.
	Environ []string
	// BackoffMin and BackoffMax bound the reconnect delay.
	BackoffMin, BackoffMax time.Duration
	// HandshakeTimeout bounds the WebSocket upgrade request.
	HandshakeTimeout time.Duration
}

// DefaultPendingTimeout matches the server side pending TTL.
const DefaultPendingTimeout = 30 * time.Minute

// Backoff bounds from the timing policy.
const (
	DefaultBackoffMin = 1 * time.Second
	DefaultBackoffMax = 15 * time.Second
)

func (c *Config) applyDefaults() {
	if c.PendingTimeout <= 0 {
		c.PendingTimeout = DefaultPendingTimeout
	}
	if c.BackoffMin <= 0 {
		c.BackoffMin = DefaultBackoffMin
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = DefaultBackoffMax
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 30 * time.Second
	}
	if c.Exec == nil {
		c.Exec = run.Exec
	}
}

// EndpointPath is appended when the configured URL carries no path.
const EndpointPath = "/bootstrap/v1"

// NormalizeURL turns a configured vault URL into a WebSocket URL. http and
// https become ws and wss. A URL without a path gets the bootstrap endpoint
// path appended.
func NormalizeURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("VAULT_URL is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("VAULT_URL is not a URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "wss", "ws":
	default:
		return "", fmt.Errorf("VAULT_URL scheme %q is not supported, use https or wss", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("VAULT_URL has no host")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = EndpointPath
	}
	u.Fragment = ""
	return u.String(), nil
}
