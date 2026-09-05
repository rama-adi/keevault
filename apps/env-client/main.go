// Command vault-bootstrap fetches an approved environment from the vault and
// replaces itself with the target command.
//
// Usage:
//
//	vault-bootstrap [flags] -- <command> [args...]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ramaadi/env-vault/apps/env-client/internal/client"
	"github.com/ramaadi/env-vault/apps/env-client/internal/protocol"
)

func main() {
	code := runMain(os.Args[1:], os.Stderr)
	os.Exit(code)
}

func runMain(args []string, stderr io.Writer) int {
	settings, command, err := parseArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "vault-bootstrap: %v\n", err)
		return client.ExitCode(err)
	}

	level, err := client.ParseLevel(settings.logLevel)
	if err != nil {
		fmt.Fprintf(stderr, "vault-bootstrap: %v\n", err)
		return client.ExitConfig
	}
	logger := client.NewLogger(stderr, level)

	cfg, err := settings.config(command, logger)
	if err != nil {
		fmt.Fprintf(stderr, "vault-bootstrap: %v\n", err)
		return client.ExitCode(err)
	}

	session, err := client.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "vault-bootstrap: %v\n", err)
		return client.ExitCode(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := session.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "vault-bootstrap: %v\n", err)
		return client.ExitCode(err)
	}
	return client.ExitProtocol
}

type settings struct {
	url            string
	token          string
	gitRepository  string
	gitCommit      string
	ociRepository  string
	ociDigest      string
	deploymentID   string
	provider       string
	evidenceFile   string
	pendingTimeout string
	logLevel       string
}

func env(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func parseArgs(args []string, stderr io.Writer) (settings, []string, error) {
	var s settings
	fs := flag.NewFlagSet("vault-bootstrap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	fs.StringVar(&s.url, "vault-url", env("VAULT_URL"), "vault endpoint, https or wss")
	fs.StringVar(&s.token, "vault-bootstrap-token", env("VAULT_BOOTSTRAP_TOKEN"), "bootstrap token")
	fs.StringVar(&s.gitRepository, "vault-git-repository", env("VAULT_GIT_REPOSITORY"), "git repository claim")
	fs.StringVar(&s.gitCommit, "vault-git-commit", env("VAULT_GIT_COMMIT"), "git commit claim")
	fs.StringVar(&s.ociRepository, "vault-oci-repository", env("VAULT_OCI_REPOSITORY"), "container image repository claim")
	fs.StringVar(&s.ociDigest, "vault-oci-digest", env("VAULT_OCI_DIGEST"), "container image digest claim")
	fs.StringVar(&s.deploymentID, "vault-deployment-id", env("VAULT_DEPLOYMENT_ID"), "provider deployment id claim")
	fs.StringVar(&s.provider, "vault-provider", env("VAULT_PROVIDER"), "provider name claim, defaults to zeabur when a deployment id is set")
	fs.StringVar(&s.evidenceFile, "vault-evidence-file", env("VAULT_EVIDENCE_FILE"), "path to a JSON array of evidence items")
	fs.StringVar(&s.pendingTimeout, "vault-pending-timeout", env("VAULT_PENDING_TIMEOUT"), "how long to wait for approval, default 30m")
	fs.StringVar(&s.logLevel, "vault-log-level", env("VAULT_LOG_LEVEL"), "debug, info, warn or error")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return settings{}, nil, &client.ExitError{Code: client.ExitConfig, Err: errors.New("no command given")}
		}
		return settings{}, nil, &client.ExitError{Code: client.ExitConfig, Err: err}
	}
	command := fs.Args()
	if len(command) == 0 {
		fs.Usage()
		return settings{}, nil, &client.ExitError{
			Code: client.ExitConfig,
			Err:  errors.New("no command given, use: vault-bootstrap [flags] -- <command> [args...]"),
		}
	}
	return s, command, nil
}

const usage = `vault-bootstrap fetches an approved environment from the vault and then
replaces itself with the target command.

Usage:
  vault-bootstrap [flags] -- <command> [args...]

Every flag has an environment variable of the same name in upper snake case,
for example --vault-url and VAULT_URL. The flag wins when both are set.

Flags:
`

func (s settings) config(command []string, logger *client.Logger) (client.Config, error) {
	timeout := client.DefaultPendingTimeout
	if s.pendingTimeout != "" {
		parsed, err := time.ParseDuration(s.pendingTimeout)
		if err != nil {
			return client.Config{}, &client.ExitError{
				Code: client.ExitConfig,
				Err:  fmt.Errorf("VAULT_PENDING_TIMEOUT: %w", err),
			}
		}
		if parsed <= 0 {
			return client.Config{}, &client.ExitError{
				Code: client.ExitConfig,
				Err:  errors.New("VAULT_PENDING_TIMEOUT must be positive"),
			}
		}
		timeout = parsed
	}

	claims, err := s.claims()
	if err != nil {
		return client.Config{}, err
	}
	evidence, err := loadEvidence(s.evidenceFile)
	if err != nil {
		return client.Config{}, err
	}

	return client.Config{
		URL:            s.url,
		Token:          s.token,
		Claims:         claims,
		Evidence:       evidence,
		PendingTimeout: timeout,
		Command:        command,
		Logger:         logger,
	}, nil
}

func (s settings) claims() (protocol.Claims, error) {
	var claims protocol.Claims
	switch {
	case s.gitRepository != "" && s.gitCommit != "":
		claims.Git = &protocol.GitClaim{Repository: s.gitRepository, Commit: s.gitCommit}
	case s.gitRepository != "" || s.gitCommit != "":
		return claims, &client.ExitError{
			Code: client.ExitConfig,
			Err:  errors.New("VAULT_GIT_REPOSITORY and VAULT_GIT_COMMIT must be set together"),
		}
	}
	switch {
	case s.ociRepository != "" && s.ociDigest != "":
		claims.OCI = &protocol.OCIClaim{Repository: s.ociRepository, Digest: s.ociDigest}
	case s.ociRepository != "" || s.ociDigest != "":
		return claims, &client.ExitError{
			Code: client.ExitConfig,
			Err:  errors.New("VAULT_OCI_REPOSITORY and VAULT_OCI_DIGEST must be set together"),
		}
	}
	name := s.provider
	if name == "" && s.deploymentID != "" {
		name = "zeabur"
	}
	if name != "" {
		claims.Provider = &protocol.ProviderClaim{Name: name, DeploymentID: s.deploymentID}
	}
	return claims, nil
}

func loadEvidence(path string) ([]protocol.Evidence, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, &client.ExitError{
			Code: client.ExitConfig,
			Err:  fmt.Errorf("VAULT_EVIDENCE_FILE: %w", err),
		}
	}
	var evidence []protocol.Evidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return nil, &client.ExitError{
			Code: client.ExitConfig,
			Err:  fmt.Errorf("VAULT_EVIDENCE_FILE must hold a JSON array of evidence items: %w", err),
		}
	}
	for i, item := range evidence {
		if item.Type == "" {
			return nil, &client.ExitError{
				Code: client.ExitConfig,
				Err:  fmt.Errorf("VAULT_EVIDENCE_FILE item %d has no type", i),
			}
		}
	}
	return evidence, nil
}
