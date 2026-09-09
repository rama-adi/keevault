package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ramaadi/keevault/apps/env-client/internal/client"
)

func TestParseArgsPrefersFlagsOverEnvironment(t *testing.T) {
	t.Setenv("VAULT_URL", "https://from-env.example.com")
	t.Setenv("VAULT_BOOTSTRAP_TOKEN", "token-from-env")

	got, command, err := parseArgs([]string{"--vault-url", "https://from-flag.example.com", "--", "node", "server.js"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.url != "https://from-flag.example.com" {
		t.Errorf("url = %s, want the flag value", got.url)
	}
	if got.token != "token-from-env" {
		t.Errorf("token = %s, want the environment value", got.token)
	}
	if strings.Join(command, " ") != "node server.js" {
		t.Errorf("command = %v, want [node server.js]", command)
	}
}

func TestParseArgsRequiresACommand(t *testing.T) {
	_, _, err := parseArgs([]string{"--vault-url", "https://vault.example.com"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("a run without a command must fail")
	}
	if code := client.ExitCode(err); code != client.ExitConfig {
		t.Errorf("exit code = %d, want %d", code, client.ExitConfig)
	}
}

func TestClaims(t *testing.T) {
	t.Run("provider defaults to zeabur with a deployment id", func(t *testing.T) {
		claims, err := settings{deploymentID: "dep_1"}.claims()
		if err != nil {
			t.Fatalf("claims: %v", err)
		}
		if claims.Provider == nil || claims.Provider.Name != "zeabur" || claims.Provider.DeploymentID != "dep_1" {
			t.Fatalf("provider claim = %+v", claims.Provider)
		}
	})
	t.Run("no provider claim without a deployment id or a name", func(t *testing.T) {
		claims, err := settings{}.claims()
		if err != nil {
			t.Fatalf("claims: %v", err)
		}
		if claims.Provider != nil {
			t.Fatalf("provider claim = %+v, want none", claims.Provider)
		}
	})
	t.Run("explicit provider wins", func(t *testing.T) {
		claims, err := settings{provider: "fly", deploymentID: "dep_1"}.claims()
		if err != nil {
			t.Fatalf("claims: %v", err)
		}
		if claims.Provider.Name != "fly" {
			t.Fatalf("provider name = %s, want fly", claims.Provider.Name)
		}
	})
	t.Run("git and oci pairs", func(t *testing.T) {
		claims, err := settings{
			gitRepository: "github.com/acme/app",
			gitCommit:     "abc",
			ociRepository: "ghcr.io/acme/app",
			ociDigest:     "sha256:aa",
		}.claims()
		if err != nil {
			t.Fatalf("claims: %v", err)
		}
		if claims.Git == nil || claims.OCI == nil {
			t.Fatal("both claims must be present")
		}
		if _, err := (settings{gitRepository: "github.com/acme/app"}).claims(); err == nil {
			t.Error("a git repository without a commit must be rejected")
		}
		if _, err := (settings{ociDigest: "sha256:aa"}).claims(); err == nil {
			t.Error("an oci digest without a repository must be rejected")
		}
	})
}

func TestPendingTimeout(t *testing.T) {
	logger := client.NewLogger(&bytes.Buffer{}, client.LevelInfo)
	base := settings{url: "https://vault.example.com", token: "t"}

	cfg, err := base.config([]string{"true"}, logger)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.PendingTimeout != client.DefaultPendingTimeout {
		t.Errorf("default pending timeout = %s, want %s", cfg.PendingTimeout, client.DefaultPendingTimeout)
	}

	withValue := base
	withValue.pendingTimeout = "90s"
	cfg, err = withValue.config([]string{"true"}, logger)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.PendingTimeout != 90*time.Second {
		t.Errorf("pending timeout = %s, want 90s", cfg.PendingTimeout)
	}

	for _, bad := range []string{"soon", "-1m", "0"} {
		broken := base
		broken.pendingTimeout = bad
		if _, err := broken.config([]string{"true"}, logger); err == nil {
			t.Errorf("pending timeout %q must be rejected", bad)
		}
	}
}

func TestLoadEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	content := `[{"type":"signed-build-manifest-v1","manifest":{"version":1},"signature":"AA","signerFingerprint":"ab"}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	evidence, err := loadEvidence(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(evidence) != 1 || evidence[0].Type != "signed-build-manifest-v1" {
		t.Fatalf("evidence = %+v", evidence)
	}
	if string(evidence[0].Manifest) != `{"version":1}` {
		t.Fatalf("the manifest must stay raw json, got %s", evidence[0].Manifest)
	}

	if got, err := loadEvidence(""); err != nil || got != nil {
		t.Fatal("no evidence file means no evidence")
	}
	if _, err := loadEvidence(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing evidence file must be an error")
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"type":"x"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadEvidence(broken); err == nil {
		t.Error("evidence must be a json array")
	}

	untyped := filepath.Join(dir, "untyped.json")
	if err := os.WriteFile(untyped, []byte(`[{"signature":"AA"}]`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadEvidence(untyped); err == nil {
		t.Error("an evidence item without a type must be rejected")
	}
}

func TestRunMainReportsConfigErrors(t *testing.T) {
	t.Setenv("VAULT_URL", "")
	t.Setenv("VAULT_BOOTSTRAP_TOKEN", "")
	stderr := &bytes.Buffer{}
	if code := runMain([]string{"--", "true"}, stderr); code != client.ExitConfig {
		t.Fatalf("exit code = %d, want %d", code, client.ExitConfig)
	}
	if !strings.Contains(stderr.String(), "keevault:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
