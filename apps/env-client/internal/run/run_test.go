package run_test

import (
	"strings"
	"testing"

	"github.com/ramaadi/keevault/apps/env-client/internal/run"
)

func secret(name, value string) run.Secret {
	return run.Secret{Name: name, Value: []byte(value)}
}

func TestBuildEnvStripsCredentialsAndAppliesSecrets(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"DATABASE_URL=old",
		"VAULT_BOOTSTRAP_TOKEN=vlt_boot_x.y",
		"VAULT_EVIDENCE_FILE=/etc/evidence.json",
		"HOME=/home/app",
	}
	env, err := run.BuildEnv(base, []run.Secret{
		secret("DATABASE_URL", "postgres://new"),
		secret("API_KEY", "sk-live"),
	})
	if err != nil {
		t.Fatalf("build env: %v", err)
	}
	want := []string{
		"PATH=/usr/bin",
		"DATABASE_URL=postgres://new",
		"HOME=/home/app",
		"API_KEY=sk-live",
	}
	if strings.Join(env, "\n") != strings.Join(want, "\n") {
		t.Fatalf("environment mismatch\n got: %v\nwant: %v", env, want)
	}
}

func TestBuildEnvKeepsEmptyValuesAndOddEntries(t *testing.T) {
	env, err := run.BuildEnv([]string{"EMPTY=", "no-equals-sign", "A=1"}, nil)
	if err != nil {
		t.Fatalf("build env: %v", err)
	}
	want := []string{"EMPTY=", "A=1"}
	if strings.Join(env, "\n") != strings.Join(want, "\n") {
		t.Fatalf("environment mismatch\n got: %v\nwant: %v", env, want)
	}
}

func TestBuildEnvRejectsDuplicatesAndBadNames(t *testing.T) {
	if _, err := run.BuildEnv(nil, []run.Secret{secret("A", "1"), secret("A", "2")}); err == nil {
		t.Fatal("two secrets with the same name must be rejected")
	}
	for _, name := range []string{"", "lower", "1LEADING", "WITH-DASH", "WITH SPACE", strings.Repeat("A", 257)} {
		if _, err := run.BuildEnv(nil, []run.Secret{secret(name, "v")}); err == nil {
			t.Errorf("name %q must be rejected", name)
		}
	}
}

func TestValidName(t *testing.T) {
	for _, name := range []string{"A", "_A", "DATABASE_URL", "A1", strings.Repeat("A", 256)} {
		if !run.ValidName(name) {
			t.Errorf("name %q must be accepted", name)
		}
	}
	for _, name := range []string{"", "a", "1A", "A-B", strings.Repeat("A", 257)} {
		if run.ValidName(name) {
			t.Errorf("name %q must be rejected", name)
		}
	}
}

func TestLookPath(t *testing.T) {
	path, err := run.LookPath("echo")
	if err != nil {
		t.Fatalf("look path: %v", err)
	}
	if !strings.HasSuffix(path, "/echo") {
		t.Fatalf("look path returned %s", path)
	}
	if _, err := run.LookPath("keevault-no-such-command"); err == nil {
		t.Fatal("an unknown command must be an error")
	}
}
