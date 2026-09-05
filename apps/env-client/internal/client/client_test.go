package client_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ramaadi/env-vault/apps/env-client/internal/client"
	"github.com/ramaadi/env-vault/apps/env-client/internal/protocol"
)

// execRecorder captures what the client would have exec'd.
type execRecorder struct {
	called bool
	path   string
	argv   []string
	env    []string
}

func (r *execRecorder) exec(path string, argv, env []string) error {
	r.called = true
	r.path = path
	r.argv = append([]string(nil), argv...)
	r.env = append([]string(nil), env...)
	return nil
}

func baseEnviron() []string {
	return []string{
		"HOME=/home/app",
		"DATABASE_URL=postgres://placeholder/old",
		"VAULT_BOOTSTRAP_TOKEN=" + testToken,
		"VAULT_EVIDENCE_FILE=/etc/vault/evidence.json",
		"VAULT_URL=https://vault.example.com",
	}
}

func testConfig(t *testing.T, url string, logs *bytes.Buffer, recorder *execRecorder) client.Config {
	t.Helper()
	return client.Config{
		URL:            url,
		Token:          testToken,
		Claims:         protocol.Claims{Provider: &protocol.ProviderClaim{Name: "zeabur", DeploymentID: "dep_1"}},
		PendingTimeout: 20 * time.Second,
		Command:        []string{"echo", "hello"},
		Logger:         client.NewLogger(logs, client.LevelDebug),
		Exec:           recorder.exec,
		Environ:        baseEnviron(),
		BackoffMin:     5 * time.Millisecond,
		BackoffMax:     20 * time.Millisecond,
	}
}

func TestApprovedFlowExecsWithTheDecryptedEnvironment(t *testing.T) {
	vault, server := newFakeVault(t, modeApprove)
	logs := &bytes.Buffer{}
	recorder := &execRecorder{}

	session, err := client.New(testConfig(t, server.URL, logs, recorder))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := session.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	connections, consumed, proofAccepted := vault.state()
	if connections != 2 {
		t.Errorf("the client made %d connections, want 2", connections)
	}
	if !proofAccepted {
		t.Error("the resume proof was not accepted")
	}
	if !consumed {
		t.Error("the vault never marked the boot consumed")
	}
	if vault.receivedDigest != vault.approvedDigest {
		t.Error("payloadDigest did not match the frame the vault sent")
	}

	if !recorder.called {
		t.Fatal("the client never reached exec")
	}
	if !strings.HasSuffix(recorder.path, "/echo") {
		t.Errorf("exec path = %s, want a path ending in /echo", recorder.path)
	}
	if len(recorder.argv) != 2 || recorder.argv[0] != "echo" || recorder.argv[1] != "hello" {
		t.Errorf("argv = %v, want [echo hello]", recorder.argv)
	}

	env := envMap(recorder.env)
	for _, s := range testSecrets {
		if env[s.name] != s.value {
			t.Errorf("child environment is missing the decrypted value for %s", s.name)
		}
	}
	if env["HOME"] != "/home/app" {
		t.Error("the child environment lost HOME")
	}
	if _, present := env["VAULT_BOOTSTRAP_TOKEN"]; present {
		t.Error("the bootstrap token must not reach the child")
	}
	if _, present := env["VAULT_EVIDENCE_FILE"]; present {
		t.Error("the evidence file path must not reach the child")
	}
	if env["VAULT_URL"] != "https://vault.example.com" {
		t.Error("unrelated vault settings should stay in the child environment")
	}
	if occurrences(recorder.env, "DATABASE_URL") != 1 {
		t.Error("a secret must replace the existing variable, not add a second one")
	}
}

func TestApprovalLogsCarryNoSecretMaterial(t *testing.T) {
	_, server := newFakeVault(t, modeApprove)
	logs := &bytes.Buffer{}
	recorder := &execRecorder{}

	session, err := client.New(testConfig(t, server.URL, logs, recorder))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := session.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	output := logs.String()
	for _, want := range []string{
		"boot request created: " + testBootID,
		"waiting for approval",
		"reconnecting",
		"approval received",
		"environment decrypted (2 values)",
		"starting application",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("log output is missing %q\ngot:\n%s", want, output)
		}
	}
	for _, s := range testSecrets {
		if strings.Contains(output, s.value) {
			t.Errorf("log output leaked a secret value for %s", s.name)
		}
		if strings.Contains(output, s.name) {
			t.Errorf("log output leaked the secret name %s", s.name)
		}
	}
	if strings.Contains(output, testToken) {
		t.Error("log output leaked the bootstrap token")
	}
}

func TestDeclinedFlowExitsWithCodeThree(t *testing.T) {
	_, server := newFakeVault(t, modeDecline)
	logs := &bytes.Buffer{}
	recorder := &execRecorder{}

	session, err := client.New(testConfig(t, server.URL, logs, recorder))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = session.Run(ctx)
	if err == nil {
		t.Fatal("a declined boot must fail")
	}
	if code := client.ExitCode(err); code != client.ExitDeclined {
		t.Errorf("exit code = %d, want %d", code, client.ExitDeclined)
	}
	if recorder.called {
		t.Error("a declined boot must not exec anything")
	}
	if strings.Contains(logs.String(), "starting application") {
		t.Error("a declined boot must not log a start")
	}
}

func TestWrongResumeSignatureIsRejected(t *testing.T) {
	vault, server := newFakeVault(t, modeWrongSignature)
	logs := &bytes.Buffer{}
	recorder := &execRecorder{}

	session, err := client.New(testConfig(t, server.URL, logs, recorder))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = session.Run(ctx)
	if err == nil {
		t.Fatal("a rejected resume proof must fail the boot")
	}
	if code := client.ExitCode(err); code != client.ExitProtocol {
		t.Errorf("exit code = %d, want %d", code, client.ExitProtocol)
	}
	if _, _, proofAccepted := vault.state(); proofAccepted {
		t.Error("the vault must not accept a proof made with another key")
	}
	if recorder.called {
		t.Error("a rejected proof must not exec anything")
	}
}

func TestUnauthorizedUpgradeIsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	logs := &bytes.Buffer{}
	recorder := &execRecorder{}
	session, err := client.New(testConfig(t, server.URL, logs, recorder))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = session.Run(ctx)
	if err == nil {
		t.Fatal("a 401 upgrade must fail immediately")
	}
	if code := client.ExitCode(err); code != client.ExitProtocol {
		t.Errorf("exit code = %d, want %d", code, client.ExitProtocol)
	}
	if strings.Contains(logs.String(), "reconnecting") {
		t.Error("a rejected token must not be retried")
	}
}

func TestPendingTimeoutExpires(t *testing.T) {
	// A vault that is down for the whole pending window.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	logs := &bytes.Buffer{}
	recorder := &execRecorder{}
	cfg := testConfig(t, server.URL, logs, recorder)
	cfg.PendingTimeout = 120 * time.Millisecond
	session, err := client.New(cfg)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	err = session.Run(context.Background())
	if err == nil {
		t.Fatal("an unreachable vault must eventually fail")
	}
	if code := client.ExitCode(err); code != client.ExitExpired {
		t.Errorf("exit code = %d, want %d", code, client.ExitExpired)
	}
	if !strings.Contains(logs.String(), "reconnecting") {
		t.Error("a retry must be logged")
	}
}

func TestNewRejectsBadConfiguration(t *testing.T) {
	logs := &bytes.Buffer{}
	recorder := &execRecorder{}
	base := testConfig(t, "https://vault.example.com", logs, recorder)

	t.Run("no command", func(t *testing.T) {
		cfg := base
		cfg.Command = nil
		assertConfigError(t, cfg)
	})
	t.Run("bad token", func(t *testing.T) {
		cfg := base
		cfg.Token = "not-a-token"
		assertConfigError(t, cfg)
	})
	t.Run("bad url", func(t *testing.T) {
		cfg := base
		cfg.URL = "ftp://vault.example.com"
		assertConfigError(t, cfg)
	})
	t.Run("no url", func(t *testing.T) {
		cfg := base
		cfg.URL = ""
		assertConfigError(t, cfg)
	})
}

func assertConfigError(t *testing.T, cfg client.Config) {
	t.Helper()
	_, err := client.New(cfg)
	if err == nil {
		t.Fatal("the configuration must be rejected")
	}
	var exit *client.ExitError
	if !errors.As(err, &exit) || exit.Code != client.ExitConfig {
		t.Fatalf("error = %v, want exit code %d", err, client.ExitConfig)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"https://vault.example.com":               "wss://vault.example.com/bootstrap/v1",
		"https://vault.example.com/":              "wss://vault.example.com/bootstrap/v1",
		"http://127.0.0.1:8787":                   "ws://127.0.0.1:8787/bootstrap/v1",
		"wss://vault.example.com/bootstrap/v1":    "wss://vault.example.com/bootstrap/v1",
		"wss://vault.example.com/custom/endpoint": "wss://vault.example.com/custom/endpoint",
	}
	for in, want := range cases {
		got, err := client.NormalizeURL(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s normalised to %s, want %s", in, got, want)
		}
	}
	for _, in := range []string{"", "ftp://vault.example.com", "vault.example.com", "https://"} {
		if _, err := client.NormalizeURL(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]client.Level{
		"":      client.LevelInfo,
		"info":  client.LevelInfo,
		"DEBUG": client.LevelDebug,
		"warn":  client.LevelWarn,
		"error": client.LevelError,
	} {
		got, err := client.ParseLevel(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q parsed to %v, want %v", in, got, want)
		}
	}
	if _, err := client.ParseLevel("chatty"); err == nil {
		t.Error("an unknown level must be rejected")
	}
}

func envMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		out[name] = value
	}
	return out
}

func occurrences(env []string, name string) int {
	count := 0
	for _, entry := range env {
		if strings.HasPrefix(entry, name+"=") {
			count++
		}
	}
	return count
}
