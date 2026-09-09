package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestProjectConfigPrecedence(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("VAULT_URL", "")
	t.Setenv("KEEVAULT_CONFIG", "")
	t.Setenv("KEEVAULT_ENVIRONMENT_ID", "")
	if err := os.WriteFile("keevault.json", []byte(`{"vaultUrl":"https://file.example","environmentId":"env_1","requiredSecrets":["DATABASE_URL"],"command":["node","a b.js"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	s, command, err := parseArgs(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if s.url != "https://file.example" || s.environmentID != "env_1" || !reflect.DeepEqual(command, []string{"node", "a b.js"}) || !reflect.DeepEqual(s.requiredSecrets, []string{"DATABASE_URL"}) {
		t.Fatalf("unexpected settings: %+v, %v", s, command)
	}
	t.Setenv("VAULT_URL", "https://env.example")
	t.Setenv("KEEVAULT_ENVIRONMENT_ID", "env_2")
	s, command, err = parseArgs(nil, &bytes.Buffer{})
	if err != nil || s.url != "https://env.example" || s.environmentID != "env_2" || !reflect.DeepEqual(command, []string{"node", "a b.js"}) {
		t.Fatalf("environment precedence failed: %+v %v %v", s, command, err)
	}
	s, _, err = parseArgs([]string{"--vault-url", "https://flag.example", "--environment-id", "env_3"}, &bytes.Buffer{})
	if err != nil || s.url != "https://flag.example" || s.environmentID != "env_3" {
		t.Fatalf("flag precedence failed: %+v %v", s, err)
	}
}

func TestProjectConfigRejectsInvalidFiles(t *testing.T) {
	for _, content := range []string{`{}`, `{"command":null}`, `null`, `[]`, `{`, `{ "unknown": true }`, `{} {}`, `{"command":[]}`, `{"command":"node"}`, `{"command":[""]}`, `{"command":["node","\u0000"]}`, `{"command":["node"],"requiredSecrets":["BAD-NAME"]}`, `{"command":["node"],"requiredSecrets":["A","A"]}`, `{"command":["node"],"environmentId":" env_1"}`} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadProjectConfig(path); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if _, err := loadProjectConfig(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("explicit missing config accepted")
	}
}
