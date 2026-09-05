// Package run builds the child environment and replaces the bootstrap process
// with the target command.
package run

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Secret is one decrypted value bound for the child environment. Value stays
// a byte slice so the caller can overwrite it once the environment is built.
type Secret struct {
	Name  string
	Value []byte
}

// NamePattern is the POSIX environment variable name rule secrets must match.
var NamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,255}$`)

// ValidName reports whether name is an acceptable secret name.
func ValidName(name string) bool { return NamePattern.MatchString(name) }

// StrippedNames are removed from the child environment. The bootstrap token is
// a credential the application must not inherit, and the evidence file path
// has already been consumed.
var StrippedNames = []string{"VAULT_BOOTSTRAP_TOKEN", "VAULT_EVIDENCE_FILE"}

// ExecFunc replaces the current process with another program. It only returns
// on failure.
type ExecFunc func(path string, argv, env []string) error

// ErrDuplicateSecret is returned when two secrets share a name.
var ErrDuplicateSecret = errors.New("duplicate secret name")

// BuildEnv returns the child environment: base with the stripped names removed
// and the secrets applied. A secret replaces an existing variable in place and
// keeps its position; new names are appended in the order given.
func BuildEnv(base []string, secrets []Secret) ([]string, error) {
	index := make(map[string]int, len(base))
	out := make([]string, 0, len(base)+len(secrets))
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if isStripped(name) {
			continue
		}
		if prev, dup := index[name]; dup {
			out[prev] = entry
			continue
		}
		index[name] = len(out)
		out = append(out, entry)
	}
	seen := make(map[string]struct{}, len(secrets))
	for _, s := range secrets {
		if !ValidName(s.Name) {
			return nil, fmt.Errorf("secret name is not a POSIX environment name")
		}
		if _, dup := seen[s.Name]; dup {
			return nil, ErrDuplicateSecret
		}
		seen[s.Name] = struct{}{}
		entry := s.Name + "=" + string(s.Value)
		if pos, exists := index[s.Name]; exists {
			out[pos] = entry
			continue
		}
		index[s.Name] = len(out)
		out = append(out, entry)
	}
	return out, nil
}

func isStripped(name string) bool {
	for _, s := range StrippedNames {
		if name == s {
			return true
		}
	}
	return false
}

// LookPath resolves the target command against PATH.
func LookPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("cannot run %s: %w", name, err)
	}
	return path, nil
}
