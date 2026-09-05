//go:build unix

package run

import (
	"fmt"
	"syscall"
)

// Exec replaces the current process with the target command. On success it
// never returns.
func Exec(path string, argv, env []string) error {
	if err := syscall.Exec(path, argv, env); err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return nil
}
