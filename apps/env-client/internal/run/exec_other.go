//go:build !unix

package run

import "errors"

// Exec is not supported outside Linux and macOS. Windows has no execve
// equivalent that keeps the process identity, and V1 does not target it.
func Exec(path string, argv, env []string) error {
	return errors.New("keevault only runs on Linux and macOS")
}
