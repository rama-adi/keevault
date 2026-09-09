package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutableClaim(t *testing.T) {
	claim, err := executableClaim()
	if err != nil {
		t.Fatal(err)
	}
	if claim.Version != Version || claim.OS != runtime.GOOS || claim.Arch != runtime.GOARCH {
		t.Fatalf("unexpected executable metadata: %+v", claim)
	}
	if len(claim.SHA256) != 64 {
		t.Fatalf("expected a SHA-256 digest, got %q", claim.SHA256)
	}
}

func TestHashExecutableReadsFileBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executable")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := hashExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("wrong digest: %s", digest)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if digest, err := hashExecutable(path); err == nil || digest != "" {
		t.Fatal("an unreadable executable must not report a hash")
	}
}
