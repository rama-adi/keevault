package client

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"

	"github.com/ramaadi/keevault/apps/env-client/internal/protocol"
)

// Version is set by the release build. Unstamped builds report dev.
var Version = "dev"

// executableClaim hashes the executable file once per session. These values
// remain untrusted: neither a file hash nor a build version attests running code.
func executableClaim() (protocol.ClientClaim, error) {
	claim := protocol.ClientClaim{Version: Version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	path := "/proc/self/exe"
	if runtime.GOOS != "linux" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return claim, err
		}
	}
	digest, err := hashExecutable(path)
	if err != nil {
		return claim, err
	}
	claim.SHA256 = digest
	return claim, nil
}

func hashExecutable(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
