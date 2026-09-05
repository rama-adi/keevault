package vaultcrypto

import "strconv"

func join(lines []string) []byte {
	total := 0
	for i, l := range lines {
		if i > 0 {
			total++
		}
		total += len(l)
	}
	out := make([]byte, 0, total)
	for i, l := range lines {
		if i > 0 {
			out = append(out, '\n')
		}
		out = append(out, l...)
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }

// ProjectKeyAAD is the additional data for wrapping a project key under a
// master key.
func ProjectKeyAAD(projectID string, projectKeyVersion, masterKeyVersion int) []byte {
	return join([]string{
		"vault:project-key:v1",
		"project=" + projectID,
		"version=" + itoa(projectKeyVersion),
		"master=" + itoa(masterKeyVersion),
	})
}

// EnvironmentKeyAAD is the additional data for wrapping an environment key
// under a project key.
func EnvironmentKeyAAD(projectID, environmentID string, envKeyVersion, projectKeyVersion int) []byte {
	return join([]string{
		"vault:environment-key:v1",
		"project=" + projectID,
		"environment=" + environmentID,
		"version=" + itoa(envKeyVersion),
		"project_key_version=" + itoa(projectKeyVersion),
	})
}

// SecretAAD is the additional data for one encrypted secret value under an
// environment key.
func SecretAAD(projectID, environmentID, secretID, name string, secretVersion, envKeyVersion int) []byte {
	return join([]string{
		"vault:secret:v1",
		"project=" + projectID,
		"environment=" + environmentID,
		"secret=" + secretID,
		"name=" + name,
		"version=" + itoa(secretVersion),
		"env_key_version=" + itoa(envKeyVersion),
	})
}

// BootEnvelopeInfo is the HKDF info string and the AES-GCM additional data for
// the boot key envelope. clientFingerprint and serverFingerprint are the
// lowercase hex SHA-256 fingerprints of the two X25519 public keys.
func BootEnvelopeInfo(bootID, environmentID string, envKeyVersion int, clientFingerprint, serverFingerprint string) []byte {
	return join([]string{
		"vault:boot-envelope:v1",
		"boot=" + bootID,
		"environment=" + environmentID,
		"env_key_version=" + itoa(envKeyVersion),
		"client=" + clientFingerprint,
		"server=" + serverFingerprint,
	})
}

// ResumeMessage is the exact message a client signs to prove possession of the
// boot signing key. challenge is the b64u challenge string exactly as received.
func ResumeMessage(bootID, challenge string) []byte {
	return join([]string{
		"vault-resume:v1",
		bootID,
		challenge,
	})
}
