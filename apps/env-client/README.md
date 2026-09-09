# keevault

keevault fetches an approved environment from the keevault control
plane and then replaces itself with your application. The application inherits
the decrypted secrets as ordinary environment variables. The bootstrap process
itself is gone by the time the application runs.

## Usage

```bash
keevault -- npm run start
```

Everything after `--` is the command to run. With no command arguments,
Keevault launches the command in `keevault.json` from the current directory.

```json
{
  "vaultUrl": "https://keevault.example.com",
  "environmentId": "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "requiredSecrets": ["DATABASE_URL"],
  "command": ["node", "server.js"]
}
```

All fields are optional. A command must come from the file or CLI. Use
`--config path/to/keevault.json` or `KEEVAULT_CONFIG` to select another file.
An explicitly selected file must exist. Unknown fields, malformed JSON,
invalid or duplicate secret names, files larger than 1 MiB, and invalid argv
arrays fail at startup. Required secret names must match
`^[A-Z_][A-Z0-9_]{0,255}$`.
Credentials belong in `VAULT_BOOTSTRAP_TOKEN`, never in the config file.

Flags override environment variables, which override file settings. CLI command
arguments replace the file's entire command array. Empty environment variables
fall back to file settings; an explicitly empty URL or environment-ID flag does
not. Relative paths and the command resolve from the process working directory,
not the config file's directory. `--environment-id` and
`KEEVAULT_ENVIRONMENT_ID` override `environmentId`; `--vault-url` and
`VAULT_URL` override `vaultUrl`. The command runs directly without shell
expansion. Use an explicit shell command only when shell behavior is needed.

The bootstrap token selects the environment on the server. `environmentId`
pins the expected ID and rejects an approval for another environment.
`requiredSecrets` requires those keys in the decrypted payload, even if they
already exist in the process environment. Keevault checks both requirements
before acknowledging the payload or launching the command. All delivered
secrets are passed to the application; `requiredSecrets` does not filter them.

What happens on start:

1. Generate an ephemeral Ed25519 keypair for reconnect proofs and an ephemeral
   X25519 keypair for key delivery. Neither private key leaves the process.
2. Open a WebSocket to the vault with the bootstrap token as a bearer
   credential and send the boot claims and evidence.
3. Wait for a human to approve the boot. Disconnects are retried with backoff
   from 1 to 15 seconds, and the boot is resumed by signing a server challenge.
4. Open the key envelope, decrypt every secret, acknowledge the payload, and
   wait for the server to confirm consumption, then exec the target command
   with the decrypted environment.

The bootstrap client never returns 0 itself. After replacement, the application
controls the exit status and may exit 0.

## Dockerfile

Use the [example Dockerfile](../../examples/zeabur-node-app/Dockerfile) to download
a versioned R2 binary and verify its pinned SHA-256 checksum during the image
build. See [release setup](../../docs/releases.md) for publishing binaries.
Copy `keevault.json` into the application's working directory and use
`ENTRYPOINT ["/usr/local/bin/keevault"]` to launch its configured command.

Set `VAULT_BOOTSTRAP_TOKEN` in the deployment. `VAULT_URL` can be set there or
provided by `vaultUrl` in the config file.

## Configuration

| Variable                  | Flag                      | Required           | Meaning                                                                                                                                        |
| ------------------------- | ------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `KEEVAULT_CONFIG`         | `--config`                | no                 | Config file path; defaults to `./keevault.json` when present.                                                                                  |
| `KEEVAULT_ENVIRONMENT_ID` | `--environment-id`        | no                 | Expected environment ID; overrides the config file.                                                                                            |
| `VAULT_URL`               | `--vault-url`             | yes, or `vaultUrl` | Vault endpoint. `https` and `wss` work; `http` and `ws` are also accepted for local development. An empty or `/` path becomes `/bootstrap/v1`. |
| `VAULT_BOOTSTRAP_TOKEN`   | `--vault-bootstrap-token` | yes                | Token of the form `vlt_boot_<id>.<secret>`.                                                                                                    |
| `VAULT_GIT_REPOSITORY`    | `--vault-git-repository`  | no                 | Git repository claim. Must be set together with the commit.                                                                                    |
| `VAULT_GIT_COMMIT`        | `--vault-git-commit`      | no                 | Git commit claim.                                                                                                                              |
| `VAULT_OCI_REPOSITORY`    | `--vault-oci-repository`  | no                 | Image repository claim. Must be set together with the digest.                                                                                  |
| `VAULT_OCI_DIGEST`        | `--vault-oci-digest`      | no                 | Image digest claim.                                                                                                                            |
| `VAULT_DEPLOYMENT_ID`     | `--vault-deployment-id`   | no                 | Provider deployment id claim.                                                                                                                  |
| `VAULT_PROVIDER`          | `--vault-provider`        | no                 | Provider name. Defaults to `zeabur` when a deployment id is set, and is omitted otherwise.                                                     |
| `VAULT_EVIDENCE_FILE`     | `--vault-evidence-file`   | no                 | Path to a JSON array of evidence items, sent unchanged with the boot request.                                                                  |
| `VAULT_PENDING_TIMEOUT`   | `--vault-pending-timeout` | no                 | Whole bootstrap-session timeout, including reconnects and acknowledgement. Positive Go duration, default `30m`.                                |
| `VAULT_LOG_LEVEL`         | `--vault-log-level`       | no                 | `debug`, `info`, `warn` or `error`. Default `info`.                                                                                            |

`--keevault-token` is an alias for `--vault-bootstrap-token`; both read
`VAULT_BOOTSTRAP_TOKEN` by default. When both flags appear, the last wins.

Claims are untrusted workload input. The vault treats them as hints for the
approver and verifies provenance separately.

The client removes inherited `VAULT_BOOTSTRAP_TOKEN` and `VAULT_EVIDENCE_FILE`
entries before applying decrypted secrets. Secrets with those names can therefore
add them back. Other inherited variables pass through, and a decrypted secret
replaces a variable of the same name. Executable lookup uses the client's
inherited `PATH`, before applying decrypted environment variables.

## Exit codes

| Code | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| 0    | Never returned by the bootstrap client; the launched application may return it.    |
| 2    | Configuration error, a missing required secret, or a command that cannot be found. |
| 3    | An administrator declined the boot.                                                |
| 4    | The boot expired, was canceled, or the pending timeout ran out.                    |
| 5    | Unrecoverable transport or protocol failure, including a rejected token.           |

## What is logged

All logging goes to stderr, one plain line at a time:

```text
boot request created: boot_01K4M4X31X2Z5G9C7Q8D3E6F4G
waiting for approval
reconnecting
approval received
environment decrypted (7 values)
starting application
```

Secret names, secret values, key material and the bootstrap token are never
logged at any level. `debug` adds connection and retry detail, still without
secret material. A unit test asserts that a full approval produces no log line
containing a secret name or value.

## Building

Run from `apps/env-client` with Go 1.26 or newer:

```bash
./build.sh
```

This writes static `linux/amd64` and `linux/arm64` binaries to `dist/` with
`CGO_ENABLED=0 -trimpath -ldflags "-s -w"` and fails if a binary exceeds
15 MiB. The script prints each binary's measured size.

## Tests

```bash
go test ./...
```

The suite covers the crypto primitives with tamper cases, the protocol
decoder, the shared vectors in `crypto/test-vectors` at the repository root
which are skipped when that directory is missing, and a fake vault server that walks a
full approval including a dropped connection, a resume proof, envelope
delivery and the acknowledgement digest.
