# vault-bootstrap

vault-bootstrap fetches an approved environment from the env-vault control
plane and then replaces itself with your application. The application inherits
the decrypted secrets as ordinary environment variables. The bootstrap process
itself is gone by the time the application runs.

## Usage

```bash
vault-bootstrap -- npm run start
```

Everything after `--` is the command to run. Configuration comes from
environment variables or from flags of the same name.

What happens on start:

1. Generate an ephemeral Ed25519 keypair for reconnect proofs and an ephemeral
   X25519 keypair for key delivery. Neither private key leaves the process.
2. Open a WebSocket to the vault with the bootstrap token as a bearer
   credential and send the boot claims and evidence.
3. Wait for a human to approve the boot. Disconnects are retried with backoff
   from 1 to 15 seconds, and the boot is resumed by signing a server challenge.
4. Open the key envelope, decrypt every secret, acknowledge the payload, and
   exec the target command with the decrypted environment.

The process never exits 0. On success it is replaced by the application.

## Dockerfile

```dockerfile
COPY --from=build /out/vault-bootstrap /usr/local/bin/vault-bootstrap
ENTRYPOINT ["/usr/local/bin/vault-bootstrap", "--"]
CMD ["node", "server.js"]
```

Set `VAULT_URL` and `VAULT_BOOTSTRAP_TOKEN` in the deployment, not in the
image.

## Configuration

| Variable                | Flag                      | Required | Meaning                                                                                          |
| ----------------------- | ------------------------- | -------- | ------------------------------------------------------------------------------------------------ |
| `VAULT_URL`             | `--vault-url`             | yes      | Vault endpoint. `https` and `wss` both work. A URL without a path gets `/bootstrap/v1` appended. |
| `VAULT_BOOTSTRAP_TOKEN` | `--vault-bootstrap-token` | yes      | Token of the form `vlt_boot_<id>.<secret>`.                                                      |
| `VAULT_GIT_REPOSITORY`  | `--vault-git-repository`  | no       | Git repository claim. Must be set together with the commit.                                      |
| `VAULT_GIT_COMMIT`      | `--vault-git-commit`      | no       | Git commit claim.                                                                                |
| `VAULT_OCI_REPOSITORY`  | `--vault-oci-repository`  | no       | Image repository claim. Must be set together with the digest.                                    |
| `VAULT_OCI_DIGEST`      | `--vault-oci-digest`      | no       | Image digest claim.                                                                              |
| `VAULT_DEPLOYMENT_ID`   | `--vault-deployment-id`   | no       | Provider deployment id claim.                                                                    |
| `VAULT_PROVIDER`        | `--vault-provider`        | no       | Provider name. Defaults to `zeabur` when a deployment id is set, and is omitted otherwise.       |
| `VAULT_EVIDENCE_FILE`   | `--vault-evidence-file`   | no       | Path to a JSON array of evidence items, sent unchanged with the boot request.                    |
| `VAULT_PENDING_TIMEOUT` | `--vault-pending-timeout` | no       | How long to wait for approval. Go duration syntax, default `30m`.                                |
| `VAULT_LOG_LEVEL`       | `--vault-log-level`       | no       | `debug`, `info`, `warn` or `error`. Default `info`.                                              |

Claims are untrusted workload input. The vault treats them as hints for the
approver and verifies provenance separately.

`VAULT_BOOTSTRAP_TOKEN` and `VAULT_EVIDENCE_FILE` are removed from the child
environment. Every other variable is passed through, and a decrypted secret
replaces a variable of the same name.

## Exit codes

| Code | Meaning                                                                                |
| ---- | -------------------------------------------------------------------------------------- |
| 0    | Never returned. A successful boot replaces the process with the command.               |
| 2    | Configuration error: missing or malformed settings, or a command that cannot be found. |
| 3    | An administrator declined the boot.                                                    |
| 4    | The boot expired, was canceled, or the pending timeout ran out.                        |
| 5    | Unrecoverable transport or protocol failure, including a rejected token.               |

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

```bash
./build.sh
```

This writes static `linux/amd64` and `linux/arm64` binaries to `dist/` with
`CGO_ENABLED=0 -trimpath -ldflags "-s -w"` and fails if a binary exceeds
15 MiB. Current size is about 6.5 MiB per target.

## Tests

```bash
go test ./...
```

The suite covers the crypto primitives with tamper cases, the protocol
decoder, the shared vectors in `crypto/test-vectors` at the repository root
(skipped when that directory is missing), and a fake vault server that walks a
full approval including a dropped connection, a resume proof, envelope
delivery and the acknowledgement digest.
