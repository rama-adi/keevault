# Zeabur Node app example

This is a minimal, dependency-free Node app that shows how to run a workload
behind keevault's bootstrap client on Zeabur. `server.js` listens on `PORT`,
answers `GET /healthz` with `200 ok`, and answers `GET /` with a JSON object
listing the names (never the values) of every environment variable starting
with `APP_`, plus the process uptime.

The Dockerfile downloads a released static `keevault` binary from R2 and verifies
its SHA-256 against the build argument you supply. It contains no Go build stage.
The entrypoint reads `keevault.json` and launches `node server.js` after approval.

## Building

Publish a release using `docs/releases.md`, then copy its trusted checksums into
your build configuration. Replace these placeholders before running:

```bash
docker build -f examples/zeabur-node-app/Dockerfile \
  --build-arg KEEVAULT_RELEASE_URL=https://downloads.example.com \
  --build-arg KEEVAULT_VERSION=v1.0.0 \
  --build-arg KEEVAULT_SHA256_AMD64='REPLACE_WITH_AMD64_SHA256' \
  --build-arg KEEVAULT_SHA256_ARM64='REPLACE_WITH_ARM64_SHA256' \
  -t zeabur-node-app-example .
```

Only the checksum
for the target architecture is required. For a multi-platform build, supply both
and use `docker buildx build --platform linux/amd64,linux/arm64`.

The example config defines the command. Add `environmentId` to pin the intended
environment and `requiredSecrets` to fail before launch if a needed secret is
missing. The bootstrap token determines which environment the server releases.
Keep the token in runtime environment variables, never in `keevault.json`.

## Running locally against a vault dev server

Point the container at a running keevault control plane and a bootstrap
token for one environment:

```bash
docker run --rm -p 3000:3000 \
  -e VAULT_URL=https://your-dev-vault.example.com \
  -e VAULT_BOOTSTRAP_TOKEN=vlt_boot_<id>.<secret> \
  zeabur-node-app-example
```

The container logs reconnect and approval status to stderr. It does not
listen on port 3000, and `/healthz` does not answer, until an administrator
approves the boot on the dashboard. This is expected: see "Readiness" below.

## Zeabur variables

Set these as Zeabur environment variables on the service, not as build
arguments and not in the image:

| Variable                | Required | Meaning                                                      |
| ----------------------- | -------- | ------------------------------------------------------------ |
| `VAULT_URL`             | yes      | The keevault control plane endpoint.                         |
| `VAULT_BOOTSTRAP_TOKEN` | yes      | The bootstrap token for this environment.                    |
| `VAULT_GIT_REPOSITORY`  | no       | Git repository claim. Zeabur exposes this as build metadata. |
| `VAULT_GIT_COMMIT`      | no       | Git commit claim. Zeabur exposes this as build metadata.     |
| `VAULT_DEPLOYMENT_ID`   | no       | Zeabur deployment id, sent as a provider claim.              |

Claims are untrusted workload input. The vault shows them to the approver for
comparison against verified facts; it never uses a claim to choose an
environment, a key version, or a secret set.

## Two deployment modes

**Native Zeabur Git build.** Zeabur builds the image from this Dockerfile
directly. Claims can carry the Git repository, commit, and Zeabur deployment
metadata. The dashboard shows these as claimed, not verified: nothing in this
path produces a cryptographic attestation of what image is actually running.
Approval is still available, and the environment policy for this path should
be `ADVISORY`.

**Prebuilt OCI deployment.** Your own CI builds and signs the image, pushes it
to a registry with an immutable digest, and Zeabur is configured to pull that
image rather than build it. The signed build manifest becomes evidence in
`boot.hello`, so the dashboard can show verified Git-to-OCI provenance. This
is the preferred path for an environment with policy `REQUIRED`. Even here,
"build provenance verified" does not mean "this exact process was remotely
attested at runtime": the image identity is claimed by the deployment, not
attested by Zeabur.

## Readiness caveat (spec section 33)

Human approval means this container can sit in startup for a long time: from
a few seconds to the length of the pending-approval TTL. Zeabur's health
check and rolling-deployment behavior keeps the previous healthy deployment
running until the replacement passes its health check, so the container must
never fake readiness to keep a deployment alive. This image does not: node
does not start, and therefore `/healthz` does not answer, until
keevault execs into it after a successful, decrypted approval.

Before calling this integration production-ready, run the test matrix in
`docs/zeabur.md`, including how long Zeabur will wait for a deployment stuck
in "waiting for approval" before it gives up.
