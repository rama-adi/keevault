# Zeabur Node app example

This is a minimal, dependency-free Node app that shows how to run a workload
behind env-vault's bootstrap client on Zeabur. `server.js` listens on `PORT`,
answers `GET /healthz` with `200 ok`, and answers `GET /` with a JSON object
listing the names (never the values) of every environment variable starting
with `APP_`, plus the process uptime.

The Dockerfile builds `vault-bootstrap` from `apps/env-client` in a Go build
stage, then copies the static binary into a Node 22 runtime image. The
container's entrypoint is `vault-bootstrap`, not `node`: the app only starts
once a human approves the boot on the env-vault dashboard and the bootstrap
client has decrypted the environment.

## Building

Build from the repository root so the build stage can see `apps/env-client`:

```bash
docker build -f examples/zeabur-node-app/Dockerfile -t zeabur-node-app-example .
```

## Running locally against a vault dev server

Point the container at a running env-vault control plane and a bootstrap
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
| `VAULT_URL`             | yes      | The env-vault control plane endpoint.                        |
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
vault-bootstrap execs into it after a successful, decrypted approval.

Before calling this integration production-ready, run the test matrix in
`docs/zeabur.md`, including how long Zeabur will wait for a deployment stuck
in "waiting for approval" before it gives up.
