# env-vault

env-vault is a secret vault for container and VPS deployments, built for Zeabur and similar platforms. A Cloudflare Worker holds encrypted secrets in D1 and releases them only after a human approves the specific process that is asking for them. The workload authenticates with a bootstrap token, but the token alone never unlocks anything: it only lets the workload open a pending request that an operator reviews on a dashboard before any plaintext leaves Cloudflare.

The release path is deliberately narrow. Each boot generates a fresh Ed25519 signing key and a fresh X25519 encryption key that never leave the process. An operator approves that exact key pair, not a commit or an image tag, so a stolen token can create a pending request but cannot make it approved, and a copied approval payload is useless without the matching private key. Compromising the D1 database, the Docker image, or the platform's own environment-variable storage each falls short of the master key, which lives only as a Cloudflare Worker secret. See `docs/threat-model.md` for the full set of attacker scenarios this design covers and does not cover.

## Trust model

```text
VAULT_MASTER_KEY_V<n>  (Worker secret, outside D1)
        │ wraps
        ▼
project key  (D1, encrypted)
        │ wraps
        ▼
environment key  (D1, encrypted)
        │ encrypts
        ▼
secret values  (D1, encrypted)
```

```text
bootstrap token  → proves the workload may ask for one environment
        │
        ▼
pending boot request  → holds the workload's ephemeral keys and claims
        │
        │  human approval, checked against provenance evidence
        ▼
environment key, wrapped to that boot's X25519 key only
        │
        ▼
workload decrypts and execs the target process
```

D1 never holds the master key and never holds plaintext secret values. The Durable Object that tracks each environment's pending boots is the only authority on whether a boot may be approved; a stale dashboard read is never used to authorize a release.

## Repository map

| Path                       | What it is                                                                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/control-plane`       | The Cloudflare Worker: TanStack Start dashboard, Better Auth, the `/bootstrap/v1` WebSocket, `EnvironmentSessionDO`, provenance verifiers.              |
| `apps/env-client`          | The Go bootstrap client (binary `vault-bootstrap`) that runs inside a workload container and execs the target process after decrypting its environment. |
| `packages/crypto`          | `@env-vault/crypto`: Web Crypto implementation of the key hierarchy, envelopes, bootstrap tokens, fingerprints, CIDR matching.                          |
| `packages/protocol`        | `@env-vault/protocol`: zod schemas and TypeScript types for every WebSocket message, the boot state machine, and canonical string builders.             |
| `packages/vault-store`     | `@env-vault/vault-store`: typed D1 access layer, tested against `node:sqlite`.                                                                          |
| `migrations`               | D1 schema migrations, split into `vault/` and `auth/`.                                                                                                  |
| `protocol`                 | `websocket-v1.md`, the generated JSON schema, and shared test vectors.                                                                                  |
| `crypto/test-vectors`      | Cross-language test vectors the TypeScript and Go crypto tests both load.                                                                               |
| `examples/zeabur-node-app` | A minimal Node app and Dockerfile showing `vault-bootstrap` as the container entrypoint.                                                                |
| `docs`                     | Operator and engineering documentation. See `docs/README.md` for the full index.                                                                        |

## Quick start for developers

Install dependencies and Vite+ tool versions:

```bash
vp install
```

Copy the local secrets file and fill in three independent random values:

```bash
cd apps/control-plane
cp .dev.vars.example .dev.vars
```

`.dev.vars.example` lists the exact generation command for each of `VAULT_MASTER_KEY_V1`, `BETTER_AUTH_SECRET`, and `VAULT_SETUP_TOKEN`. Do not derive one from another, and never commit `.dev.vars`.

Apply the local D1 migrations:

```bash
pnpm run db:migrate:local
```

Start the dashboard:

```bash
vp run dev
```

Run the checks and tests:

```bash
vp check
vp run -r test
```

`vp check` formats, lints, and type-checks. `vp run -r test` runs every package's Vitest suite across the workspace. Run the Go client's tests separately:

```bash
cd apps/env-client
go vet ./...
go test ./...
```

## Further reading

- `docs/README.md` is the index into every document below, ordered for a new operator.
- `docs/architecture.md` covers components, request paths, the key hierarchy, and the boot state machine.
- `docs/operations.md` is the deployment runbook, from creating the D1 databases to rotating keys.
- `docs/dashboard.md` is a page-by-page guide to the operator dashboard.
- `docs/threat-model.md`, `docs/key-rotation.md`, `docs/incident-response.md`, and `docs/provenance.md` cover security design, key rotation, incident runbooks, and the provenance verification model.
- `docs/zeabur.md` is the Zeabur integration test matrix.
- `docs/engineering-brief.md` pins the exact byte-level encodings both the TypeScript and Go implementations must agree on, and tracks implementation status.
- `protocol/websocket-v1.md` is the normative WebSocket protocol specification.
