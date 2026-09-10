# keevault

keevault is a secret vault for container and VPS deployments, built for Zeabur and similar platforms. A Cloudflare Worker holds encrypted secrets in D1 and releases them only after a human approves the specific process that is asking for them. The workload authenticates with a bootstrap token, but the token alone never unlocks anything: it only lets the workload open a pending request that an operator reviews on a dashboard before any plaintext leaves Cloudflare.

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

| Path                       | What it is                                                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `apps/control-plane`       | The Cloudflare Worker: TanStack Start dashboard, Better Auth, the `/bootstrap/v1` WebSocket, `EnvironmentSessionDO`, provenance verifiers.       |
| `apps/keevault-marketing`  | TanStack Start marketing site and Fumadocs user documentation, styled with Tailwind CSS.                                                         |
| `apps/env-client`          | The Go bootstrap client (binary `keevault`) that runs inside a workload container and execs the target process after decrypting its environment. |
| `packages/crypto`          | `@keevault/crypto`: Web Crypto implementation of the key hierarchy, envelopes, bootstrap tokens, fingerprints, CIDR matching.                    |
| `packages/protocol`        | `@keevault/protocol`: zod schemas and TypeScript types for every WebSocket message, the boot state machine, and canonical string builders.       |
| `packages/vault-store`     | `@keevault/vault-store`: typed D1 access layer, tested against `node:sqlite`.                                                                    |
| `migrations`               | D1 schema migrations, split into `vault/` and `auth/`.                                                                                           |
| `protocol`                 | `websocket-v1.md`, the generated JSON schema, and shared test vectors.                                                                           |
| `crypto/test-vectors`      | Cross-language test vectors the TypeScript and Go crypto tests both load.                                                                        |
| `examples/zeabur-node-app` | A minimal Node app and Dockerfile showing `keevault` as the container entrypoint.                                                                |
| `docs`                     | Hosting runbooks, architecture, specifications, audits, and integration test matrices. See `docs/README.md` for the full index.                  |

## Run a workload

Create `keevault.json` in your application's working directory:

```json
{
  "vaultUrl": "https://vault.example.com",
  "environmentId": "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "requiredSecrets": ["DATABASE_URL", "API_KEY"],
  "command": ["node", "server.js"]
}
```

Set `VAULT_BOOTSTRAP_TOKEN` through your deployment platform, then run `keevault`.
The client waits for approval, checks the environment ID and required secret names,
and replaces itself with the configured command. Keep secret values and bootstrap
tokens out of this file. The token selects the environment; `environmentId` checks
that the server approved the one you expected. `requiredSecrets` checks presence;
it does not filter the approved environment's secrets.

Put the application command in `keevault.json` and run `keevault` without
command arguments. Use `--config path/to/keevault.json` to select another file.
See [client configuration](apps/keevault-marketing/content/docs/client.mdx).

Container builds download a precompiled Linux binary from R2 and verify a pinned
SHA-256 checksum. They do not need a Go toolchain. Releases provide `amd64` and
`arm64` binaries under versioned paths. See [release setup](docs/releases.md) and
the [example Dockerfile](examples/zeabur-node-app/Dockerfile). R2 publication needs
your bucket, public download domain, and CI credentials before the first release.

## Quick start for developers

Run these commands from the repository root. Install dependencies and build the
workspace packages, whose exports point to generated `dist` files:

```bash
vp install
vp run -r build
```

Copy the local secrets file and fill in three independent random values:

```bash
cp apps/control-plane/.dev.vars.example apps/control-plane/.dev.vars
```

`.dev.vars.example` lists the exact generation command for each of `VAULT_MASTER_KEY_V1`, `BETTER_AUTH_SECRET`, and `VAULT_SETUP_TOKEN`. Do not derive one from another, and never commit `.dev.vars`.

Apply the local D1 migrations:

```bash
vp run control-plane#db:migrate:local
```

Start the dashboard:

```bash
vp run dev
```

Start the marketing site and user documentation in a separate terminal:

```bash
vp run dev:marketing
```

Run the checks and tests:

```bash
vp check
vp test
vp run -r test
```

`vp check` checks formatting, lint, and types. Use `vp check --fix` to apply formatting fixes. `vp run -r test` runs every package's Vitest suite across the workspace. Run the Go client's tests separately:

```bash
cd apps/env-client
go vet ./...
go test ./...
```

## Hosted applications

- Marketing and documentation: https://keevault.my.id
- Vault API and operator dashboard: https://vault.keevault.my.id

Both Cloudflare Workers deploy from `master` in `rama-adi/keevault`. The vault build checks that test harness routes are excluded, then applies D1 migrations before deploying. Complete first-owner enrollment at `https://vault.keevault.my.id/setup` using the production setup token and your passkey.

## Further reading

User documentation is served by `apps/keevault-marketing` at `/docs`.

- [Getting started](apps/keevault-marketing/content/docs/getting-started.mdx) covers the first approved workload.
- [Managing secrets](apps/keevault-marketing/content/docs/managing-secrets.mdx) and [approving boots](apps/keevault-marketing/content/docs/approving-boots.mdx) cover everyday use.
- [Operations](docs/operations.md) covers vault hosting and administration.
- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md) explain the security boundaries.
- [Documentation index](docs/README.md) links to all operator guides and engineering references.
- [Latest code audit](docs/audit-2026-09-09.md) covers fixes and remaining rotation and setup concurrency risks.
- [WebSocket protocol](protocol/websocket-v1.md) defines the normative wire contract.
