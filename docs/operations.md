# Operations

This is the deployment runbook, from an empty Cloudflare account to a running vault with an approved boot. It also covers the day-two tasks an operator repeats after that: creating projects and environments, managing secrets and tokens, approving boots, reading the audit log, changing roles, rotating keys, and revoking a token. It ends with the local development loop and a troubleshooting section for WebSocket close codes.

## Deployment runbook

### 1. Create the two D1 databases

The vault uses two separate D1 databases: one for vault data, one for Better Auth. Create both and record their ids.

```bash
cd apps/control-plane
wrangler d1 create env-vault-vault
wrangler d1 create env-vault-auth
```

Each command prints a `database_id`. Put both into `wrangler.jsonc`, replacing the placeholder UUIDs:

```jsonc
"d1_databases": [
  { "binding": "VAULT_DB", "database_name": "env-vault-vault", "database_id": "<id from the first command>", "migrations_dir": "../../migrations/vault" },
  { "binding": "AUTH_DB", "database_name": "env-vault-auth", "database_id": "<id from the second command>", "migrations_dir": "../../migrations/auth" }
]
```

### 2. Generate and set the secrets

Three secrets are required. Generate each independently. Do not derive one from another.

`VAULT_MASTER_KEY_V1`, 32 random bytes, base64url without padding:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

`BETTER_AUTH_SECRET`, at least 32 characters:

```bash
openssl rand -base64 32
```

`VAULT_SETUP_TOKEN`, the one-time token that gates the first-owner ceremony at `/setup`:

```bash
openssl rand -base64 32
```

Set each as a Worker secret:

```bash
wrangler secret put VAULT_MASTER_KEY_V1
wrangler secret put BETTER_AUTH_SECRET
wrangler secret put VAULT_SETUP_TOKEN
```

Save an offline copy of `VAULT_MASTER_KEY_V1` before continuing. See "back up the master key" below.

### 3. Set BETTER_AUTH_URL

`wrangler.jsonc` ships `BETTER_AUTH_URL` as `http://localhost:5173` under `vars`, for local development. Before deploying, change it to the vault's real public origin, for example:

```jsonc
"vars": {
  "VAULT_MASTER_KEY_ACTIVE_VERSION": "1",
  "BETTER_AUTH_URL": "https://vault.example.com"
}
```

`BETTER_AUTH_URL` also sets the WebAuthn relying party id, since `buildAuthOptions` derives it from this URL's hostname. Passkeys registered against one hostname do not work against another.

### 4. Apply remote migrations

```bash
pnpm run db:migrate:remote
```

This runs `wrangler d1 migrations apply VAULT_DB --remote` and `wrangler d1 migrations apply AUTH_DB --remote` in sequence, applying `migrations/vault/0001_init.sql` and `migrations/auth/0001_better_auth.sql`.

### 5. Deploy

```bash
pnpm run build
wrangler deploy -c dist/server/wrangler.json
```

### 6. Run the first-owner ceremony at /setup

Visit `https://<your-vault-host>/setup`. This route is reachable only while the auth database has zero user rows; once an owner exists it returns 404 for everyone, signed in or not.

Fill in the setup token you generated in step 2, a name, and an email. The form posts to a Better Auth endpoint at `/vault-setup/claim-owner`, which checks the token in constant time and, only if the user table is still empty, creates the first user with role `owner` and starts a session.

### 7. Register the passkey

Immediately after the owner account is created, the setup page prompts a passkey registration through `authClient.passkey.addPasskey`. Complete it. If this step fails after the account was created, sign-in is impossible until a passkey exists, since the vault has no password fallback; the documented recovery in that case is to recreate the auth database and run setup again.

### 8. Setup closes itself, nothing else to disable

Once the first user row exists, `/setup` returns 404 unconditionally. There is no separate flag to disable and no second step to remember: the ceremony is gated purely on `ownerExists()`, which checks whether the user table is empty.

### 9. Back up the master key offline

Losing the sole master key makes every piece of vault ciphertext permanently unrecoverable. D1 backups contain only ciphertext, which is useful for restoring metadata and history, but the master key is the one thing D1 point-in-time recovery cannot give back. Store a copy of `VAULT_MASTER_KEY_V1` outside Cloudflare, in a hardware password manager, an offline encrypted archive, or an organizational secrets manager, before this vault holds anything you cannot afford to lose. Document who can access that copy and under what conditions.

## Day-two tasks

### Create a project and an environment

On the dashboard, `/projects` lists projects and, for an admin or owner, offers "New project". A project needs a name and a slug. Inside a project's page, `/projects/$projectId`, create an environment the same way; each environment gets its own environment key, independent of every other environment in the project.

### Add secrets or import a .env file

Open an environment at `/projects/$projectId/environments/$environmentId` and use the Secrets tab. Adding a secret encrypts the value in the Worker before it reaches D1. Importing a `.env` file sends its plaintext over HTTPS to the Worker, which parses it, encrypts each value independently, and discards the plaintext; the dashboard never returns a value once stored; see `docs/dashboard.md` for what the secrets list looks like.

### Create a bootstrap token and place it in Zeabur

From the environment's Tokens tab, create a token with a label and, optionally, a CIDR allow list. The token is shown once, in the form `vlt_boot_<tokenId>.<secret>`; copy it immediately, since only its hash is stored. Set it as `VAULT_BOOTSTRAP_TOKEN` in the Zeabur service's environment variables, alongside `VAULT_URL` pointing at this vault. See `apps/env-client/README.md` for every variable the bootstrap client reads and `examples/zeabur-node-app/README.md` for a working Dockerfile.

### Approve a boot

New boot requests appear on `/boots`. Opening one shows the boot request, the claimed workload, verified evidence, and the boot's key fingerprints. Approving requires the admin role and a passkey verification from the last five minutes; if the last verification is older, the dashboard prompts for one before the approval goes through. See `docs/dashboard.md` for what each section means and what a `FAILED` evidence line means.

### Read the audit log

`/audit` lists every audit event, filterable by project and environment. Every project, environment, secret, token, provenance, and boot-lifecycle action listed in `docs/product-specs.md` section 35 is recorded here. No audit event ever contains a secret value, a key, or key material.

### Change an operator role

On `/settings`, an owner can change any other administrator's role between `owner`, `admin`, and `viewer`. This is step-up gated: the dialog asks for a passkey verification from the last five minutes before it submits.

### Rotate keys

See `docs/key-rotation.md` for the three runbooks: environment key, project key, and master key. All three are owner-only, step-up-gated operations, reachable from the project or environment page.

### Revoke a token

From the Tokens tab, revoke a token to set its `revoked_at`. Revocation immediately blocks new WebSocket connections and reconnects for that token and cancels every `PENDING` boot from it; `APPROVED` but not yet delivered boots are canceled too, since the safest behavior is to fail closed. A boot that already reached `CONSUMED` cannot be revoked retroactively, since that workload already holds its environment.

### Local development loop

```bash
vp install
cd apps/control-plane
cp .dev.vars.example .dev.vars   # fill in the three secrets
pnpm run db:migrate:local
vp run dev
```

`vp run dev` runs the `dev` script in `apps/control-plane/package.json`, which is `vp dev`, the Vite+ dev server wired to the Cloudflare Worker plugin. Run tests and checks from the repo root:

```bash
vp check
vp run -r test
```

Run the Go client's tests separately, since they are not part of the pnpm workspace:

```bash
cd apps/env-client
gofmt -l .
go vet ./...
go test ./...
```

## Troubleshooting

### Common WebSocket close codes

These are the close codes the bootstrap endpoint sends, from `protocol/websocket-v1.md`. Use this table to read a bootstrap client's connection failure.

| Code | What it means to an operator                                                                                                                                                                                                                              |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1000 | Normal. The boot finished: the workload received its environment and acknowledged it.                                                                                                                                                                     |
| 4400 | Protocol error: malformed JSON, an unknown message type, a schema violation, a failed resume signature, or a digest mismatch on `boot.received`. Usually a client bug or version mismatch, not an attack.                                                 |
| 4401 | Missing, malformed, or unknown bootstrap token, including a token sent in the query string instead of the `Authorization` header. Check `VAULT_BOOTSTRAP_TOKEN` on the deployment.                                                                        |
| 4403 | The token is revoked or expired, or the connecting IP failed the token's CIDR allow list. Check `bootstrap_tokens.revoked_at` and `expires_at`, and confirm the deployment's outbound IP against the allow list.                                          |
| 4404 | The boot id in a `boot.resume` is unknown to this environment. The boot may have already finished, or the client is resuming against the wrong vault host.                                                                                                |
| 4409 | Either the token already has the maximum number of pending boots (default 3), or a state transition conflicted with another one in flight. A flood of 4409s from one token suggests a retrying client or a stolen token; see `docs/incident-response.md`. |
| 4410 | The boot is terminal: it was declined, expired, or canceled. Preceded by `boot.declined`, `boot.expired`, or `boot.canceled`, which carries the reason.                                                                                                   |
| 4429 | Rate limited. The client should back off before retrying.                                                                                                                                                                                                 |

Any other close code is a transport failure. Both sides are expected to reconnect under the client's backoff policy (1 to 15 seconds with jitter) while the boot is still pending.

### Other things to check

- If `/setup` returns 404 unexpectedly, an owner already exists. Confirm with `wrangler d1 execute AUTH_DB --remote --command "select count(*) from user"`.
- If passkey sign-in fails after moving `BETTER_AUTH_URL` to a new hostname, existing passkeys were registered against the old relying party id and will not validate against the new one; affected users need to register a new passkey.
- If a boot never reaches `PENDING`, confirm the Worker can read `VAULT_MASTER_KEY_V<n>` and that the active version in `VAULT_MASTER_KEY_ACTIVE_VERSION` matches a secret that actually exists.
