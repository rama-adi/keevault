# Architecture

## Components

```text
Cloudflare Worker (apps/control-plane/src/server/worker.ts)
├── TanStack Start dashboard: pages under src/routes, server functions under src/server/functions
├── Better Auth: passkey-only session auth, first-owner setup ceremony
├── /bootstrap/v1 WebSocket upgrade handler
└── Provenance verifiers (claims-only, signed-build-manifest-v1)

Durable Object: EnvironmentSessionDO, one instance per environment
├── Authoritative boot state machine
├── Hibernating WebSocket connections
├── Reconnect and resume-proof handling
└── SQLite storage for boot rows, keyed by environment id

D1: vault database (VAULT_DB binding)
├── projects, project_keys
├── environments, environment_keys
├── secrets
├── bootstrap_tokens
├── provenance_policies, trusted_signers
├── boot_requests (dashboard index, not authoritative)
├── boot_approvals
└── audit_events

D1: auth database (AUTH_DB binding)
└── Better Auth tables: users, sessions, passkey credentials (migrations/auth/0001_better_auth.sql)

Worker secrets
├── VAULT_MASTER_KEY_V<n>
├── BETTER_AUTH_SECRET
└── VAULT_SETUP_TOKEN

Go bootstrap client (apps/env-client)
└── Runs inside the workload container, speaks the bootstrap WebSocket protocol, execs the target process
```

The Worker's `fetch` handler in `worker.ts` checks the request path first: a request to `/bootstrap/v1` goes to `handleBootstrapRequest`, everything else goes to the TanStack Start server entry. The bootstrap path never renders a page and never reads a session cookie.

## Request paths

### Dashboard request

```text
browser
  │ session cookie
  ▼
TanStack Start route loader (src/routes/**)
  │ calls a server function (src/server/functions/*.ts)
  ▼
guarded() wrapper (functions/guarded.ts)
  │ requireSession / requireRole / requireRecentPasskey (auth/guards.ts)
  ▼
vault service (server/vault/service.ts) reads or writes D1 via @env-vault/vault-store
  ▼
response rendered by the route component
```

Every server function runs its body inside `guarded()`, which turns an `AuthorizationError`, a `VaultKeyError`, or a validation error into an encoded message the client-side error handling in `src/lib/vault-errors.ts` knows how to read, so no stack trace or internal detail reaches the browser.

### Bootstrap WebSocket upgrade path

```text
GET /bootstrap/v1
Authorization: Bearer vlt_boot_<tokenId>.<secret>
  │
  ▼
routeBootstrapUpgrade (server/bootstrap/upgrade.ts)
  │ 1. reject a token in the query string outright (401)
  │ 2. parse tokenId, look up bootstrap_tokens by id
  │ 3. compare SHA-256(secret) to token_hash in constant time
  │ 4. check revoked_at and expires_at
  │ 5. check CF-Connecting-IP against allowed_cidrs_json (skip if empty)
  │ 6. resolve environment_id from the token row
  ▼
env.ENVIRONMENT_SESSION.idFromName(environmentId).fetch(forwardedRequest)
  ▼
EnvironmentSessionDO accepts the WebSocket upgrade, may hibernate after boot.pending
```

The client never selects an environment. Any environment identifier it sends is ignored. Failures before the upgrade completes are HTTP status codes (401, 403, 429); after the upgrade they are WebSocket close codes. See `protocol/websocket-v1.md` for the full frame catalogue and close code table.

### Approval path

```text
dashboard: POST approveBootFn { bootId, evidenceDigest }
  │ requireRole("admin"), then requireRecentPasskey()
  ▼
stubFor(environmentId).approve(...)  (functions/boots.ts calls the DO stub)
  ▼
EnvironmentSessionDO.approve
  │ re-checks: still PENDING, not expired, token still valid, policy still satisfied
  │ generates a fresh server X25519 keypair for this approval
  │ builds keyEnvelope: HKDF(shared secret) -> AES-256-GCM wrap of the environment key
  │ writes boot_approvals row, transitions PENDING -> APPROVED
  ▼
if a socket is attached: send boot.approved immediately, transition APPROVED -> DELIVERED
else: wait for boot.resume, then send boot.approved on resume
```

The DO re-validates every precondition at approval time rather than trusting what the dashboard read a moment earlier, because D1's `boot_requests` row is an index, not the source of truth.

## Key hierarchy and AAD strings

```text
VAULT_MASTER_KEY_V<n>  (Worker secret, 32 bytes, b64u)
        │ AES-256-GCM wrap
        ▼
project key  (32 random bytes, generated independently, never derived)
        │ AES-256-GCM wrap
        ▼
environment key  (32 random bytes, generated independently)
        │ AES-256-GCM encrypt, one operation per secret value
        ▼
secret value
```

Every AES-256-GCM operation uses a fresh random 96-bit nonce and a canonical AAD string. The AAD is UTF-8, lines joined with `\n`, no trailing newline:

Project key wrap:

```text
vault:project-key:v1
project=<projectId>
version=<projectKeyVersion>
master=<masterKeyVersion>
```

Environment key wrap:

```text
vault:environment-key:v1
project=<projectId>
environment=<environmentId>
version=<envKeyVersion>
project_key_version=<projectKeyVersion>
```

Secret value:

```text
vault:secret:v1
project=<projectId>
environment=<environmentId>
secret=<secretId>
name=<SECRET_NAME>
version=<secretVersion>
env_key_version=<envKeyVersion>
```

Boot envelope, wrapping the environment key to one boot's ephemeral X25519 key:

```text
vault:boot-envelope:v1
boot=<bootId>
environment=<environmentId>
env_key_version=<envKeyVersion>
client=<hex fingerprint of client X25519 pub>
server=<hex fingerprint of server X25519 pub>
```

The wrap key is `HKDF-SHA256(ikm = X25519(serverPriv, clientPub), salt = 32 random bytes, info = the string above, L = 32)`. Integers in every AAD string are decimal, no leading zeros. These strings and the code that builds them live in `packages/crypto/src/aad.ts` and `packages/crypto/src/envelope.ts`.

## Boot state machine

The Durable Object owns this table. D1's `boot_requests.status` column is a projection and must never be read to authorize a transition.

| From      | Event         | To        | Trigger                                                    |
| --------- | ------------- | --------- | ---------------------------------------------------------- |
| PENDING   | approve       | APPROVED  | an administrator approved                                  |
| PENDING   | decline       | DECLINED  | an administrator declined                                  |
| PENDING   | expirePending | EXPIRED   | pending TTL alarm fired                                    |
| PENDING   | cancel        | CANCELED  | token revoked, environment deleted, or admin cancel        |
| APPROVED  | deliver       | DELIVERED | the `boot.approved` frame was written to the socket        |
| APPROVED  | cancel        | CANCELED  | token revoked, environment deleted, or admin cancel        |
| APPROVED  | expirePayload | EXPIRED   | payload TTL alarm fired                                    |
| DELIVERED | redeliver     | DELIVERED | same payload resent after a resume, inside the payload TTL |
| DELIVERED | consume       | CONSUMED  | a valid `boot.received` arrived                            |
| DELIVERED | expirePayload | EXPIRED   | payload TTL alarm fired                                    |

`CREATING` exists only inside the `boot.hello` handler before the row is written and is never observable outside it. `CONSUMED`, `DECLINED`, `EXPIRED`, and `CANCELED` are terminal. Any transition not in this table is rejected: `terminal` if the current state is one of the four above, `conflict` otherwise. Defaults: pending TTL 1800 seconds, payload TTL 300 seconds, challenge TTL 30 seconds, max 3 concurrent pending boots per token. The state machine's core logic is in `apps/control-plane/src/server/durable-objects/boot-session-core.ts`, covered by `boot-session-core.test.ts` including hibernation and restart cases.

## D1 versus Durable Object storage

| Data                                                              | Lives in                                                    |
| ----------------------------------------------------------------- | ----------------------------------------------------------- |
| Project and environment catalog, slugs, names                     | D1 vault database                                           |
| Wrapped project keys, wrapped environment keys                    | D1 vault database                                           |
| Encrypted secret values                                           | D1 vault database                                           |
| Bootstrap token hashes, CIDR lists, expiry, revocation            | D1 vault database                                           |
| Provenance policy configuration, trusted signers                  | D1 vault database                                           |
| Audit event history                                               | D1 vault database                                           |
| Boot request index for the dashboard's boot list                  | D1 vault database (`boot_requests`, a projection)           |
| Approval record: fingerprints, evidence digest, approver identity | D1 vault database (`boot_approvals`) and the Durable Object |
| Live boot status, the authoritative state machine                 | `EnvironmentSessionDO` SQLite storage                       |
| Active WebSocket-to-boot association                              | `EnvironmentSessionDO`, via hibernation attachments         |
| Resume challenge, in-flight approval payload bytes                | `EnvironmentSessionDO`                                      |
| Admin users, sessions, passkey credentials                        | D1 auth database                                            |

When the dashboard's D1 read disagrees with the Durable Object, the Durable Object wins. The approval server function always re-fetches the DO's current state before authorizing delivery rather than trusting a D1 row read moments earlier.

## Package dependency graph

```text
apps/control-plane
├── depends on @env-vault/crypto
├── depends on @env-vault/protocol
└── depends on @env-vault/vault-store
      └── depends on @env-vault/crypto (indirectly, via shared encoding helpers)

apps/env-client (Go, separate module)
├── internal/vaultcrypto  mirrors packages/crypto: AES-GCM, X25519, HKDF, Ed25519, bootstrap token parsing
├── internal/protocol     mirrors packages/protocol: message decoding, frame validation
├── internal/client       WebSocket session: hello, resume, approval handling
└── internal/run          exec-based environment injection

crypto/test-vectors/*.json   generated by packages/crypto, loaded by both packages/crypto tests and apps/env-client tests
protocol/test-vectors/*.json validated by packages/protocol (zod) and apps/env-client/internal/protocol (Go decoders)
```

`packages/protocol` and `packages/crypto` have no dependency on `apps/control-plane` or on each other; `apps/control-plane` and `apps/env-client` each depend downward on the shared test vectors to keep both implementations byte-compatible, never on each other's source.
