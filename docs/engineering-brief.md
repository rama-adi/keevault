# env-vault V1 engineering brief (read fully before touching code)

Repo: /Users/ramaadi/WorkProjects/env-vault (pnpm workspace managed by Vite+ `vp`).
Product spec: docs/product-specs.md is authoritative for behaviour. This brief pins the exact encodings, layout and message shapes the spec leaves open, so the TypeScript and Go implementations agree byte for byte. Agents read this file before starting a work package.
Repo conventions: CLAUDE.md (Vite+ usage, TanStack Start page/route rules, shadcn rules).

## Working rules for every agent

- Do only the work package you were given. Do not edit files owned by another package unless told to.
- Do not `git commit`. Leave changes in the working tree.
- TypeScript: run `vp check` (fmt+lint+typecheck) and `vp test` for your package until clean. Anti-slop oxlint rules are ON (tools/oxlint/anti-slop). Practically:
  - no `unknown` in parameter or return types; no `unknown` type aliases; no `object` parameters. Parse external input at the boundary with zod (`zod` v4) and pass typed values inward.
  - no `typeof x === "..."` runtime checks; use zod or discriminated unions.
  - every `as` type assertion needs a `// SAFETY: ...` comment on the line above and no chained assertions (`as unknown as`) at all.
  - no `Record<string, T>` style dictionary types where a `Map` or a typed interface fits; if you must, expect the lint to complain and restructure.
  - no `vi.mock` module mocking; inject dependencies instead.
  - no shape words in identifiers (`fooObj`, `barArr`, `bazStr`).
  - the rule `vite-plus/prefer-vite-plus-imports` requires importing `defineConfig` from "vite-plus" in vite.config.ts.
- Go: `gofmt`, `go vet ./...`, `go test ./...` clean. Go 1.26 is installed. Stdlib crypto only (`crypto/ecdh`, `crypto/ed25519`, `crypto/aes`, `crypto/cipher`, `crypto/hkdf`, `crypto/sha256`). Only allowed third-party module: `github.com/coder/websocket`.
- Never log or print secret material, tokens, keys, or plaintext secret values (spec §35-36). Tests may print nothing sensitive either.
- Prose (docs, comments, README): plain, direct, sentence-case headings, no em dashes, no marketing words, no "leverage/robust/seamless/comprehensive". Say what the thing does and what the reader must do. See .agents/skills/unslop/SKILL.md.
- When you are done, reply with: files created/changed, commands you ran and their final result (exact pass/fail), anything you could not finish and why, any decision you made that deviates from this brief.

## Repository layout (final)

```
apps/control-plane/          Cloudflare Worker: TanStack Start dashboard + Better Auth + /bootstrap/v1 WebSocket + EnvironmentSessionDO + provenance verifiers
  src/routes/                TanStack file routes (pages). Real directories, no dot-notation.
  src/components/ui/         shadcn primitives (installed via shadcn CLI)
  src/components/vault/      product components built on top of ui/
  src/server/                server-only code: worker entry, DO, auth, vault service, bootstrap WS handler, provenance
  wrangler.jsonc
packages/protocol/           @env-vault/protocol: zod schemas + TS types for every WS message, state machine, constants, canonical string builders
packages/crypto/             @env-vault/crypto: Web Crypto implementation of the hierarchy, envelopes, tokens, fingerprints, CIDR matching
packages/vault-store/        @env-vault/vault-store: D1 schema access layer (typed SQL over a minimal D1-shaped interface), tested against node:sqlite
cmd/vault-bootstrap/         Go module `github.com/ramaadi/env-vault/cmd/vault-bootstrap` (go.mod lives here). main.go + internal/{vaultcrypto,protocol,client,run}
migrations/vault/            D1 vault DB migrations (0001_init.sql ...)
migrations/auth/             D1 auth DB migrations (Better Auth generated)
protocol/                    websocket-v1.md, messages.schema.json (generated from zod), test-vectors/
crypto/test-vectors/         JSON vectors shared by TS and Go tests
examples/zeabur-node-app/    Dockerfile + tiny Node app for Phase 10
docs/                        product-specs.md (given), plus threat-model.md, key-rotation.md, incident-response.md, provenance.md, architecture.md, operations.md, README index
```

Workspace globs in pnpm-workspace.yaml: apps/_, packages/_, tools/*. Package names are scoped `@env-vault/<name>`. Internal deps use `"workspace:*"`. Add third-party versions to the pnpm catalog when several packages share them.

Current versions seen on npm today (pin these unless broken): @tanstack/react-start 1.168.49, @tanstack/react-router 1.170.32, @cloudflare/vite-plugin 1.54.4, wrangler 4.129.0, @cloudflare/workers-types 5.20260905.1, better-auth 1.7.2, zod 4.5.4, react 19.2.8, @vitejs/plugin-react 6.1.1, tailwindcss 4.3.3, @tailwindcss/vite 4.3.3, kysely 0.29.5.

## Identifiers

- Prefixed ULIDs (Crockford base32, 26 chars, uppercase): `proj_`, `env_`, `sec_`, `tok_`, `boot_`, `aud_`, `pol_`, `sig_`. Generate with a tiny local ULID implementation (no dependency) or `crypto.randomUUID()`-free approach; Go uses the same alphabet. Uniqueness matters more than monotonicity.
- Slugs: `^[a-z0-9][a-z0-9-]{0,62}$`.
- Secret names: `^[A-Z_][A-Z0-9_]{0,255}$` (POSIX env names). Values: UTF-8, max 64 KiB.

## Binary and text encodings (both languages must match byte for byte)

- Every binary field inside JSON is base64url WITHOUT padding (RFC 4648 §5). Call it `b64u`.
- Hashes shown to humans are lowercase hex.
- Key fingerprint = lowercase hex SHA-256 of the raw 32-byte public key. UI may display it colon-grouped; wire and storage use plain hex.
- Timestamps in messages are RFC 3339 UTC with millisecond precision: `2026-09-05T10:00:00.000Z`. D1 stores ISO strings as TEXT (same format).
- AES-256-GCM: 96-bit random nonce per operation, 128-bit tag appended to the ciphertext (Web Crypto default; Go `cipher.NewGCM` Seal does the same). `ciphertext` on the wire = ct||tag as b64u. `nonce` separate b64u.
- All "canonical strings" below are UTF-8, lines joined with `\n`, no trailing newline, no CR.

## Key hierarchy and AADs

Master key: 32 bytes from Worker secret `VAULT_MASTER_KEY_V1` (b64u encoded, 43 chars). Support `VAULT_MASTER_KEY_V<n>`; `VAULT_MASTER_KEY_ACTIVE_VERSION` (var, integer, default 1) chooses which version wraps new project keys.

Project key wrap (AES-256-GCM under master):

```
vault:project-key:v1
project=<projectId>
version=<projectKeyVersion>
master=<masterKeyVersion>
```

Environment key wrap (under project key):

```
vault:environment-key:v1
project=<projectId>
environment=<environmentId>
version=<envKeyVersion>
project_key_version=<projectKeyVersion>
```

Secret value (under environment key):

```
vault:secret:v1
project=<projectId>
environment=<environmentId>
secret=<secretId>
name=<SECRET_NAME>
version=<secretVersion>
env_key_version=<envKeyVersion>
```

Integers are decimal without leading zeros.

## Boot envelope (environment DEK delivery to one boot)

- Server generates a fresh X25519 keypair per approval. Shared = X25519(serverPriv, clientEncryptionPub).
- salt = 32 random bytes. info string:

```
vault:boot-envelope:v1
boot=<bootId>
environment=<environmentId>
env_key_version=<envKeyVersion>
client=<hex fingerprint of client X25519 pub>
server=<hex fingerprint of server X25519 pub>
```

- wrapKey = HKDF-SHA256(ikm=shared, salt, info, L=32).
- ciphertext = AES-256-GCM(wrapKey, nonce(12 random), plaintext=envDEK(32 bytes), aad=UTF-8(info)).
- Wire object `keyEnvelope`: `{ "serverPublicKey": b64u(32), "salt": b64u(32), "nonce": b64u(12), "ciphertext": b64u(48) }`.
- Client rejects if any all-zero shared secret (low-order point) is produced.

## Bootstrap token

- Format: `vlt_boot_<tokenId>.<secret>`; tokenId = 26-char ULID (no prefix inside the token; the D1 id is `tok_<ULID>`); secret = b64u of 32 random bytes (43 chars). Regex: `^vlt_boot_([0-9A-HJKMNP-TV-Z]{26})\.([A-Za-z0-9_-]{43})$`.
- D1 stores `token_hash` = lowercase hex SHA-256 over the UTF-8 bytes of the secret string (the 43 chars), never the token. Compare hashes with constant-time comparison.
- Presented as `Authorization: Bearer <token>` on the WebSocket upgrade. Query-string tokens are rejected with 4401.
- CIDR check on `CF-Connecting-IP` only. IPv4 and IPv6. Empty allowed list = skip check.

## Resume proof

Challenge = 32 random bytes b64u. Client signs (Ed25519) the UTF-8 bytes of:

```
vault-resume:v1
<bootId>
<challenge b64u exactly as received>
```

Signature b64u (64 bytes). Challenge valid 30 s, single use.

## payloadDigest

`payloadDigest` in `boot.received` = lowercase hex SHA-256 of the exact UTF-8 bytes of the `boot.approved` text frame as transmitted. Server stores the digest of the frame it sent and requires equality.

## WebSocket protocol v1 (text frames, one JSON object per frame, `type` discriminator)

Endpoint `GET /bootstrap/v1` with `Upgrade: websocket`, `Authorization: Bearer vlt_boot_...`.
Client -> server:

- `boot.hello` { type, protocol: 1, bootNonce: b64u(>=16 bytes), signingPublicKey: b64u(32), encryptionPublicKey: b64u(32), claims: { git?: {repository, commit}, oci?: {repository, digest}, provider?: {name, deploymentId?, region?} }, evidence: Evidence[] }
- `boot.resume` { type, protocol: 1, bootId }
- `boot.challenge-response` { type, bootId, signature: b64u }
- `boot.received` { type, bootId, payloadDigest }
  Server -> client:
- `boot.pending` { type, bootId, expiresAt }
- `boot.challenge` { type, bootId, challenge }
- `boot.resumed` { type, bootId, status: "PENDING" | "APPROVED" | "DELIVERED", expiresAt }
- `boot.approved` { type, bootId, environmentId, projectId, environmentKeyVersion, payloadExpiresAt, keyEnvelope, secrets: [{ id, name, version, envKeyVersion, nonce, ciphertext }] }
- `boot.declined` { type, bootId, reason? } then close 4410
- `boot.expired` { type, bootId } then close 4410
- `boot.canceled` { type, bootId, reason } then close 4410
- `boot.consumed` { type, bootId } then close 1000
- `boot.error` { type, code, message } then close with the same code
  Close codes: 1000 normal; 4400 protocol error; 4401 bad/missing token; 4403 CIDR or revoked/expired token; 4404 unknown boot; 4409 too many pending boots for token (default max 3) or conflicting state; 4410 boot is terminal; 4429 rate limited.
  Evidence item: `{ type: "signed-build-manifest-v1", manifest: Manifest, signature: b64u(64), signerFingerprint: hex }`. Unknown evidence types are kept but marked UNAVAILABLE by verifiers.

## Boot state machine (DO is authoritative; D1 is an index)

States: PENDING, APPROVED, DELIVERED, CONSUMED, DECLINED, EXPIRED, CANCELED. (CREATING exists only inside the hello handler before the row is written.)
Transitions: PENDING->APPROVED (admin approve), PENDING->DECLINED, PENDING->EXPIRED (alarm at pending TTL), PENDING/APPROVED->CANCELED (token revoked, env deleted, admin cancel), APPROVED->DELIVERED (frame sent), DELIVERED->CONSUMED (valid boot.received), APPROVED/DELIVERED->EXPIRED (alarm at payload TTL). DELIVERED->DELIVERED redelivery to the same key on resume is allowed inside payload TTL. Every other transition is a conflict. Defaults: pending TTL 1800 s, approved payload TTL 300 s, challenge TTL 30 s, max concurrent pending per token 3.
Approval record binds: environmentId, bootId, both public key fingerprints, evidence digest (hex SHA-256 of the stored provenance summary JSON), approver user id, approver credential id, approvedAt.

## Signed build manifest v1 (provenance)

```json
{
  "version": 1,
  "source": { "repository": "github.com/acme/foo", "commit": "<40 or 64 hex>" },
  "artifact": { "type": "oci", "repository": "ghcr.io/acme/foo", "digest": "sha256:<64 hex>" },
  "builder": "acme-ci",
  "issuedAt": "2026-09-05T10:00:00.000Z"
}
```

Canonical bytes = JSON serialisation with object keys sorted by UTF-16 code unit order at every level, no whitespace, values limited to strings and the integer 1. Go MUST use an encoder with `SetEscapeHTML(false)`; JS `JSON.stringify` on a key-sorted rebuilt object. Signed message = UTF-8 of `vault:signed-build-manifest:v1\n` + canonical JSON. Ed25519 signature. `signerFingerprint` = hex SHA-256 of signer public key; the vault looks up trusted_signers by fingerprint.
Verifier statuses: VERIFIED, UNVERIFIED, FAILED, UNAVAILABLE (spec §25). No scores.

## Test vectors

- `crypto/test-vectors/*.json` generated by the TS package (deterministic inputs listed in the file: keys, nonces, salts, plaintexts as b64u, expected ciphertext/AADs/derived keys). Go tests load these and must pass. Files: `aes-gcm-secret.json`, `key-wrap.json`, `boot-envelope.json`, `resume-signature.json`, `bootstrap-token.json`, `manifest-canonical.json`, `fingerprint.json`.
- `protocol/test-vectors/*.json` example frames validated by both zod schemas (TS) and Go decoders.
- Every vector file has `{ "description": string, "vectors": [...] }` with self-describing field names.
