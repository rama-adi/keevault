# Security review, V1

Reviewed against docs/product-specs.md sections 3, 11 to 18, 20, 22, 35 to 38, 41, 43 phase 11, 44 and 47, plus docs/threat-model.md and protocol/websocket-v1.md. Code read: packages/crypto/src, packages/protocol/src, apps/control-plane/src/server (auth, bootstrap, durable-objects, provenance, vault, functions, log.ts, worker.ts), apps/control-plane/src/routes/boots, apps/env-client/internal.

The core is in good shape. The key hierarchy, the AAD strings, the boot envelope and the resume proof all hold up against the section 44 attacks, and I could not construct a path to a plaintext secret without an administrator approving the attacker's own ephemeral key. Every finding below is either a state-machine gap or a defence-in-depth control that is weaker than the spec asks for. The two I would fix before launch are 1 and 6: one turns a double-clicked approve button into a dead boot, and the other is a step-up guard that fails open on a value it cannot parse.

I did not fix anything. Another agent is editing server code, so this review adds tests only. Five new test files, 48 new cases, 6 of them marked failing against the finding they are waiting on.

## Findings

| Id  | Severity      | Component                         | Status             |
| --- | ------------- | --------------------------------- | ------------------ |
| 1   | High          | Durable Object, approval          | fixed-by-test-only |
| 2   | Medium        | Durable Object, reconnect         | fixed-by-test-only |
| 3   | Medium        | Durable Object, pending TTL       | fixed-by-test-only |
| 4   | Medium        | Server functions, step-up         | open               |
| 5   | Low           | Go client, frame limit            | fixed-by-test-only |
| 6   | Medium        | Better Auth guards, step-up       | open               |
| 7   | Low           | Better Auth, setup ceremony       | open               |
| 8   | Low           | Bootstrap endpoint, rate limiting | open               |
| 9   | Informational | Server functions, CSRF posture    | open               |

"fixed-by-test-only" means a test in this repository now names the defect and fails until somebody fixes the source. Nothing in this review changed a non-test file.

## Finding 1: two approvals of the same boot both win

Severity: high. Component: `BootSessionCore.approve`.

### Attack

An administrator double-clicks Approve, or two administrators approve the same boot in the same second, or an attacker who has already stolen an admin session replays the approve request. `approve` reads the boot row at the top and then awaits five separate things: the bootstrap token lookup, the environment lookup, the provenance context load, the verifier run and the environment key unwrap. None of those are Durable Object storage operations, so the object's input gate does not hold other events off during them. A second `approve` for the same boot is delivered in the middle of the first, reads the same PENDING row, and passes the same checks.

Both calls then reach the transition. `#apply` is handed the row each call read at the start, so both see PENDING and both write APPROVED. The loser overwrites `delivered_frame` and `payload_digest` with a second envelope that was never sent to anybody, and clobbers the DELIVERED status the winner had already reached. The client is holding the first frame, so its `boot.received` digest no longer matches what the object stored, the acknowledgement is refused with 4400, and the boot sits at APPROVED until the payload TTL kills it. A workload that was legitimately approved never starts.

The second `insertBootApproval` then throws on the `boot_approvals` primary key, so the losing call returns an encoded "unknown" error rather than the conflict spec section 44 requires. That throw is the only reason a second approval record does not exist.

### Evidence

- `apps/control-plane/src/server/durable-objects/boot-session-core.ts:765`, the row is read.
- `apps/control-plane/src/server/durable-objects/boot-session-core.ts:858`, `#apply(boot, "approve")` is called against that row after every await in between.
- `apps/control-plane/src/server/durable-objects/boot-session-core.test.ts:520` is the existing test. It awaits the first approval before starting the second, so it never overlaps them and passes today.

### Fix

Re-read the row and re-check the status immediately before the transition, with no await between the read and the write. JavaScript is single threaded, so a synchronous read, check and write cannot be interleaved:

```ts
const current = this.#readBoot(boot.id);
if (current === null || current.status !== "PENDING") {
  return failure("conflict", "That boot changed state while it was being approved.");
}
const next = this.#apply(current, "approve");
```

Everything computed before that point (the envelope, the payload, the digest) is still valid for the winner and is simply discarded by the loser.

### Tests

`apps/control-plane/src/server/durable-objects/boot-session.security.test.ts`, three cases. Two are `it.fails`: "lets one approval win and answers the other with a conflict" and "keeps the delivered frame and the stored digest in agreement". The third, "writes at most one approval record for a boot", passes today only because of the primary key.

## Finding 2: revoking a token does not stop a reconnect

Severity: medium. Component: `BootSessionCore` resume handlers.

### Attack

Spec section 17 says the environment bootstrap token must still be valid on reconnect, and calls that the administrator's kill switch. Spec section 38 says revoking a token prevents reconnect. Neither handler in the resume path takes the connection's identity: `#handleResume` and `#handleChallengeResponse` are given a socket and a boot id and nothing else. They never compare the connecting token against `boots.token_id`, and they never re-read `revoked_at` or `expires_at`.

Two consequences. First, any token that is still valid for the environment can drive the resume of a boot that a different token opened, which matters when an operator revokes one deployment's token but leaves another in place. Second, and worse, the only thing that actually stops a resume after a revocation is `cancelForToken`, and that call is best effort: `revokeBootstrapToken` wraps it in a try/catch that logs and moves on when the Durable Object cannot be reached. If that call fails, the token is dead for new sockets but every boot it already opened keeps its reconnect rights, including redelivery of an approved payload, until its own TTL expires. For an APPROVED boot that is up to five minutes of continued key delivery after the operator believed they had cut it off.

The attacker still needs the boot's Ed25519 private key to answer the challenge, so this is not a takeover. It is a revocation that does not revoke.

### Evidence

- `apps/control-plane/src/server/durable-objects/boot-session-core.ts:530`, `#handleResume(connection, bootId)` takes no identity.
- `apps/control-plane/src/server/durable-objects/boot-session-core.ts:552`, `#handleChallengeResponse(connection, bootId, signature)` likewise, and it attaches the socket and redelivers without consulting any token.
- `apps/control-plane/src/server/vault/tokens.ts:135`, the empty `catch` that swallows a failed cancel.
- Compare `approve`, which does re-check the token at `boot-session-core.ts:780`.

### Fix

Thread `identity` through `handleFrame` into both resume handlers. In `#handleChallengeResponse`, before attaching the socket:

1. Refuse with 4403 when `identity.tokenId !== boot.token_id`.
2. Load the token with `getBootstrapTokenByTokenId(db, boot.token_id.replace(/^tok_/, ""))` and refuse with 4403 when it is missing, revoked, or past `expires_at`, the same three checks `approve` already makes.

Do the token check in `#handleChallengeResponse` rather than `#handleResume` so a revoked token cannot use the challenge as an oracle for which boot ids exist.

### Tests

`boot-session.security.test.ts`, two `it.fails` cases: "refuses to resume a boot whose token was revoked" and "refuses a resume driven by a different token than the one that opened the boot". Two passing cases cover the path that does work, cancelling on revocation and leaving other tokens' boots alone.

## Finding 3: a pending boot past its TTL still resumes as pending

Severity: medium. Component: `BootSessionCore.#handleChallengeResponse`.

### Attack

After a successful resume proof the handler branches on status. The APPROVED and DELIVERED branch checks `payload_expires_at` and expires the boot when it has passed. The PENDING branch checks nothing: it sends `boot.resumed` with `expiresAt` taken straight from `pending_expires_at`, even when that timestamp is in the past.

The alarm normally catches this first. It does not always run first. A Durable Object that has been hibernated and woken by an incoming socket handles the message before the alarm fires, and an alarm that was dropped or delayed leaves the row live indefinitely. Spec section 18 is explicit that an expired request becomes EXPIRED and never stays PENDING or becomes reusable. Today the state machine relies entirely on a timer to enforce that, with no check on the read path, which is the same mistake as trusting a stale D1 row.

The blast radius is bounded because `approve` does check the pending TTL, so an expired boot cannot be approved. What it can do is stay visible, stay resumable, and keep telling the client a deadline that has already gone.

### Evidence

`apps/control-plane/src/server/durable-objects/boot-session-core.ts:593` to `602`, the PENDING branch, against `604` to `608`, the payload branch that does check.

### Fix

Mirror the payload branch:

```ts
if (boot.status === "PENDING") {
  if (boot.pending_expires_at !== null && boot.pending_expires_at <= this.#deps.now()) {
    await this.#expire(boot, "expirePending");
    return;
  }
  ...
}
```

Consider doing the same at the top of `#handleResume` so an expired boot answers with its terminal frame instead of a challenge.

### Tests

`boot-session.security.test.ts`, one `it.fails` case: "expires a pending boot on resume when its TTL has already passed". The payload-side equivalent, "refuses to redeliver a payload once the payload TTL has passed", passes today and is there to keep the two branches honest against each other.

## Finding 4: two policy changes skip the step-up check

Severity: medium. Component: server functions for tokens and trusted signers.

### Attack

Spec section 22 requires a passkey verification newer than five minutes before approving a boot, rotating keys, creating a token, deleting an environment and changing a provenance requirement. Every one of those is guarded. Two neighbouring mutations are not, and both loosen a control that the guarded operations depend on.

`addTrustedSignerFn` adds an Ed25519 public key that the signed-build-manifest verifier will then treat as authoritative for the environment. Under `REQUIRED` provenance, adding a signer is exactly how an approval becomes possible: sign your own manifest, add your own key, and the verifier returns VERIFIED. It is the provenance requirement, reached from the other side.

`updateTokenCidrsFn` rewrites a token's allowed source addresses. Widening the list to `0.0.0.0/0` turns off the IP restriction that spec section 12 describes as an additional constraint on a stolen token.

An attacker with a hijacked but idle admin session, one that signed in more than five minutes ago and therefore cannot approve a boot, can still do both of these and then wait for a legitimate approval to deliver secrets to a boot they control from an address that was previously blocked.

### Evidence

- `apps/control-plane/src/server/functions/tokens.ts:78` to `89`, `updateTokenCidrsFn`, `requireRole("admin")` and no step-up.
- `apps/control-plane/src/server/functions/tokens.ts:101` to `117`, `addTrustedSignerFn`, same.
- Compare `createBootstrapTokenFn` at `tokens.ts:61` to `62`, which does call `requireRecentPasskey`.

`revokeBootstrapTokenFn` and `revokeTrustedSignerFn` are correctly left alone: both tighten, and a step-up prompt in front of a revocation is a reason not to revoke.

### Fix

Add `await requireRecentPasskey();` after the `requireRole("admin")` line in both functions.

### Tests

None added. Both functions import `cloudflare:workers` through the guards, which no test in this app can load; the existing app tests all avoid that import deliberately. The check is a one-line change and the fix is verified by reading it. Extracting the guard chain into a pure function would make this testable, and would also make finding 6 testable.

## Finding 5: the Go client accepts frames 32 times larger than the protocol allows

Severity: low. Component: `apps/env-client/internal/client/session.go`.

### Attack

The protocol document caps a frame at 1 MiB and the server enforces that on the way in, at `boot-session-core.ts:397`. The client sets its read limit to 32 MiB. A control plane that has been taken over, or anything that can terminate TLS between the workload and the vault, can send every reconnecting workload a 32 MiB frame per read and make it buffer all of it. The reconnect loop retries with backoff, so this repeats.

Nothing else in the client bounds the payload either. `validateApproved` walks `m.Secrets` with no cap, while the protocol limits a payload to 4096 records.

I tested this by padding a valid `boot.approved` with an unknown JSON field out to 2 MiB. The Go decoder ignores unknown fields, so the client opened the envelope, decrypted both secrets, acknowledged the frame and exec'd the target command on a payload the server would have refused to send.

### Evidence

`apps/env-client/internal/client/session.go:24`, `const readLimit = 32 << 20`, applied at `session.go:167`.

### Fix

Set `readLimit` to `1 << 20` to match the protocol, and add a `len(m.Secrets) > 4096` check to `validateApproved` in `internal/protocol/codec.go`. The comment above `readLimit` reasons about 256 secrets at 64 KiB each, but that arithmetic is about plaintext; the wire limit is what the server enforces and the client should agree with it.

### Tests

`apps/env-client/internal/client/hostile_server_security_test.go`, `TestClientRefusesAFrameLargerThanTheProtocolLimit`, marked `t.Skip` with a reference to this finding. Removing the skip today produces "the client opened and acknowledged a frame larger than the protocol allows".

## Finding 6: an unparseable step-up timestamp grants step-up

Severity: medium. Component: `requireRecentPasskey`.

### Attack

The guard computes the age of the last passkey assertion and compares it against the maximum:

```ts
const ageSeconds =
  verifiedAt === null ? Number.POSITIVE_INFINITY : (Date.now() - verifiedAt.getTime()) / 1000;
if (ageSeconds > maxAgeSeconds) { throw ... }
```

`verifiedAt` comes from the session schema, which accepts a `Date`, a string it passes to `new Date(...)`, or a number. A string the `Date` constructor cannot parse produces an Invalid Date rather than a schema error, `getTime()` returns `NaN`, `ageSeconds` is `NaN`, and `NaN > 300` is `false`. The guard returns the session and the caller proceeds. Every step-up protected operation, approving a boot included, is then reachable from a session of any age.

The null case is handled correctly and yields `Infinity`, so the bug is specifically in the parse-failure path. Getting there needs the `stepUpAt` column to come back as something `Date` cannot read, which depends on how the Better Auth Kysely D1 dialect round-trips a nullable date column on a table that also has rows written before the field existed. I have not reproduced it against a live D1. I am reporting it anyway because the direction of the failure is wrong: a guard whose whole job is to refuse should not treat an unreadable timestamp as fresh. A negative age, from clock skew or a future timestamp, passes for the same reason.

### Evidence

- `apps/control-plane/src/server/auth/guards.ts:141` to `142`, the age computation.
- `apps/control-plane/src/server/auth/guards.ts:34` to `38`, `dateFromSession`, which does not reject an Invalid Date.

### Fix

Treat anything that is not a finite, non-future timestamp as infinitely old:

```ts
const verifiedAtMillis = verifiedAt?.getTime() ?? Number.NaN;
const ageSeconds = Number.isFinite(verifiedAtMillis)
  ? Math.max(0, (Date.now() - verifiedAtMillis) / 1000)
  : Number.POSITIVE_INFINITY;
```

While in there, tighten `dateFromSession` to reject a value whose `getTime()` is `NaN`, so the same input also shows up as `auth.session.unparseable` in the log.

### Tests

None added, for the reason given under finding 4: `guards.ts` reaches `cloudflare:workers` through `createAuth`. Moving the age arithmetic into an exported pure function, `stepUpAgeSeconds(verifiedAt: Date | null, now: number): number`, would make it a three-line unit test.

## Finding 7: the setup ceremony throws instead of answering 404 when no setup token is set

Severity: low. Component: `vaultSetup` plugin.

### Attack

The endpoint reads `env.VAULT_SETUP_TOKEN` and immediately takes `.length` on it. When the Worker secret is not configured the binding is absent, the property read yields `undefined`, and `.length` throws a `TypeError` inside the endpoint handler. The result is a 500 rather than the 404 the code is careful to return everywhere else.

This fails closed, so no account is created. What it leaks is the distinction the rest of the handler works to hide: a 500 on an unconfigured vault against a 404 on a configured one tells a prober whether the setup ceremony is still open and whether an operator has got as far as setting the token. On a vault with no accounts yet, that is the one endpoint worth probing.

The re-enablement guard itself is correct. The endpoint checks `listUsers(1)` first and answers 404 the moment any user exists, `deleteUser` is disabled, and there is no other path that creates a user, so the ceremony cannot be reopened by deleting accounts through the product.

### Evidence

`apps/control-plane/src/server/auth/setup-plugin.ts:68` to `69`.

### Fix

```ts
const expected = env.VAULT_SETUP_TOKEN ?? "";
```

The existing `expected.length === 0` branch then does the right thing, and the constant-time comparison below it already handles a length mismatch.

## Finding 8: no per-source rate limit

Severity: low. Component: bootstrap endpoint.

Spec section 37 asks for two limits: concurrent pending boots per token, and a boot request creation threshold per source address. The first is implemented and enforced in the Durable Object. The second does not exist. `CLOSE_CODES.RATE_LIMITED` is defined in the protocol package and mapped to HTTP 429 in `bootstrap-auth.ts:75`, but nothing in the server ever sends it.

An attacker holding a stolen token is capped at three pending boots, which is the limit that matters for authorization. What is uncapped is connection churn: repeated upgrades each cost a token lookup, a SHA-256, a D1 read and a D1 write to `last_seen_at`, and each hello that is refused for exceeding the pending cap still wakes the Durable Object. The spec is right that this is abuse protection rather than an authorization control, so I would not hold launch for it, but the checklist item is not met.

The `touchBootstrapTokenLastSeen` write on every successful authentication is the specific thing to look at: it makes every reconnect a D1 write, which is both the cost driver under churn and the thing an attacker can force cheaply.

## Finding 9: CSRF rests entirely on the cookie attribute

Severity: informational. Component: TanStack Start server functions.

Every mutating server function is `createServerFn({ method: "POST" })`, every one of them calls a guard, and the session cookie is set `SameSite=Strict`, `HttpOnly`, and `Secure` whenever `BETTER_AUTH_URL` is https. A cross-site POST therefore arrives with no cookie and is refused as unauthenticated. Better Auth's own endpoints additionally check `trustedOrigins`, which is pinned to the single base URL.

That is a correct posture, and it is also the only layer. The server functions themselves do not check `Origin`. If `useSecureCookies` ever ends up false in a deployed environment, which happens automatically when `BETTER_AUTH_URL` is not https, the cookie loses `Secure` while keeping `SameSite=Strict`. There is no test anywhere that asserts the cookie attributes, so a future change to `advanced.defaultCookieAttributes` would not be caught.

Two things worth doing, neither urgent: assert the built options in a unit test, since `buildAuthOptions` is a pure function that does not import `cloudflare:workers` and is trivially testable, and refuse to boot when `BETTER_AUTH_URL` is not https outside local development.

## What held up

Recording these so the next reviewer does not redo them.

The AAD strings bind every field they need to. Moving a secret between environments, renaming it, replaying an older version, or swapping in a ciphertext from another environment key all fail authentication. The boot envelope binds the boot id, the environment id, the key version and both key fingerprints, so a captured approval frame is useless to a boot with different keys, and a low-order X25519 point is rejected explicitly.

Token comparison is constant time over the SHA-256 hex, the query string is refused before the token is parsed or hashed, and the CIDR check reads `CF-Connecting-IP` only. An absent `CF-Connecting-IP` with a policy configured fails closed, and an unreadable `allowed_cidrs_json` is treated as a deny rather than as no policy.

The internal `x-env-vault-*` headers are deleted from the client's request before the Worker sets them, `Authorization` is deleted too, and the environment comes from the token rather than from anything the client sends. Header casing does not matter because `Headers.delete` is case insensitive.

The log layer has a closed field set with no free-form payload, so no call site can smuggle a value into a line. Audit metadata is a flat map of scalars for the same reason. I ran a full administrative session plus a full boot through both and searched everything the server wrote, log lines, audit rows, every D1 table and the Durable Object's own storage, for eleven markers including the plaintext secrets, both halves of the bootstrap token, the environment key and the master key in two encodings. Nothing matched.

The dotenv parser reports problems by line number and variable name and never by value. The approval is bound to a digest of the verifier run the approver read, and the verifiers are re-run fresh at approval time so a signer revoked while the screen was open takes effect immediately.

The Go client pins the environment id and the payload digest after the first approval, refuses duplicate secret names, refuses names that are not POSIX variables, and strips `VAULT_BOOTSTRAP_TOKEN` from the child environment.

## Tests added

All new files. No existing test or source file was changed.

| File                                                                          | Cases | Failing pending a fix |
| ----------------------------------------------------------------------------- | ----- | --------------------- |
| `packages/crypto/tests/cross-binding.security.test.ts`                        | 9     | 0                     |
| `apps/control-plane/src/server/bootstrap/edge.security.test.ts`               | 12    | 0                     |
| `apps/control-plane/src/server/durable-objects/boot-session.security.test.ts` | 17    | 5                     |
| `apps/control-plane/src/server/redaction.security.test.ts`                    | 2     | 0                     |
| `apps/env-client/internal/client/hostile_server_security_test.go`             | 8     | 1                     |

The six failing cases are marked `it.fails` in TypeScript and `t.Skip` in Go, each with a comment naming the finding. They go green when the fix lands and start failing again if it regresses.

## Spec section 47 launch criteria

| Criterion                                        | Satisfied by                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No plaintext vault values visible in raw D1      | `packages/vault-store/tests/raw-contents.test.ts`, `service.test.ts` "no row in any table holds a plaintext value or a key in the clear", and `redaction.security.test.ts`, which dumps every table after a full scenario and a full boot.                                                                                                                                                               |
| No plaintext secrets in Worker logs              | `redaction.security.test.ts` "a full administrative session and boot leak nothing through logs or stored rows" captures every `console` line the log layer writes and searches it, plus `log.test.ts` for the header redaction and the closed field set.                                                                                                                                                 |
| No plaintext secrets in Docker image             | Not satisfied by an automated test. `examples/zeabur-node-app/Dockerfile` builds only the client binary and the app, and the design has no build-time secret, but nothing scans a built image. Procedure: build the example image and run a layer scan before each release.                                                                                                                              |
| Bootstrap token cannot retrieve secrets directly | `edge.security.test.ts` (the token resolves an identity and nothing else) and `boot-session-core.test.ts:315` "gives a stolen token its own boot and leaves the legitimate one untouched". No path exists from a token to a payload without an approval.                                                                                                                                                 |
| IP policy tested                                 | `bootstrap-auth.test.ts` and `edge.security.test.ts` "source address policy", covering the allow case, the deny case, `X-Forwarded-For` being ignored, a missing `CF-Connecting-IP`, and an unreadable policy. `packages/crypto/tests/cidr.test.ts` covers the matcher.                                                                                                                                  |
| Passkey approval tested                          | Not satisfied. Step-up is covered only by reading `guards.ts`, and finding 6 is a fail-open path in exactly that code. There is no test at all for `requireRecentPasskey`, and no browser-driven WebAuthn test. Missing: the pure-function extraction described under finding 6, and a manual ceremony run recorded against a real deployment.                                                           |
| WS hibernation tested                            | Partly. `boot-session-core.test.ts` uses `harness.restart()` to build a fresh core over the same storage, which is what a woken object does, and proves no state lives in memory. The real `acceptWebSocket` and tag round-trip in `environment-session.ts` is not exercised, because no test in this app runs under workerd. Missing: one workerd test that hibernates a socket and resumes through it. |
| Reconnect proof tested                           | `boot-session-core.test.ts` "resume" and `boot-session.security.test.ts`, covering a copied boot id, a foreign signing key, a spent challenge, an expired challenge and a stale challenge. Go side: `fakevault_test.go` `modeWrongSignature`.                                                                                                                                                            |
| Network-loss-after-approval tested               | `boot-session-core.test.ts` "holds the payload when no socket is attached and sends it on resume" and "redelivers the identical frame after a reconnect inside the payload TTL", plus `boot-session.security.test.ts` for the refusal once the payload TTL has passed and for the crashed-client case. Go side: `TestApprovedFlowExecsWithTheDecryptedEnvironment`, which drops the first connection.    |
| Concurrent approval race tested                  | Tested and failing. `boot-session.security.test.ts` "lets one approval win and answers the other with a conflict" is `it.fails` against finding 1. Not satisfied until that fix lands.                                                                                                                                                                                                                   |
| Token revocation tested                          | Partly. `boot-session-core.test.ts` "cancels every live boot for a revoked token", "refuses an approval once the bootstrap token was revoked", and `bootstrap-auth.test.ts` "rejects a revoked token with 4403" all pass. The reconnect half is `it.fails` against finding 2. Not satisfied until that fix lands.                                                                                        |
| D1 compromise simulation tested                  | `packages/vault-store/tests/raw-contents.test.ts`, `service.test.ts` "redaction", `redaction.security.test.ts`, and `cross-binding.security.test.ts`, which takes the attacker's position of holding both environments' rows and shows the AAD refuses every swap.                                                                                                                                       |
| Zeabur env-dump simulation tested                | `apps/env-client/internal/run/run_test.go` and `client_test.go` show the token is stripped from the child environment; `edge.security.test.ts` and `boot-session-core.test.ts:315` show what a stolen token buys, which is a boot request an administrator has to approve.                                                                                                                               |
| Provenance failure states tested                 | `provenance.test.ts` covers all four statuses, a tampered signature, an untrusted signer, a claim mismatch, and every `REQUIRED` blocking path including the no-configured-rows fallback. `boot-session.security.test.ts` covers the evidence digest guard at approval.                                                                                                                                  |
| Key rotation runbook tested                      | Partly. `service.test.ts` "rotation" covers project and environment key rotation including re-encryption counts. `docs/key-rotation.md` exists. The runbook itself, master key rewrap against a live deployment, has not been walked through. Missing: one recorded dry run.                                                                                                                             |
| Master-key backup verified                       | Not satisfied. `loadMasterKeys` reads and validates every configured version and `keys.test.ts` covers that, but nothing verifies a backup can be restored. This is an operator procedure: restore `VAULT_MASTER_KEY_V<n>` from backup into a scratch Worker, unwrap one project key, record the result.                                                                                                 |
| Zeabur long-start behavior validated             | Not satisfied. Every row in `docs/zeabur.md` is unrun. Missing: the live matrix, native Git build, prebuilt OCI, readiness timing and reconnect under a real deployment.                                                                                                                                                                                                                                 |

Seven of the seventeen criteria are not met. Three of those (concurrent approval, token revocation, passkey approval) are code fixes with tests already written or described. The other four (Docker image scan, hibernation under workerd, key rotation dry run, master key restore, Zeabur matrix) are procedures somebody has to run against a real deployment and record.
