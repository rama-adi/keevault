# Security review, V1

This is the historical V1 review and its original follow-up notes. It is not a current launch sign-off. The [2026-09-09 audit](audit-2026-09-09.md) found additional secret-write and setup-session issues, now fixed, plus unresolved initial-owner creation and key-rotation races. Its current findings qualify the conclusions and launch criteria below. Browser, live-runtime, backup, and deployment checks remain unverified unless a later report records their results.

Reviewed against docs/product-specs.md sections 3, 11 to 18, 20, 22, 35 to 38, 41, 43 phase 11, 44 and 47, plus docs/threat-model.md and protocol/websocket-v1.md. Code read: packages/crypto/src, packages/protocol/src, apps/control-plane/src/server (auth, bootstrap, durable-objects, provenance, vault, functions, log.ts, worker.ts), apps/control-plane/src/routes/boots, apps/env-client/internal.

Findings 1 to 8 have since been fixed in this repository. Each finding below carries a "Fixed" note saying what changed and which test proves it, and every test that was written to fail against a finding now passes as an ordinary test. Finding 9 is informational and still open.

The core is in good shape. The key hierarchy, the AAD strings, the boot envelope and the resume proof all hold up against the section 44 attacks, and I could not construct a path to a plaintext secret without an administrator approving the attacker's own ephemeral key. Every finding below is either a state-machine gap or a defence-in-depth control that is weaker than the spec asks for. The two I would fix before launch are 1 and 6: one turns a double-clicked approve button into a dead boot, and the other is a step-up guard that fails open on a value it cannot parse.

The review itself changed no source file: it added five test files and 48 cases, 6 of them marked failing against the finding they were waiting on. A later work package fixed findings 1 to 8 and turned those 6 into ordinary passing cases.

## Findings

| Id  | Severity      | Component                         | Status |
| --- | ------------- | --------------------------------- | ------ |
| 1   | High          | Durable Object, approval          | fixed  |
| 2   | Medium        | Durable Object, reconnect         | fixed  |
| 3   | Medium        | Durable Object, pending TTL       | fixed  |
| 4   | Medium        | Server functions, step-up         | fixed  |
| 5   | Low           | Go client, frame limit            | fixed  |
| 6   | Medium        | Better Auth guards, step-up       | fixed  |
| 7   | Low           | Better Auth, setup ceremony       | fixed  |
| 8   | Low           | Bootstrap endpoint, rate limiting | fixed  |
| 9   | Informational | Server functions, CSRF posture    | open   |

"fixed" means the source change is in the working tree and a test that fails without it passes with it. The test files named under each finding are the ones to run.

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

`apps/control-plane/src/server/durable-objects/boot-session.security.test.ts`, four cases, all passing: "lets one approval win and answers the other with a conflict", "keeps the delivered frame and the stored digest in agreement", "gives the conflict to the approval that started first when it finishes last", and "writes at most one approval record for a boot".

### Fixed

`approve` in `boot-session-core.ts` now does every await first (the token read, the environment read, the provenance context, the verifier run, the key unwrap, the secret list and the envelope), then re-reads the boot row and applies the transition and the payload write in one synchronous storage step with no await in between. A second approval that overlapped the first reads APPROVED and returns `conflict` before it writes anything, so `delivered_frame` and `payload_digest` still belong to the winner. The third test parks the first approval inside the key unwrap and runs the second to completion in the gap, so the call that started first is the one that gets the conflict.

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

`boot-session.security.test.ts`, four passing cases: "refuses to resume a boot whose token was revoked", "refuses a resume driven by a different token than the one that opened the boot", "cancels the boots a revoked token opened when the cancel does reach the object", and "leaves boots from another token alone when one token is revoked".

### Fixed

`handleFrame` passes the authenticated identity into both resume handlers. `#handleResume` refuses with 4403 when `identity.tokenId` is not the boot's `token_id`. `#handleChallengeResponse` repeats that check and then re-reads the token from D1 through `#tokenStillValid`, refusing with 4403 when it is missing, revoked or past `expires_at`; a revoked token also cancels the boot on the spot, so the kill switch lands even when the cancel at revocation time never reached the object. `revokeBootstrapToken` in `src/server/vault/tokens.ts` still revokes the row before it cancels, and the swallowed cancel is now harmless.

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

`boot-session.security.test.ts`, two passing cases: "expires a pending boot on resume when its TTL has already passed" and the payload-side equivalent "refuses to redeliver a payload once the payload TTL has passed".

### Fixed

`#expireIfDue` expires one boot whose deadline has passed and returns the current row. Both `#handleResume` and `#handleChallengeResponse` call it before they do anything else with the boot, so an overdue PENDING boot answers `boot.expired` with close 4410 instead of a challenge or a `boot.resumed`. `#handleHello` calls `#expireDue` first, which is the same sweep the alarm runs, so an overdue boot no longer occupies a slot in the token's pending count.

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

No direct test: all three functions reach `cloudflare:workers` through the guards, which no test in this app can load. The freshness rule the guard applies is now a pure function with its own tests, covered under finding 6.

### Fixed

`await requireRecentPasskey();` follows `requireRole("admin")` in `updateTokenCidrsFn`, `addTrustedSignerFn` and `revokeTrustedSignerFn` in `src/server/functions/tokens.ts`. Revoking a signer is gated too, so the trusted-signer list cannot be edited in either direction from an idle session. The step-up table in `docs/dashboard.md` records the three rows as step-up gated.

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

`apps/env-client/internal/client/hostile_server_security_test.go`, `TestClientRefusesAFrameLargerThanTheProtocolLimit`, no longer skipped, and `apps/env-client/internal/protocol/protocol_test.go`, `TestDecodeRejectsMoreSecretsThanTheProtocolAllows`.

### Fixed

`session.go` sets `maxFrameBytes` to the protocol's 1 MiB and reads at most that plus 64 KiB of slack, so a frame just over the limit is read and reported as a protocol error rather than as a torn connection, and anything larger is cut off by the transport. Both paths end in exit 5: `read` refuses a frame over `maxFrameBytes`, and `classifyRead` maps `websocket.ErrMessageTooBig` to the same exit. `validateApproved` in `internal/protocol/codec.go` refuses a payload carrying more than `MaxSecretsPerPayload`, which is 4096.

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

`apps/control-plane/src/server/auth/step-up-policy.test.ts`, 12 cases covering the window, a missing timestamp, an empty one, two the `Date` constructor cannot read, a future timestamp inside and outside the skew allowance, and an unreadable clock.

### Fixed

`isRecentStepUp(stepUpAt, now, maxAgeSeconds)` lives in `src/server/auth/step-up-policy.ts`, imports nothing from Cloudflare or Better Auth, and returns false for a missing timestamp, an unparseable timestamp, an unreadable clock and any timestamp more than 60 seconds in the future. `requireRecentPasskey` in `guards.ts` calls it instead of computing an age itself. `dateFromSession` now rejects a value whose `getTime()` is not finite, so the same input shows up as `auth.session.unparseable` and the session is refused.

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

### Tests

`apps/control-plane/src/server/auth/setup-token.test.ts`, 9 cases: the configured token, a wrong token, an unset secret, an empty secret, a prefix of the token, and the constant-time comparison itself.

### Fixed

`setupTokenAccepted(configured, presented)` and `constantTimeEquals` moved to `src/server/auth/setup-token.ts`, which has no Cloudflare import. `setup-plugin.ts` calls it with `env.VAULT_SETUP_TOKEN`, so an absent binding, an empty secret and a wrong token all answer false and produce the same 404.

## Finding 8: no per-source rate limit

Severity: low. Component: bootstrap endpoint.

Spec section 37 asks for two limits: concurrent pending boots per token, and a boot request creation threshold per source address. The first is implemented and enforced in the Durable Object. The second does not exist. `CLOSE_CODES.RATE_LIMITED` is defined in the protocol package and mapped to HTTP 429 in `bootstrap-auth.ts:75`, but nothing in the server ever sends it.

An attacker holding a stolen token is capped at three pending boots, which is the limit that matters for authorization. What is uncapped is connection churn: repeated upgrades each cost a token lookup, a SHA-256, a D1 read and a D1 write to `last_seen_at`, and each hello that is refused for exceeding the pending cap still wakes the Durable Object. The spec is right that this is abuse protection rather than an authorization control, so I would not hold launch for it, but the checklist item is not met.

The `touchBootstrapTokenLastSeen` write on every successful authentication is the specific thing to look at: it makes every reconnect a D1 write, which is both the cost driver under churn and the thing an attacker can force cheaply.

### Tests

`boot-session.security.test.ts`, two cases: "refuses the eleventh boot from one source address inside the window" and "counts each source address on its own and forgets the window".

### Fixed

`BootSessionCore` enforces the creation threshold in `#handleHello`: at most `MAX_BOOTS_PER_SOURCE` (10) new boots per source address per environment in any `BOOT_RATE_WINDOW_SECONDS` (60) window, counted from `boots.created_at` so cancelled and expired requests still count. The next `boot.hello` from that address gets `boot.error` with 4429 and a close with the same code, and no boot row is written. A request with no source address is not rate limited, because there is nothing to attribute it to. `protocol/websocket-v1.md` records the limit under close codes. This is abuse protection at the object, not at the edge: the upgrade itself, including the token lookup and the `last_seen_at` write, is still uncapped.

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
| `apps/control-plane/src/server/durable-objects/boot-session.security.test.ts` | 20    | 0                     |
| `apps/control-plane/src/server/redaction.security.test.ts`                    | 2     | 0                     |
| `apps/env-client/internal/client/hostile_server_security_test.go`             | 8     | 0                     |

The six cases that were marked `it.fails` in TypeScript and `t.Skip` in Go are now ordinary passing cases, and they fail again if the fix regresses. Three more cases were added with the fixes: the approval race seen from the losing call, and the two source-address rate limit cases. The fixes also added `apps/control-plane/src/server/auth/step-up-policy.test.ts` (12 cases) and `apps/control-plane/src/server/auth/setup-token.test.ts` (9 cases).

## Spec section 47 launch criteria

| Criterion                                        | Satisfied by                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No plaintext vault values visible in raw D1      | `packages/vault-store/tests/raw-contents.test.ts`, `service.test.ts` "no row in any table holds a plaintext value or a key in the clear", and `redaction.security.test.ts`, which dumps every table after a full scenario and a full boot.                                                                                                                                                                                  |
| No plaintext secrets in Worker logs              | `redaction.security.test.ts` "a full administrative session and boot leak nothing through logs or stored rows" captures every `console` line the log layer writes and searches it, plus `log.test.ts` for the header redaction and the closed field set.                                                                                                                                                                    |
| No plaintext secrets in Docker image             | Not satisfied by an automated test. `examples/zeabur-node-app/Dockerfile` builds only the client binary and the app, and the design has no build-time secret, but nothing scans a built image. Procedure: build the example image and run a layer scan before each release.                                                                                                                                                 |
| Bootstrap token cannot retrieve secrets directly | `edge.security.test.ts` (the token resolves an identity and nothing else) and `boot-session-core.test.ts:315` "gives a stolen token its own boot and leaves the legitimate one untouched". No path exists from a token to a payload without an approval.                                                                                                                                                                    |
| IP policy tested                                 | `bootstrap-auth.test.ts` and `edge.security.test.ts` "source address policy", covering the allow case, the deny case, `X-Forwarded-For` being ignored, a missing `CF-Connecting-IP`, and an unreadable policy. `packages/crypto/tests/cidr.test.ts` covers the matcher.                                                                                                                                                     |
| Passkey approval tested                          | Partly. The freshness rule is now the pure `isRecentStepUp`, covered by `step-up-policy.test.ts` including every fail-closed path from finding 6, and `guards.ts` calls it. There is still no browser-driven WebAuthn test. Missing: a manual ceremony run recorded against a real deployment.                                                                                                                              |
| WS hibernation tested                            | Partly. `boot-session-core.test.ts` uses `harness.restart()` to build a fresh core over the same storage, which is what a woken object does, and proves no state lives in memory. The real `acceptWebSocket` and tag round-trip in `environment-session.ts` is not exercised, because no test in this app runs under workerd. Missing: one workerd test that hibernates a socket and resumes through it.                    |
| Reconnect proof tested                           | `boot-session-core.test.ts` "resume" and `boot-session.security.test.ts`, covering a copied boot id, a foreign signing key, a spent challenge, an expired challenge and a stale challenge. Go side: `fakevault_test.go` `modeWrongSignature`.                                                                                                                                                                               |
| Network-loss-after-approval tested               | `boot-session-core.test.ts` "holds the payload when no socket is attached and sends it on resume" and "redelivers the identical frame after a reconnect inside the payload TTL", plus `boot-session.security.test.ts` for the refusal once the payload TTL has passed and for the crashed-client case. Go side: `TestApprovedFlowExecsWithTheDecryptedEnvironment`, which drops the first connection.                       |
| Concurrent approval race tested                  | Satisfied. Finding 1 is fixed and `boot-session.security.test.ts` covers it with three passing cases: one approval wins and the other gets a conflict, the delivered frame and the stored digest stay in agreement, and the approval that started first gets the conflict when it finishes last.                                                                                                                            |
| Token revocation tested                          | Satisfied. `boot-session-core.test.ts` "cancels every live boot for a revoked token" and "refuses an approval once the bootstrap token was revoked", `bootstrap-auth.test.ts` "rejects a revoked token with 4403", and, since finding 2 was fixed, `boot-session.security.test.ts` "refuses to resume a boot whose token was revoked" and "refuses a resume driven by a different token than the one that opened the boot". |
| D1 compromise simulation tested                  | `packages/vault-store/tests/raw-contents.test.ts`, `service.test.ts` "redaction", `redaction.security.test.ts`, and `cross-binding.security.test.ts`, which takes the attacker's position of holding both environments' rows and shows the AAD refuses every swap.                                                                                                                                                          |
| Zeabur env-dump simulation tested                | `apps/env-client/internal/run/run_test.go` and `client_test.go` show the token is stripped from the child environment; `edge.security.test.ts` and `boot-session-core.test.ts:315` show what a stolen token buys, which is a boot request an administrator has to approve.                                                                                                                                                  |
| Provenance failure states tested                 | `provenance.test.ts` covers all four statuses, a tampered signature, an untrusted signer, a claim mismatch, and every `REQUIRED` blocking path including the no-configured-rows fallback. `boot-session.security.test.ts` covers the evidence digest guard at approval.                                                                                                                                                     |
| Key rotation runbook tested                      | Partly. `service.test.ts` "rotation" covers project and environment key rotation including re-encryption counts. `docs/key-rotation.md` exists. The runbook itself, master key rewrap against a live deployment, has not been walked through. Missing: one recorded dry run.                                                                                                                                                |
| Master-key backup verified                       | Not satisfied. `loadMasterKeys` reads and validates every configured version and `keys.test.ts` covers that, but nothing verifies a backup can be restored. This is an operator procedure: restore `VAULT_MASTER_KEY_V<n>` from backup into a scratch Worker, unwrap one project key, record the result.                                                                                                                    |
| Zeabur long-start behavior validated             | Not satisfied. Every row in `docs/zeabur.md` is unrun. Missing: the live matrix, native Git build, prebuilt OCI, readiness timing and reconnect under a real deployment.                                                                                                                                                                                                                                                    |

Concurrent approval and token revocation are now satisfied, and passkey approval is satisfied on the server side. What is left is procedural or needs a runtime no test here has: a Docker image layer scan, one workerd test that hibernates a socket and resumes through it, the browser-driven passkey ceremony, a key rotation dry run, a master key restore, and the Zeabur live matrix. Nobody can close those from this repository alone.
