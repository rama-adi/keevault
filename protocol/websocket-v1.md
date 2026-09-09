# keevault bootstrap WebSocket protocol v1

This document is normative. It defines every frame exchanged on `/bootstrap/v1`, the states a boot request moves through, and when each side closes the socket. Implementations in TypeScript (`packages/protocol`) and Go (`apps/env-client/internal/protocol`) must agree byte for byte with what is written here.

The machine readable form of the message catalogue is `protocol/messages.schema.json`, generated from the zod schemas in `packages/protocol/src/messages.ts`. Example and counter-example frames are in `protocol/test-vectors/frames.json`. When this document and the schema disagree, fix both.

## Transport and authentication

The endpoint is a single URL:

```text
wss://<vault-host>/bootstrap/v1
```

The client opens it with an HTTP GET carrying `Upgrade: websocket` and this header:

```text
Authorization: Bearer vlt_boot_<tokenId>.<secret>
```

Token rules:

- The token format is `^vlt_boot_([0-9A-HJKMNP-TV-Z]{26})\.([A-Za-z0-9_-]{43})$`. The first group is a Crockford base32 ULID, the second is base64url of 32 random bytes.
- Send the token only in the `Authorization` header. A token in the query string is rejected before upgrade with HTTP 401, corresponding to protocol code 4401, even when otherwise valid, because URLs end up in logs.
- The server hashes the 43 character secret with SHA-256 and compares the lowercase hex digest against `token_hash` in D1 using a constant-time comparison.
- The server then checks revocation, expiry, and the token's CIDR allow list against `CF-Connecting-IP`. An empty allow list skips the CIDR check.

The token selects the environment. No client frame selects an environment. The Go client may pin an expected `environmentId` in local `keevault.json` configuration and reject a mismatched approval; that setting is not sent to the server.

Before the upgrade completes, failures are HTTP status codes: 401 for a missing or unparseable token, 403 for a revoked token or a CIDR miss, 429 for rate limiting. After the upgrade, the same conditions use the matching WebSocket close codes below.

## Framing

- Text frames only. A binary frame is a protocol error (4400).
- One frame carries exactly one JSON object. No frame batching, no newline-delimited streams.
- The object has a `type` string that selects the message. `type` is the discriminator for both directions.
- Unknown top-level fields are rejected. Every message schema is closed. The one exception is an evidence item whose `type` this version does not know, described under `boot.hello`.
- Encoding is UTF-8. A frame must not exceed 1 MiB.
- Binary values are base64url without padding, RFC 4648 section 5, written `b64u` below. Digests are lowercase hex. Timestamps are RFC 3339 UTC with exactly three fractional digits, for example `2026-09-05T10:00:00.000Z`.

A `b64u` field of n bytes is `ceil(n * 8 / 6)` characters. Where that count carries slack bits the final character is constrained: 43 characters ending in `[AEIMQUYcgkosw048]` for 32 bytes, 86 characters ending in `[AQgw]` for 64 bytes, 16 characters for 12 bytes, 64 characters for 48 bytes. Producers must zero the slack bits. Parsers must reject strings that do not.

Identifiers are prefixed ULIDs in Crockford base32: `boot_`, `env_`, `proj_`, `sec_`, each followed by 26 characters from `[0-9A-HJKMNP-TV-Z]`.

## Message catalogue

### Client to server

#### boot.hello

Opens a new boot request. It must be the first frame on a connection that is not resuming.

| Field                          | Format                                              | Required |
| ------------------------------ | --------------------------------------------------- | -------- |
| `type`                         | `"boot.hello"`                                      | yes      |
| `protocol`                     | integer `1`                                         | yes      |
| `bootNonce`                    | b64u of 16 to 64 random bytes                       | yes      |
| `signingPublicKey`             | b64u of a 32 byte Ed25519 public key                | yes      |
| `encryptionPublicKey`          | b64u of a 32 byte X25519 public key                 | yes      |
| `claims`                       | object, see below, may be empty                     | yes      |
| `claims.git.repository`        | printable ASCII without spaces, 1 to 512 characters | no       |
| `claims.git.commit`            | 40 or 64 lowercase hex characters                   | no       |
| `claims.oci.repository`        | `^[a-z0-9][a-z0-9._:/-]{0,254}$`                    | no       |
| `claims.oci.digest`            | `^sha256:[0-9a-f]{64}$`                             | no       |
| `claims.provider.name`         | slug, `^[a-z0-9][a-z0-9-]{0,62}$`                   | no       |
| `claims.provider.deploymentId` | printable ASCII without spaces, 1 to 128 characters | no       |
| `claims.provider.region`       | printable ASCII without spaces, 1 to 64 characters  | no       |
| `evidence`                     | array of evidence items, 0 to 32 entries            | yes      |

Each half of `claims` is optional and `claims` itself may be `{}`. Send `"claims": {}` rather than omitting the field.

An evidence item is either a signed build manifest or an item this version cannot check.

A `signed-build-manifest-v1` item has:

| Field                          | Format                                                        |
| ------------------------------ | ------------------------------------------------------------- |
| `type`                         | `"signed-build-manifest-v1"`                                  |
| `manifest.version`             | integer `1`                                                   |
| `manifest.source.repository`   | printable ASCII without spaces, 1 to 512 characters           |
| `manifest.source.commit`       | 40 or 64 lowercase hex characters                             |
| `manifest.artifact.type`       | `"oci"`                                                       |
| `manifest.artifact.repository` | `^[a-z0-9][a-z0-9._:/-]{0,254}$`                              |
| `manifest.artifact.digest`     | `^sha256:[0-9a-f]{64}$`                                       |
| `manifest.builder`             | printable ASCII, spaces allowed, 1 to 128 characters          |
| `manifest.issuedAt`            | RFC 3339 UTC with milliseconds                                |
| `signature`                    | b64u of a 64 byte Ed25519 signature                           |
| `signerFingerprint`            | 64 lowercase hex characters, SHA-256 of the signer public key |

The signature covers `vault:signed-build-manifest:v1\n` followed by the canonical manifest JSON: keys sorted by UTF-16 code unit order at every level, no whitespace, no HTML escaping.

Any other item must be a JSON object with a `type` that matches the slug pattern. The server stores it as sent and every verifier reports `UNAVAILABLE` for it. An item whose `type` is `signed-build-manifest-v1` but whose shape does not match the table is a protocol error, not an unknown item.

The server answers `boot.hello` with `boot.pending`, or with `boot.error` when the token already has the maximum number of pending boots (4409) or the frame is malformed (4400).

#### boot.resume

First frame on a reconnect. The client must not send `boot.hello` for a boot it already owns.

| Field      | Format                          |
| ---------- | ------------------------------- |
| `type`     | `"boot.resume"`                 |
| `protocol` | integer `1`                     |
| `bootId`   | `^boot_[0-9A-HJKMNP-TV-Z]{26}$` |

The server answers with `boot.challenge`, or with a terminal frame when the boot has finished, or `boot.error` with 4404 when the boot does not belong to this environment.

#### boot.challenge-response

| Field       | Format                              |
| ----------- | ----------------------------------- |
| `type`      | `"boot.challenge-response"`         |
| `bootId`    | boot identifier                     |
| `signature` | b64u of a 64 byte Ed25519 signature |

The signature covers the resume message defined under "Reconnect and resume proof". The server verifies it against the `signingPublicKey` from the original `boot.hello`, not against any key in this frame.

#### boot.received

Sent only after the client decrypted the key envelope, decrypted every secret record, and validated all of them.

| Field           | Format                      |
| --------------- | --------------------------- |
| `type`          | `"boot.received"`           |
| `bootId`        | boot identifier             |
| `payloadDigest` | 64 lowercase hex characters |

### Server to client

#### boot.pending

| Field       | Format                                                 |
| ----------- | ------------------------------------------------------ |
| `type`      | `"boot.pending"`                                       |
| `bootId`    | boot identifier                                        |
| `expiresAt` | RFC 3339 UTC with milliseconds, end of the pending TTL |

After sending it the Durable Object may hibernate.

#### boot.challenge

| Field       | Format                  |
| ----------- | ----------------------- |
| `type`      | `"boot.challenge"`      |
| `bootId`    | boot identifier         |
| `challenge` | b64u of 32 random bytes |

#### boot.resumed

Sent after a valid `boot.challenge-response`. The socket is now attached to the boot.

| Field       | Format                                                                                    |
| ----------- | ----------------------------------------------------------------------------------------- |
| `type`      | `"boot.resumed"`                                                                          |
| `bootId`    | boot identifier                                                                           |
| `status`    | `"PENDING"`, `"APPROVED"` or `"DELIVERED"`                                                |
| `expiresAt` | RFC 3339 UTC with milliseconds. Pending TTL when status is PENDING, payload TTL otherwise |

When `status` is `APPROVED` or `DELIVERED` the server sends `boot.approved` immediately afterwards.

#### boot.approved

| Field                         | Format                                                               |
| ----------------------------- | -------------------------------------------------------------------- |
| `type`                        | `"boot.approved"`                                                    |
| `bootId`                      | boot identifier                                                      |
| `projectId`                   | `^proj_[0-9A-HJKMNP-TV-Z]{26}$`                                      |
| `environmentId`               | `^env_[0-9A-HJKMNP-TV-Z]{26}$`                                       |
| `environmentKeyVersion`       | integer, 1 or greater                                                |
| `payloadExpiresAt`            | RFC 3339 UTC with milliseconds                                       |
| `keyEnvelope.serverPublicKey` | b64u of a 32 byte X25519 public key, fresh for this approval         |
| `keyEnvelope.salt`            | b64u of 32 random bytes                                              |
| `keyEnvelope.nonce`           | b64u of 12 random bytes                                              |
| `keyEnvelope.ciphertext`      | b64u of 48 bytes: the 32 byte environment key plus a 16 byte GCM tag |
| `secrets`                     | array of 0 to 4096 records                                           |
| `secrets[].id`                | `^sec_[0-9A-HJKMNP-TV-Z]{26}$`                                       |
| `secrets[].name`              | `^[A-Z_][A-Z0-9_]{0,255}$`                                           |
| `secrets[].version`           | integer, 1 or greater                                                |
| `secrets[].envKeyVersion`     | integer, 1 or greater                                                |
| `secrets[].nonce`             | b64u of 12 random bytes                                              |
| `secrets[].ciphertext`        | b64u of the AES-256-GCM ciphertext with its tag appended             |

The envelope derivation, the HKDF info string and the AAD are in the engineering brief under "Boot envelope". The client must reject the envelope when the X25519 shared secret is all zero.

#### boot.declined

| Field    | Format                                |
| -------- | ------------------------------------- |
| `type`   | `"boot.declined"`                     |
| `bootId` | boot identifier                       |
| `reason` | string up to 256 characters, optional |

The server closes with 4410 after sending it.

#### boot.expired

| Field    | Format           |
| -------- | ---------------- |
| `type`   | `"boot.expired"` |
| `bootId` | boot identifier  |

The server closes with 4410 after sending it.

#### boot.canceled

| Field    | Format                                |
| -------- | ------------------------------------- |
| `type`   | `"boot.canceled"`                     |
| `bootId` | boot identifier                       |
| `reason` | string up to 256 characters, required |

Sent when the bootstrap token was revoked, the environment was deleted, or an administrator canceled the boot. The server closes with 4410 after sending it.

#### boot.consumed

| Field    | Format            |
| -------- | ----------------- |
| `type`   | `"boot.consumed"` |
| `bootId` | boot identifier   |

The server closes with 1000 after sending it.

#### boot.error

| Field     | Format                                          |
| --------- | ----------------------------------------------- |
| `type`    | `"boot.error"`                                  |
| `code`    | one of 4400, 4401, 4403, 4404, 4409, 4410, 4429 |
| `message` | string, 1 to 512 characters, no secret material |

The server closes with the same numeric code it put in `code`.

## Boot state machine

The Durable Object for the environment owns boot state. D1 is an index and must never be read to decide a transition.

States: `PENDING`, `APPROVED`, `DELIVERED`, `CONSUMED`, `DECLINED`, `EXPIRED`, `CANCELED`. `CREATING` exists only inside the `boot.hello` handler, before the row is written, and is never observable.

Terminal states: `CONSUMED`, `DECLINED`, `EXPIRED`, `CANCELED`.

Transition table. Every pair not listed is rejected. The rejection reason is `terminal` when the current state is terminal and `conflict` otherwise.

| From      | Event           | To        | Trigger                                                                |
| --------- | --------------- | --------- | ---------------------------------------------------------------------- |
| PENDING   | `approve`       | APPROVED  | an administrator approved on the dashboard                             |
| PENDING   | `decline`       | DECLINED  | an administrator declined                                              |
| PENDING   | `expirePending` | EXPIRED   | the pending TTL alarm fired                                            |
| PENDING   | `cancel`        | CANCELED  | token revoked, environment deleted, or admin cancel                    |
| APPROVED  | `deliver`       | DELIVERED | the `boot.approved` frame was written to the socket                    |
| APPROVED  | `cancel`        | CANCELED  | token revoked, environment deleted, or admin cancel                    |
| APPROVED  | `expirePayload` | EXPIRED   | the payload TTL alarm fired                                            |
| DELIVERED | `redeliver`     | DELIVERED | the same payload was sent again after a resume, inside the payload TTL |
| DELIVERED | `consume`       | CONSUMED  | a valid `boot.received` arrived                                        |
| DELIVERED | `expirePayload` | EXPIRED   | the payload TTL alarm fired                                            |

`redeliver` is a no-op on state. It exists so redelivery goes through the same guard as every other event and so the audit log records it.

Single use applies to the authorization, not to TCP frames. The same payload may be sent again to the same boot key while the payload TTL is open. It may never be sent to a different key: a `boot.hello` with a new key pair is a new boot needing a new approval.

An approved boot that expires becomes `EXPIRED`. It never returns to `PENDING` and is never reusable.

The approval record binds the environment id, the boot id, the fingerprints of both client public keys, the evidence digest, the approver's user id, the approver's credential id, and the approval timestamp.

## Timing policy

| Timer                                  | Default                 | Notes                                                |
| -------------------------------------- | ----------------------- | ---------------------------------------------------- |
| Pending approval TTL                   | 1800 s                  | configurable per environment                         |
| Approved payload TTL                   | 300 s                   | starts at approval, not at delivery                  |
| Resume challenge TTL                   | 30 s                    | single use, discarded after one verification attempt |
| Reconnect backoff                      | 1 s to 15 s with jitter | client side, bounded by the client session timeout   |
| Max concurrent pending boots per token | 3                       | a fourth `boot.hello` gets 4409                      |

The server schedules pending and payload expiry with a Durable Object alarm and checks challenge expiry when verifying the response. A client must not assume a socket stays open for the whole TTL.

## Reconnect and resume proof

Losing the connection must not cancel an approval. The client keeps the boot id, the Ed25519 private key and the X25519 private key in memory until the boot succeeds or fails permanently. If the process restarts and loses those keys, the boot is unusable and the client must start a new one.

On reconnect the client presents the same bootstrap token, which must still be valid, then:

1. Client sends `boot.resume` with the boot id.
2. Server replies with `boot.challenge` carrying 32 random bytes as b64u.
3. Client signs, with the boot Ed25519 key, the UTF-8 bytes of exactly this string:

```text
vault-resume:v1
<bootId>
<challenge b64u exactly as received>
```

Three lines joined with `\n`. No trailing newline, no carriage returns. The challenge is copied verbatim, not re-encoded.

4. Client sends `boot.challenge-response` with the b64u signature.
5. Server verifies against the stored `signingPublicKey`, discards the challenge, and replies `boot.resumed`.

A challenge is valid for 30 seconds and for one verification attempt. A failed or late verification gets `boot.error` with 4400 and a close. The client may open a new connection and start again while the boot is still pending.

Revoking the bootstrap token blocks reconnects. This is the operator kill switch.

## Delivery and acknowledgement

The server sends `boot.approved` as one text frame and records the state change with `deliver`. It also stores `payloadDigest`, the lowercase hex SHA-256 of the exact UTF-8 bytes of that frame as transmitted.

The client computes the digest over the bytes it received, before parsing, and returns it in `boot.received`. The server requires equality with the digest it stored. A mismatch is a protocol error (4400) and the boot stays `DELIVERED` until it expires.

On a matching digest the server:

1. Applies `consume`, moving the boot to `CONSUMED`.
2. Writes the audit event.
3. Deletes the stored encrypted delivery payload.
4. Sends `boot.consumed`.
5. Closes with 1000.

Redelivery inside the payload TTL uses the same stored frame, so the digest does not change.

## Close codes

| Code | Meaning                                                                                        | Sent after                                         |
| ---- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| 1000 | the boot finished normally                                                                     | `boot.consumed`                                    |
| 4400 | protocol error: bad JSON, unknown type, schema violation, failed resume proof, digest mismatch | `boot.error`                                       |
| 4401 | missing, malformed, or unknown bootstrap token, including a token in the query string          | `boot.error`                                       |
| 4403 | token revoked or expired, or the client IP failed the CIDR check                               | `boot.error`                                       |
| 4404 | the boot id is unknown to this environment                                                     | `boot.error`                                       |
| 4409 | too many pending boots for the token, or a conflicting state transition                        | `boot.error`                                       |
| 4410 | the boot is terminal                                                                           | `boot.declined`, `boot.expired` or `boot.canceled` |
| 4429 | rate limited                                                                                   | `boot.error`                                       |

A source address may create at most 10 boot requests per environment in any 60 second window; the next `boot.hello` from that address gets `boot.error` with 4429 and a close with the same code.

Both sides treat any other close code as a transport failure and reconnect under the backoff policy.

## Error handling

- Worker or Cloudflare unavailable: the client reconnects with exponential backoff and jitter until the pending TTL expires. The application does not start.
- Disconnect while pending: reconnect and resume. The approval is unaffected.
- Disconnect right after approval: reconnect, resume, and receive the same payload while the payload TTL is open.
- Boot private keys lost: the boot is dead. Start a new one and get a new approval.
- Administrator declines: the server sends `boot.declined` and closes 4410. The bootstrap client exits non-zero.
- Token revoked while waiting: every `PENDING` and `APPROVED` boot for that token becomes `CANCELED`, the server sends `boot.canceled` and closes 4410. Already consumed boots are not affected, because the workload already holds the values.
- Environment deleted: pending boots are canceled first, then key material is removed.
- Provenance policy `REQUIRED` with verification unavailable: approval stays disabled, so the boot expires as `PENDING` unless an operator fixes the evidence. Policy `ADVISORY` shows a warning and allows approval.
- Rate limited: the server sends `boot.error` with 4429 and closes. The client backs off before retrying.

The client fails closed. It never starts the application without a fully decrypted and validated secret set.

## What is trusted and what is not

Untrusted, workload supplied, never used for an authorization decision on its own:

- everything in `claims`
- everything in `evidence` before a verifier checks it
- `bootNonce`
- any environment or project identifier a client sends

Trusted:

- the bootstrap token, after hash comparison, revocation, expiry and CIDR checks
- the `signingPublicKey` and `encryptionPublicKey` recorded at `boot.hello`, for the lifetime of that boot only
- verifier output, which is a status of `VERIFIED`, `UNVERIFIED`, `FAILED` or `UNAVAILABLE` plus normalized facts, with no numeric score
- the administrator's approval, bound to the key fingerprints and the evidence digest

`UNAVAILABLE` means no cryptographic attestation exists for this deployment. `FAILED` means evidence was supplied and did not validate. The dashboard must show them differently, and an environment with policy `REQUIRED` must not enable approval for either.

The server displays claims on the approval screen so a human can compare them with verified facts. It must never use a claim to pick the environment, the key version, or the secret set.

## Worked example: one boot with a reconnect

The client holds token `vlt_boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C.<secret>`. Values below are shortened for reading. Real frames carry full length b64u.

1. Client opens `wss://vault.example.com/bootstrap/v1` with `Authorization: Bearer vlt_boot_...`. The Worker verifies the token hash, revocation, expiry and CIDR, resolves `env_01JQ...`, and routes to that environment's Durable Object.

2. Client sends:

```json
{
  "type": "boot.hello",
  "protocol": 1,
  "bootNonce": "AQgPFh0kKzI5QEdOVQ",
  "signingPublicKey": "AQgPFh0kKzI5QEdOVVxjanF4f4aNlJuiqbC3vsXM09o",
  "encryptionPublicKey": "KDE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tng5-758w",
  "claims": {
    "git": { "repository": "github.com/acme/foo", "commit": "3a6d..." },
    "provider": { "name": "zeabur", "deploymentId": "dep-1234" }
  },
  "evidence": []
}
```

3. Server creates the boot in `PENDING` and replies:

```json
{
  "type": "boot.pending",
  "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "expiresAt": "2026-09-05T10:30:00.000Z"
}
```

The Durable Object hibernates. The connection drops 40 seconds later while an administrator is still reading the approval screen.

4. Client reconnects with the same token and sends:

```json
{ "type": "boot.resume", "protocol": 1, "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C" }
```

5. Server replies:

```json
{
  "type": "boot.challenge",
  "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "challenge": "Vh0kKzI5QEdOVVxjanF4f4aNlJuiqbC3vsXM09o"
}
```

6. Client signs the UTF-8 bytes of:

```text
vault-resume:v1
boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C
Vh0kKzI5QEdOVVxjanF4f4aNlJuiqbC3vsXM09o
```

and sends:

```json
{
  "type": "boot.challenge-response",
  "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "signature": "5Qn..."
}
```

7. Server verifies the signature against the key from step 2 and replies:

```json
{
  "type": "boot.resumed",
  "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "status": "PENDING",
  "expiresAt": "2026-09-05T10:30:00.000Z"
}
```

8. The administrator approves. The state becomes `APPROVED`, the server builds the envelope against the client's X25519 key, and sends:

```json
{
  "type": "boot.approved",
  "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "projectId": "proj_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "environmentId": "env_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
  "environmentKeyVersion": 1,
  "payloadExpiresAt": "2026-09-05T10:12:30.000Z",
  "keyEnvelope": {
    "serverPublicKey": "WmFob3Z9hIuSmaCnrrW8w8rR2N_m7fT7Ago",
    "salt": "goeQl56lrLO6wcjP1t3k6_IBCA8WHSQrMjlAR05V",
    "nonce": "AwoRGB8mLTQ7Qkk",
    "ciphertext": "yM_W3eTr8vkAB..."
  },
  "secrets": [
    {
      "id": "sec_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
      "name": "DATABASE_URL",
      "version": 3,
      "envKeyVersion": 1,
      "nonce": "PENKUVhfZm10ew",
      "ciphertext": "CxIZIC..."
    }
  ]
}
```

The server records `deliver`, moving the boot to `DELIVERED`, and stores the SHA-256 of the exact frame bytes.

9. Client derives the wrap key, decrypts the environment key, decrypts every secret, then hashes the received frame bytes and sends:

```json
{ "type": "boot.received", "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C", "payloadDigest": "9f2c..." }
```

10. Digests match. The server records `consume`, writes the audit event, deletes the stored payload, sends:

```json
{ "type": "boot.consumed", "bootId": "boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C" }
```

and closes with 1000. The client execs the application with the secrets in its environment.

Had the connection dropped between steps 8 and 9, the client would repeat steps 4 to 7, get `boot.resumed` with `status: "DELIVERED"`, and receive the identical `boot.approved` frame again under the `redeliver` event, with the same digest.
