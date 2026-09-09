# Threat model

## What the vault protects

The vault stores environment secrets for container and VPS deployments, primarily on Zeabur. It protects those secrets against compromise of the deployment platform's environment-variable storage, Docker image storage, container registries, D1 database exports, historical bootstrap credentials, and accidental `.env` leakage.

The vault does not protect secrets from an attacker who already has arbitrary code execution or root access inside an approved running workload after the workload has decrypted its environment. Once a container has its plaintext, that plaintext is the container's to lose. See "out of scope" below.

## Against whom

The design assumes an attacker who can obtain one or more of the following, alone or in combination: a full export of the D1 vault database, a copy of the Docker image or OCI artifact, a dump of Zeabur's environment-variable storage for the deployment, a stolen or leaked bootstrap token, network position to observe or replay bootstrap WebSocket traffic, or the ability to race a legitimate boot request. It also assumes an attacker who compromises a dashboard admin account or a passkey device, since human approval is the control that gates every environment release.

## Assets

| Asset                               | Where it lives                                  | Why it matters                                                                                                                        |
| ----------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Master key, `VAULT_MASTER_KEY_V<n>` | Cloudflare Worker secret                        | Wraps every project key. Losing it to an attacker unwraps everything below it. Losing it entirely makes all ciphertext unrecoverable. |
| Project keys                        | D1, wrapped under the master key                | Wrap every environment key for a project.                                                                                             |
| Environment DEKs                    | D1, wrapped under the project key               | Encrypt every secret value in an environment.                                                                                         |
| Secret ciphertext                   | D1 `secrets.ciphertext`                         | The encrypted values themselves. Useless without the environment DEK.                                                                 |
| Bootstrap tokens                    | D1 `bootstrap_tokens.token_hash`                | Let a workload open a boot request. Do not authorize release on their own.                                                            |
| Boot private keys                   | Held only in the bootstrap process memory       | An Ed25519 signing key and an X25519 encryption key, generated fresh per boot. Neither ever leaves the process.                       |
| Admin sessions                      | Better Auth session store, separate D1 database | Let a human view the dashboard and, after step-up, approve boots.                                                                     |
| Approval records                    | D1 `boot_requests`, Durable Object SQLite       | Bind one approval to one boot identity, one admin, and one evidence snapshot.                                                         |

## Trust boundaries

| Component                       | What it holds                                                                   | What it trusts                                                                                       | What it must never trust                                                                                                                                       |
| ------------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bootstrap client, written in Go | Ephemeral Ed25519 and X25519 private keys, decrypted environment after approval | Its own key generation, TLS server authentication, and authenticated decryption of the boot envelope | Its own claims as proof of anything; the server does not trust them either                                                                                     |
| Outer Worker                    | Bootstrap token verification, D1 access, master key unwrap                      | Cloudflare's `CF-Connecting-IP` header, the WebSocket `Authorization` header at upgrade time         | Any client-supplied forwarding header, the `claims` object in `boot.hello`, query-string tokens                                                                |
| EnvironmentSessionDO            | Authoritative boot state machine, live socket association                       | Its own SQLite storage, a valid Ed25519 signature on resume                                          | A cached in-memory value that did not survive hibernation, a D1 row that disagrees with its own state                                                          |
| D1 vault database               | Wrapped keys, ciphertext, token hashes, audit log                               | The Worker to write only encrypted or hashed values                                                  | Its own contents as sufficient to decrypt anything; D1 never holds the master key                                                                              |
| Better Auth / dashboard         | Admin sessions, passkey credentials                                             | A valid WebAuthn assertion, a session cookie that is `Secure`, `HttpOnly`, and within its TTL        | A session alone for a sensitive action; approval, rotation, token creation, environment deletion, and provenance changes require recent step-up authentication |
| Provenance verifiers            | Evidence supplied with a boot request                                           | A signature that verifies against a fingerprint in `trusted_signers`                                 | The `claims` object, the verifier's own absence of evidence, which must report `UNAVAILABLE`, not `VERIFIED`                                                   |

## Trusted and untrusted inputs

| Input                                                                                       | Classification                                                                                                    | Why                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `claims` in `boot.hello`: git repository, commit, OCI repository, digest, provider metadata | Untrusted                                                                                                         | The spec states everything inside `claims` is explicitly untrusted workload input. Stored as `claimed_*` columns in `boot_requests` so code never mistakes them for verified facts.                                 |
| `evidence` in `boot.hello`                                                                  | Untrusted until verified                                                                                          | A verifier must check the signature against a trusted signer before any fact derived from it is treated as verified.                                                                                                |
| `CF-Connecting-IP`                                                                          | Trusted                                                                                                           | Cloudflare sets this at its edge from the actual client connection. Any other forwarding header a client can set is untrusted and must not be used for CIDR checks.                                                 |
| `Authorization: Bearer <token>` header at WebSocket upgrade                                 | Trusted as a credential, not as an identity claim                                                                 | It proves possession of a bootstrap-token secret. It does not prove which commit or image is running. A token in the query string is rejected outright with close code 4401.                                        |
| D1 rows                                                                                     | Trusted for what the Worker itself wrote as ciphertext or hash, untrusted as a source of live authorization state | D1 is a catalog and an index. The Durable Object is authoritative for whether a boot may be approved or resumed.                                                                                                    |
| Durable Object state                                                                        | Trusted                                                                                                           | It is the single authoritative source for boot status. A stale D1 row that disagrees with the DO must never be used to authorize delivery.                                                                          |
| Dashboard session cookie                                                                    | Trusted for identity, not sufficient alone for sensitive actions                                                  | A valid session proves who is logged in. Approve, rotate, create token, delete environment, and change provenance requirement all additionally require step-up passkey authentication within the last five minutes. |
| WebAuthn assertion                                                                          | Trusted                                                                                                           | It is the basis for both login and step-up authentication.                                                                                                                                                          |

## Attacker scenarios

### Stolen bootstrap token

Attacker has: a valid bootstrap token for one environment, read from a leaked Zeabur environment dump or a `.env` file.

What they can do: open a WebSocket to `/bootstrap/v1`, authenticate, and create a pending boot request with their own ephemeral keys and their own claims.

What stops them: the boot request sits in `PENDING` until an administrator approves it. The dashboard shows the attacker's own encryption and signing key fingerprints, not the legitimate workload's. An administrator who checks the approval screen against the deployment they expect declines or ignores the request. If IP restrictions are configured on the token, the attacker must also originate from an allowed CIDR.

Residual risk: an administrator who approves a boot without checking source IP, claimed repository, or provenance status hands the attacker the environment DEK and every secret in that environment. This is a human-process risk, not a cryptographic one, and it is why the approval screen must show source IP, claimed workload, and provenance status prominently.

### Attacker copies a legitimate boot ID and tries to reconnect

Attacker has: a boot ID observed on the wire or leaked from logs.

What they can do: send `boot.resume` with that boot ID.

What stops them: the server issues a random challenge and requires an Ed25519 signature from the private signing key generated by the original bootstrap process. The attacker does not have that private key, since it never leaves the process that created it.

Residual risk: none beyond the private key's own secrecy. If the original process's memory is itself compromised, the attacker already has everything the legitimate boot has.

### Attacker copies an encrypted `boot.approved` payload

Attacker has: a full copy of the `boot.approved` frame, including `keyEnvelope` and encrypted secret records.

What they can do: replay the frame to any server they can reach.

What stops them: the envelope is wrapped to the specific client X25519 public key from that boot. X25519 unwrap by any other private key fails. Without the matching private key, the ciphertext is unusable.

Residual risk: none. This is the direct purpose of per-boot ephemeral encryption keys.

### Full D1 export

Attacker has: every row from the vault D1 database, including wrapped project keys, wrapped environment keys, secret ciphertext, token hashes, and audit records.

What they can do: read metadata, token IDs, audit history, and ciphertext.

What stops them: the master key is never stored in D1. It lives only as a Cloudflare Worker secret. Without it, wrapped project keys cannot be unwrapped, so nothing below them can be decrypted either.

Residual risk: metadata exposure. An attacker with the D1 export learns project names, environment slugs, secret names, claimed repositories and commits, and the full audit trail. None of that is plaintext secret material, but it can inform a more targeted social-engineering attempt against an administrator.

### Docker image or Zeabur environment dump

Attacker has: the built container image, or the plaintext of `VAULT_ENDPOINT` and `VAULT_BOOTSTRAP_TOKEN` from a Zeabur dashboard leak.

What they can do: extract the bootstrap token and attempt the stolen-token scenario above. The image itself contains no plaintext environment values and no long-term decryption keys, since the bootstrapper only ever holds ephemeral, per-boot key material generated at startup.

What stops them: the same controls as the stolen-token scenario. Human approval is still required, and the environment DEK is still delivered only to a specific ephemeral encryption key the attacker does not hold.

Residual risk: same as stolen bootstrap token.

### Flood of boot requests from a stolen token

See spec section 37. Attacker has: a valid bootstrap token.

What they can do: open many WebSocket connections and create many pending boot requests in quick succession.

What stops them: a per-token limit on concurrent pending boots, default three, and a per-source-address threshold on boot request creation. These are abuse controls, not authorization controls. They reduce dashboard noise and make the flood visible as an anomaly, but they never substitute for the Durable Object's own state machine.

Residual risk: rate limiting alone does not prevent an attacker from eventually getting one request in front of an administrator. The dashboard must collapse repeated requests from the same token and mark the activity as unusual so an administrator does not approve one out of habit.

### Attacker races a legitimate boot

Attacker has: knowledge of an approved commit or digest, and the ability to submit a competing boot request claiming the same workload identity.

What they can do: submit `boot.hello` with matching claims before or alongside the legitimate workload's request.

What stops them: approval binds to a specific ephemeral boot public key, not to a commit or digest. The legitimate boot and the attacker's boot are different boot IDs with different key fingerprints. An administrator approving the wrong one is a human error, not a protocol gap, which is why the approval screen shows key fingerprints rather than only claimed source information.

Residual risk: an administrator who approves by glancing at the claimed commit alone, without checking that only one boot request is pending, can approve the attacker's boot instead of the legitimate one.

### Two simultaneous approval operations

Attacker has: no special access. This scenario covers concurrency correctness, since a race here would let a second approval or a decline slip past the first winning transition.

What they can do: nothing beyond triggering ordinary concurrent admin actions.

What stops them: the Durable Object serializes state transitions. Exactly one of two simultaneous approve or decline operations on the same boot wins, and the other receives a conflict.

Residual risk: none, if the state machine is implemented correctly. This is exactly why phase 11 requires explicit concurrent-approval tests.

## Out of scope

An attacker who already holds arbitrary code execution or root access inside an approved running workload, after that workload has received and decrypted its environment, is out of scope. That attacker already has the plaintext secrets the workload was authorized to receive. The vault's job ends at delivering an environment to the boot identity a human approved. What that workload does with its own memory afterward is a workload security problem, not a vault problem.

## Known implementation limitations

The [2026-09-09 audit](audit-2026-09-09.md) records two unresolved concurrency issues. Initial-owner creation does not atomically claim setup, so parallel valid-token requests can create more than one owner. Environment rotation can overwrite a concurrent secret update or miss a newly created secret; project rotation also needs coordination with environment creation and rotation. These are limits of the current implementation, not guarantees supplied by encryption or the boot Durable Object.

Setup and passkey registration do not establish recent step-up authentication. Only a session created after successful passkey authentication receives that timestamp. See [key rotation](key-rotation.md) for operational precautions while the rotation races remain open.
