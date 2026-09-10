# Keevault V1 product specification

## Status of this specification

This document describes intended V1 behavior. It is not evidence that every
feature or launch criterion is complete. The [engineering brief](./engineering-brief.md)
tracks implementation, and the [latest audit](./audit-2026-09-09.md) records fixes
and open findings.

As of 2026-09-10, client configuration and the GitHub release publication workflow are
implemented. Additional administrator invitations are not implemented. First-owner
creation is not atomic, and key rotation can race secret writes. Passkey step-up
is granted only after authentication, not during setup. The approval credential
field currently stores `session` rather than an individual WebAuthn credential ID.
Master-key rewrap tooling and repository/digest policy allow lists are not implemented.
Live Zeabur and browser passkey validation remain outstanding.

The exact wire formats and cryptographic encodings are defined in
[the protocol](../protocol/websocket-v1.md) and the engineering brief. Examples
below that describe future features do not extend that wire contract.

## 1. Objective

Build a Cloudflare-hosted secret vault intended primarily for container/VPS deployments such as Zeabur.

The vault protects environment secrets against compromise of:

- deployment-platform environment-variable storage;
- Docker image storage;
- container registries;
- D1 database exports;
- historical bootstrap credentials;
- accidental `.env` leakage.

The vault does **not** attempt to protect secrets from an attacker who already has arbitrary code execution/root access inside an approved running workload after the secrets have been released.

The V1 authorization model is:

```text
bootstrap credential
        │
        │ may request access
        ▼
pending boot request
        │
        │ human approval + provenance review
        ▼
specific ephemeral boot public key
        │
        │ receives environment DEK
        ▼
decrypt environment
        │
        ▼
application starts
```

The approval is bound to one boot identity, not merely to a Git commit.

---

# 2. V1 scope

V1 will support:

| Capability                            | V1                  |
| ------------------------------------- | ------------------- |
| Projects                              | Yes                 |
| Multiple environments/project         | Yes                 |
| Multiple bootstrap tokens/environment | Yes                 |
| Optional CIDR/IP restriction/token    | Yes                 |
| Environment key/value secrets         | Yes                 |
| Encrypted storage in D1               | Yes                 |
| Master key outside D1                 | Yes                 |
| WS-only workload protocol             | Yes                 |
| WS reconnect                          | Yes                 |
| Ephemeral boot encryption key         | Yes                 |
| Ephemeral reconnect/signing key       | Yes                 |
| Human boot approval                   | Yes                 |
| Better Auth dashboard authentication  | Yes                 |
| Passkeys                              | Yes                 |
| Provenance/evidence framework         | Yes                 |
| Generic signed Git→OCI provenance     | Yes                 |
| Zeabur metadata                       | Advisory evidence   |
| GitHub attestation adapter            | Extensible/optional |
| Public secret-management API          | No                  |
| Machine-to-machine automatic approval | No                  |
| Serverless workloads                  | V2                  |
| Runtime hardware attestation          | Future              |

The only public machine-facing protocol in V1 should be the bootstrap WebSocket.

The dashboard will naturally have internal HTTP routes/server actions, but they are not a supported public API.

---

# 3. Primary security properties

V1 should guarantee the following.

### D1 compromise is insufficient

D1 contains:

```text
wrapped project keys
wrapped environment keys
encrypted secret values
hashed bootstrap-token secrets
metadata
audit records
```

It does **not** contain the master wrapping key.

An attacker obtaining only D1 cannot decrypt secrets.

### Zeabur environment-variable compromise is insufficient

A Zeabur deployment may contain:

```text
VAULT_ENDPOINT
VAULT_BOOTSTRAP_TOKEN
```

A stolen bootstrap token allows an attacker to create a boot request only.

It does not authorize environment release.

If IP restrictions are configured, the attacker must additionally originate from an allowed source address.

The administrator must still approve the attacker's ephemeral boot identity.

### Docker image compromise is insufficient

Docker images contain no plaintext environment values and no long-term environment-decryption keys.

### Approval is boot-specific

An approval binds:

```text
environment ID
boot ID
client encryption public key
client signing public key
claims/evidence snapshot
expiration
```

A second boot from the same commit requires another approval.

### Reconnect cannot transfer approval

A reconnect must prove possession of the ephemeral private key belonging to the approved boot.

Possession of the bootstrap token alone cannot attach to another boot request.

---

# 4. Recommended technology stack

## Cloudflare control plane

Use:

```text
Cloudflare Worker
├── request routing
├── dashboard backend
├── Better Auth
├── vault crypto
└── provenance verifier registry

Durable Object
└── one EnvironmentSessionDO per environment
    ├── WebSocket hibernation
    ├── live boot state
    ├── reconnect handling
    └── approval delivery

D1: vault database
├── projects
├── environments
├── secrets
├── bootstrap tokens
├── policies
└── audit/history

D1: auth database
└── Better Auth data

Worker Secrets
├── VAULT_MASTER_KEY_V1
├── BETTER_AUTH_SECRET
└── optional audit/integration credentials
```

Use two D1 databases rather than putting Better Auth and vault state together.

Cloudflare currently supports hibernating WebSockets on Durable Objects, allowing the DO to be evicted while connections remain attached. That is well suited to waiting for human approval.

SQLite-backed Durable Objects are currently available on the Workers Free plan.

## Bootstrap client

Implement the workload bootstrapper in **Go**.

Reasons:

- easy static Linux binaries;
- amd64 + arm64 builds;
- straightforward WebSocket support;
- Ed25519/X25519 support;
- better memory control than Node;
- can use `execve` semantics to replace itself with the actual application.

Configure the application in `keevault.json`:

```json
{
  "vaultUrl": "https://vault.example.com",
  "environmentId": "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "requiredSecrets": ["DATABASE_URL"],
  "command": ["npm", "run", "start"]
}
```

Run `keevault` without command arguments. The application command comes from
this file. In a container:

```dockerfile
COPY keevault.json ./keevault.json
ENTRYPOINT ["/usr/local/bin/keevault"]
```

The example image downloads a precompiled Linux binary from a versioned GitHub release
URL during image build and verifies a pinned checksum. CI produces amd64 and
arm64 artifacts. See [release setup](releases.md).

After approval and server confirmation of consumption, the bootstrapper executes
the target command with the decrypted environment.

The bootstrap process itself disappears.

---

# 5. Repository structure

Implemented monorepo:

```text
keevault/
├── apps/
│   ├── control-plane/
│   │   ├── src/routes/
│   │   ├── src/components/
│   │   ├── src/server/
│   │   └── wrangler.jsonc
│   └── env-client/
│       ├── main.go
│       ├── project_config.go
│       └── internal/
├── packages/
│   ├── crypto/
│   ├── protocol/
│   └── vault-store/
├── migrations/
│   ├── auth/
│   └── vault/
├── protocol/
│   ├── websocket-v1.md
│   ├── messages.schema.json
│   └── test-vectors/
├── crypto/test-vectors/
├── examples/zeabur-node-app/
├── scripts/build-release.sh
├── .github/workflows/release-client.yml
└── docs/
```

Protocol test vectors should be shared between the TypeScript and Go implementations so cryptographic compatibility is continuously tested.

---

# 6. Domain model

```text
Project
│
├── project key
│
├── Environment: production
│   ├── environment key
│   ├── secrets
│   ├── token A
│   ├── token B
│   ├── token C
│   └── provenance policy
│
└── Environment: staging
    ├── separate environment key
    ├── separate secrets
    └── separate tokens
```

The token relationship is:

```text
Environment 1 ──────── * BootstrapToken
```

Each token belongs to **exactly one environment**.

The client cannot choose an environment after authentication.

The token determines it.

---

# 7. Cryptographic hierarchy

Use:

```text
MASTER KEK
   │
   │ wraps
   ▼
PROJECT KEK
   │
   │ wraps
   ▼
ENVIRONMENT DEK
   │
   │ encrypts
   ▼
SECRET VALUES
```

## Master key

Generate 256 random bits.

Store as a Cloudflare Worker Secret:

```text
VAULT_MASTER_KEY_V1
```

Cloudflare Worker Secrets are intended for encrypted sensitive bindings, unlike ordinary Worker `vars`, which are not encrypted configuration.

Never derive:

```text
projectKey = hash(master || projectId)
```

Instead generate every project/environment key independently using a CSPRNG.

## Project key

```text
32 random bytes
```

Store:

```text
AES-256-GCM(
    master,
    projectKey,
    AAD = project identity + key version
)
```

## Environment key

Generate another random 32-byte key.

Store:

```text
AES-256-GCM(
    projectKey,
    environmentKey,
    AAD = project ID + environment ID + versions
)
```

## Secret values

Encrypt each value independently:

```text
AES-256-GCM(
    environmentKey,
    secret plaintext,
    fresh 96-bit nonce,
    AAD
)
```

Suggested canonical AAD:

```text
vault:secret:v1
project=<project-id>
environment=<environment-id>
secret=<secret-id>
version=<secret-version>
```

Every AES-GCM encryption operation gets a fresh random 96-bit nonce.

Never reuse a key/nonce pair.

Cloudflare Workers currently expose AES-GCM, HKDF, Ed25519 and X25519 through Web Crypto.

---

# 8. Important release optimization

During ordinary boot, **the Worker should not decrypt every secret value**.

D1 already contains:

```text
DATABASE_URL → AES-GCM ciphertext
API_KEY      → AES-GCM ciphertext
JWT_SECRET   → AES-GCM ciphertext
```

The Worker only needs to unwrap:

```text
MASTER
 → PROJECT KEY
   → ENVIRONMENT KEY
```

Then it encrypts the environment key to the boot public key.

The boot receives:

```text
wrapped environment key
+
already encrypted secret records
```

The container decrypts the environment key and then decrypts the secret records itself.

This reduces plaintext exposure inside the Cloudflare runtime.

---

# 9. Boot cryptographic identity

Every process startup creates two ephemeral keypairs.

## Signing pair

```text
Ed25519
```

Purpose:

```text
reconnect proof-of-possession
```

## Encryption pair

```text
X25519
```

Purpose:

```text
environment-key delivery
```

Do not reuse one keypair for both operations.

Neither private key ever leaves the boot process.

If the process dies, those keys disappear and the pending request becomes unusable.

---

# 10. Environment-key delivery

When the administrator approves a boot:

```text
client X25519 public key
              +
server ephemeral X25519 private key
              ↓
         shared secret
              ↓
         HKDF-SHA256
              ↓
     256-bit wrapping key
              ↓
          AES-GCM
              ↓
      environment DEK
```

Use HKDF context containing:

```text
protocol version
boot ID
environment ID
environment-key version
client public key fingerprint
server public key fingerprint
```

Response contains:

```json
{
  "serverEncryptionPublicKey": "...",
  "hkdfSalt": "...",
  "nonce": "...",
  "wrappedEnvironmentKey": "...",
  "environmentKeyVersion": 4,
  "secrets": [...]
}
```

The response is cryptographically usable only by the holder of that boot's X25519 private key.

---

# 11. Bootstrap-token format

Generate at least 256 bits of random secret material.

Suggested representation:

```text
vlt_boot_<token-id>.<random-secret>
```

For example:

```text
vlt_boot_01K4ABC....pxJQ...
```

D1 stores:

```text
token ID
SHA-256(random-secret)
```

not the plaintext token.

Because the token secret has full cryptographic entropy, SHA-256 is appropriate; password-specific slow hashing is unnecessary.

The token ID allows a direct indexed lookup without scanning token hashes.

Compare hashes in constant time.

---

# 12. Bootstrap-token policy

Each token supports:

```text
environment_id
label
allowed CIDRs[]
expires_at
revoked_at
last_seen_at
```

Example:

```text
production

Token: zeabur-prod-1
CIDR: 203.0.113.44/32

Token: backup-vps
CIDR: 198.51.100.0/24
```

Source-IP checks should use Cloudflare's trusted incoming-client metadata, specifically `CF-Connecting-IP`, rather than accepting arbitrary client-provided forwarding headers. Cloudflare documents that header as containing the client IP connecting to its edge.

If no CIDR policy exists, skip the IP check.

IP restriction is an additional constraint, not a replacement for authentication.

---

# 13. WebSocket endpoint

The only machine protocol for V1:

```text
wss://vault.example.com/bootstrap/v1
```

Use:

```text
Authorization: Bearer <bootstrap-token>
```

The Go WS client can provide the header during the HTTP Upgrade request.

Never put the credential into:

```text
?token=...
```

because URLs are much more likely to appear in logs.

The outer Worker performs:

```text
token parse
↓
D1 token lookup
↓
hash verification
↓
expiration/revocation check
↓
CIDR check
↓
resolve environment ID
↓
route to EnvironmentSessionDO(environment ID)
```

The client never selects the environment.

---

# 14. Durable Object layout

Create one DO instance per environment:

```text
EnvironmentSessionDO(environment-id)
```

Example:

```text
Project Foo / production
        ↓
EnvironmentSessionDO("env_abc")
```

It coordinates all pending boots for that environment.

Use the Hibernation WebSocket API, not the normal WebSocket API, because regular connected sockets keep a DO active while hibernating sockets permit eviction during idle approval waits.

Persist authoritative boot state in the DO's SQLite storage.

WebSocket attachments should contain only enough information to associate a socket with a boot, such as:

```text
bootId
connectionGeneration
```

Do not depend on normal JavaScript in-memory variables surviving hibernation.

---

# 15. Boot state machine

Use:

```text
CREATING
   │
   ▼
PENDING
   │
   ├──── decline ───────────> DECLINED
   │
   ├──── pending timeout ───> EXPIRED
   │
   └──── approve
            │
            ▼
         APPROVED
            │
            │ payload transmitted
            ▼
         DELIVERED
            │
            │ valid ACK
            ▼
         CONSUMED
```

Additional terminal state:

```text
CANCELED
```

for token revocation/admin cancellation.

The single-use property applies to the **authorization**, not to TCP packets.

An approved payload may be retransmitted to the **same ephemeral boot key** after connection failure.

It may never be transferred to another key.

---

# 16. WebSocket protocol

## Client → server: hello

```json
{
  "type": "boot.hello",
  "protocol": 1,

  "bootNonce": "...",

  "signingPublicKey": "...",
  "encryptionPublicKey": "...",

  "claims": {
    "git": {
      "repository": "github.com/acme/app",
      "commit": "abc123"
    },
    "oci": {
      "repository": "ghcr.io/acme/app",
      "digest": "sha256:..."
    },
    "provider": {
      "name": "zeabur",
      "deploymentId": "..."
    }
  },

  "evidence": [...]
}
```

Everything inside `claims` is explicitly considered **untrusted workload input**.

## Server → client

```json
{
  "type": "boot.pending",
  "bootId": "boot_...",
  "expiresAt": "..."
}
```

At this point the DO may hibernate.

## Approval

After dashboard approval:

```json
{
  "type": "boot.approved",
  "bootId": "...",
  "payloadExpiresAt": "...",

  "keyEnvelope": {
    "serverPublicKey": "...",
    "salt": "...",
    "nonce": "...",
    "ciphertext": "..."
  },

  "secrets": [...]
}
```

## Client acknowledgement

Only after successfully decrypting and validating all records:

```json
{
  "type": "boot.received",
  "bootId": "...",
  "payloadDigest": "..."
}
```

Server:

```text
mark CONSUMED
write audit event
delete transient encrypted delivery object
close WebSocket 1000
```

---

# 17. Reconnect protocol

Connection loss must not cancel an approval.

The client retains:

```text
boot ID
Ed25519 private key
X25519 private key
```

until the boot succeeds or permanently fails.

Reconnect:

```text
WS connection
    │
    │ boot.resume(bootId)
    ▼
server
    │
    │ random challenge
    ▼
client
    │
    │ Ed25519 signature
    ▼
server verifies original signing pubkey
```

Messages:

```json
{
  "type": "boot.resume",
  "bootId": "boot_..."
}
```

Server:

```json
{
  "type": "boot.challenge",
  "challenge": "..."
}
```

Client signs a canonical value containing:

```text
vault-resume:v1
boot ID
challenge
```

and returns:

```json
{
  "type": "boot.challenge-response",
  "signature": "..."
}
```

Only then is the new WebSocket associated with the boot request.

Require the environment bootstrap token to still be valid on reconnect as well.

This gives an administrator an effective kill switch: revoking the bootstrap token can prevent future reconnects.

---

# 18. Timing policy

Recommended initial defaults:

```text
pending approval TTL       30 minutes
approved payload TTL        5 minutes
reconnect backoff           1–15 seconds with jitter
challenge TTL               30 seconds
```

Pending TTL should be configurable per environment.

An approved request that expires without completion becomes:

```text
EXPIRED
```

Never:

```text
PENDING
```

or automatically reusable.

A new boot authorization requires another explicit approval.

---

# 19. D1 vault schema

Use migrations from day one.

## projects

```text
id
slug
name
current_project_key_version
created_at
updated_at
```

## project_keys

```text
project_id
version
master_key_version
wrapped_key
nonce
status
created_at
```

## environments

```text
id
project_id
slug
name

current_env_key_version

provenance_mode
pending_ttl_seconds
approved_ttl_seconds

created_at
updated_at
```

## environment_keys

```text
environment_id
version
project_key_version

wrapped_key
nonce
status

created_at
```

## secrets

```text
id
environment_id

name
ciphertext
nonce

env_key_version
secret_version

created_at
updated_at

UNIQUE(environment_id, name)
```

## bootstrap_tokens

```text
id
environment_id

label
token_hash
allowed_cidrs_json

expires_at
revoked_at
last_seen_at

created_at
```

## provenance_policies

```text
id
environment_id

verifier_type
configuration_json

required
enabled

created_at
updated_at
```

## trusted_signers

```text
id
project_id nullable
environment_id nullable

type
label
public_key
fingerprint

enabled
created_at
```

## boot_requests

D1 contains the dashboard/index/history representation:

```text
id
environment_id
bootstrap_token_id

status
source_ip

signing_public_key
encryption_public_key

claimed_git_repository
claimed_git_commit

claimed_oci_repository
claimed_oci_digest

provenance_summary_json

created_at
approved_at
approved_by
consumed_at
expired_at
```

Use `claimed_*` names deliberately so code never accidentally interprets these values as verified facts.

## audit_events

```text
id
timestamp

actor_type
actor_id

action

project_id nullable
environment_id nullable
boot_id nullable

metadata_json
```

Never put decrypted secret values into audit metadata.

---

# 20. D1 versus Durable Object responsibility

Use this division:

```text
D1
=
catalog
configuration
encrypted vault
dashboard index
long-term history

Durable Object
=
live authorization state
socket association
approval serialization
reconnect
delivery state
```

The Environment DO is authoritative for whether a boot can be approved or resumed.

D1 dashboard state is a projection/index.

Therefore:

```text
dashboard says PENDING
but
DO says EXPIRED
```

must result in:

```text
approval rejected
dashboard refreshed
```

Never trust a stale D1 row to authorize delivery.

---

# 21. Dashboard authentication

Use Better Auth with a separate D1 binding.

Better Auth currently supports Cloudflare D1 directly, and its passkey plugin provides WebAuthn/passkey authentication.

Worker Secrets:

```text
BETTER_AUTH_SECRET
VAULT_MASTER_KEY_V1
```

must be completely independent random values.

Do not derive one from the other.

## V1 account model

Keep V1 single-tenant.

Roles:

```text
owner
admin
viewer
```

Permissions:

| Operation               | Owner | Admin | Viewer |
| ----------------------- | ----: | ----: | -----: |
| View metadata           |     ✓ |     ✓ |      ✓ |
| View pending boots      |     ✓ |     ✓ |      ✓ |
| Approve/decline         |     ✓ |     ✓ |        |
| Edit secrets            |     ✓ |     ✓ |        |
| Manage bootstrap tokens |     ✓ |     ✓ |        |
| Configure provenance    |     ✓ |     ✓ |        |
| Rotate project/env keys |     ✓ |       |        |
| Manage administrators   |     ✓ |       |        |

Public signup should be disabled.

Provide a one-time first-owner setup ceremony and remove/disable it immediately after initialization.

The current implementation closes setup after a user exists, but concurrent
valid-token requests can create multiple owners. Invitations are not implemented;
setup cannot be repeated to add users after initialization.

---

# 22. Approval authentication

Signing into the dashboard with a passkey is not sufficient by itself for a highly sensitive approval session that might remain open for hours.

Require **recent passkey authentication** before:

```text
Approve boot
Rotate keys
Create token
Delete environment
Change provenance requirement
```

Initial policy:

```text
step-up authentication valid for 5 minutes
```

An approval records:

```text
admin user ID
credential used
approval time
boot ID
boot public-key fingerprints
reviewed evidence digest
```

A later hardening version can bind a WebAuthn challenge directly to a digest of the approval statement.

---

# 23. Dashboard secret UX

Do not build a normal password-manager-style “reveal secret” interface.

Recommended V1 behavior:

```text
SECRET_NAME        *************     Updated ...
DATABASE_URL       *************     ...
OPENAI_API_KEY     *************     ...
```

Operations:

```text
create
replace
delete
```

Avoid:

```text
reveal existing plaintext
```

The Worker technically has the ability to decrypt secrets, but keeping reveal out of V1 substantially reduces accidental disclosure paths.

Support:

```text
Import .env
```

The browser sends plaintext over HTTPS.

The Worker parses it, encrypts individual values, and stores ciphertext.

Never return those values afterward.

---

# 24. Provenance architecture

Do **not** model GitHub as the architecture.

Model:

```text
Claims
   ↓
Evidence
   ↓
Verifier adapters
   ↓
Normalized verified facts
   ↓
Environment policy
   ↓
Human decision
```

## Claims

Claims are workload-provided:

```text
repository
commit
OCI repository
OCI digest
deployment ID
provider
```

They are untrusted.

## Evidence

Evidence can come from:

```text
signed build manifest
OCI registry
GitHub Artifact Attestation
Sigstore/in-toto
CI signing key
Zeabur metadata
future workload identity
future hardware attestation
```

## Normalized verification result

Every verifier returns something like:

```json
{
  "verifier": "signed-build-manifest-v1",
  "status": "verified",

  "subject": {
    "type": "oci",
    "repository": "ghcr.io/acme/foo",
    "digest": "sha256:..."
  },

  "source": {
    "repository": "github.com/acme/foo",
    "commit": "abc123"
  },

  "builder": {
    "identity": "ci-signing-key-01"
  },

  "evidenceDigest": "...",
  "warnings": []
}
```

No numeric “trust score”.

Return individual facts and warnings.

---

# 25. Verifier interface

Conceptually:

```ts
interface ProvenanceVerifier {
  id: string;

  verify(input: {
    environment: Environment;
    claims: WorkloadClaims;
    evidence: Evidence[];
  }): Promise<VerificationResult>;
}
```

Status:

```text
VERIFIED
UNVERIFIED
FAILED
UNAVAILABLE
```

These have different meanings.

For example:

```text
UNAVAILABLE
=
this provider has no cryptographic attestation

FAILED
=
cryptographic evidence was supplied but did not validate
```

The UI must distinguish them.

---

# 26. Environment provenance policy

Each environment selects:

```text
OFF
ADVISORY
REQUIRED
```

### OFF

No provenance requirement.

Claims are displayed but don't block approval.

### ADVISORY

Run all configured verifiers.

Display results prominently.

Administrator may approve despite missing/unverified provenance.

Best default for native Zeabur builds.

### REQUIRED

At least the configured required verification conditions must succeed before the Approve button is enabled.

Example:

```text
repository = github.com/acme/foo
OCI repository = ghcr.io/acme/foo
signed-build-manifest-v1 = VERIFIED
```

---

# 27. Initial V1 provenance implementation

Implement the abstraction first and ship two verifier classes.

## A. Claims-only verifier

Supports every deployment.

Output:

```text
UNVERIFIED
```

It merely normalizes information supplied by the workload.

This allows Zeabur native builds to work immediately.

## B. Generic signed-build-manifest-v1

This should be the first cryptographically useful V1 verifier.

Define your own simple canonical manifest:

```json
{
  "version": 1,

  "source": {
    "repository": "https://github.com/acme/foo",
    "commit": "abc123..."
  },

  "artifact": {
    "type": "oci",
    "repository": "ghcr.io/acme/foo",
    "digest": "sha256:..."
  },

  "builder": "acme-ci",

  "issuedAt": "..."
}
```

CI signs the canonical representation using Ed25519.

The vault has the CI public key configured as a trusted signer.

This gives you a provider-neutral cryptographic statement:

```text
trusted CI says:

commit ABC
      ↓
produced
      ↓
OCI digest XYZ
```

Any CI capable of signing a blob can produce it.

It doesn't require GitHub.

---

# 28. Standard provenance adapters after V1 core

The verifier interface should subsequently support:

```text
github-artifact-attestation
sigstore-cosign
in-toto/SLSA
provider-specific deployment assertions
```

GitHub Artifact Attestations currently include signed provenance information such as repository, workflow and commit SHA, and support container images.

Cosign supports signed in-toto attestations independently of GitHub, so this is the more general future interoperability path.

Do not make either representation part of the core boot protocol.

---

# 29. Zeabur integration

Zeabur currently exposes Git metadata during its build phase, including commit SHA, repository owner/name and branch. Those values should be considered metadata rather than independent cryptographic attestation.

Support two modes.

## Native Zeabur Git build

```text
Git
 ↓
Zeabur build infrastructure
 ↓
Zeabur runtime
```

Bootstrap claims may contain:

```text
Git repository
commit
provider deployment metadata
```

Dashboard displays:

```text
Bootstrap authentication    ✓
Source IP                   ✓

Git commit claimed          abc123
Git repository claimed      acme/foo

Cryptographic provenance    unavailable
Runtime image identity      unverified

Policy: ADVISORY
```

Human approval remains available.

## Prebuilt OCI deployment

Preferred security path:

```text
Git
 ↓
your CI
 ├── builds OCI image
 ├── obtains immutable digest
 └── signs provenance
 ↓
registry
 ↓
Zeabur pulls prebuilt image
```

Zeabur supports prebuilt Docker-image deployments.

Then the dashboard can show verified Git→OCI provenance independently of Zeabur.

Still label runtime identity accurately:

```text
Build provenance           VERIFIED
Runtime image identity     CLAIMED / not remotely attested
```

Do not imply provenance proves what is currently executing.

---

# 30. Bootstrap client behavior

The Go bootstrapper performs:

```text
1. Read configuration and validate launch settings.
2. Generate ephemeral keypairs.
3. Open a WebSocket authenticated by the bootstrap token.
4. Submit boot claims/evidence.
5. Wait for approval, reconnecting with resume proof if necessary.
6. Receive the environment-key envelope and encrypted secrets.
7. Check the configured environment ID, when provided.
8. Derive the wrapping key and decrypt the environment DEK.
9. Decrypt all secret values and check required secret names.
10. ACK the exact payload digest.
11. Wait for boot.consumed from the server.
12. Resolve the command and build its environment.
13. Destroy temporary buffers best-effort.
14. exec the target process.
```

Implemented configuration:

```json
{
  "vaultUrl": "https://vault.example.com",
  "environmentId": "env_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "requiredSecrets": ["DATABASE_URL"],
  "command": ["node", "server.js"]
}
```

The client reads `keevault.json` from the working directory, or an explicit
`--config` / `KEEVAULT_CONFIG` path. Keep `VAULT_BOOTSTRAP_TOKEN` outside this
file. The token selects the environment; `environmentId` pins the expected
approval and `requiredSecrets` checks presence without filtering delivered keys.
`VAULT_URL` can override the file URL. Flags override the corresponding settings,
and command arguments replace the configured command. See
[client configuration](../apps/env-client/README.md) for exact precedence.

Optional non-secret metadata:

```text
VAULT_GIT_REPOSITORY
VAULT_GIT_COMMIT
VAULT_OCI_REPOSITORY
VAULT_OCI_DIGEST
VAULT_DEPLOYMENT_ID
```

These are claims only.

---

# 31. Environment injection

Do not populate a Node bootstrapper's `process.env`.

The Go process should build the target application's environment and then replace itself using an exec-style launch.

Conceptually:

```text
keevault
    │
    │ decrypt
    ▼
environment map
    │
    │ execve()
    ▼
application
```

For Node applications using `dotenv`, this generally works naturally because values already present in the environment can be consumed through `process.env`.

The application still possesses the plaintext at runtime. That is unavoidable.

V1 should not write `.env` plaintext to persistent disk.

Optional future fallback:

```text
tmpfs /run/secrets
```

for applications requiring file-based secrets.

---

# 32. Multiple applications in one container

If the container runs:

```text
supervisor
├── app A
├── app B
└── worker C
```

then:

```text
keevault → exec supervisor
```

and the supervisor's children inherit the environment.

V1 treats the container environment as one authorization boundary.

Per-process secret subsets can be a later feature:

```text
secret groups/scopes
```

Do not complicate V1 with it unless immediately necessary.

---

# 33. Zeabur readiness consideration

Human approval means the service may remain in startup for a meaningful period.

Zeabur performs readiness/health checks and retains the previous healthy deployment until the replacement is ready for ordinary rolling deployments.

Test explicitly:

```text
new deployment waiting 1 minute
5 minutes
15 minutes
30 minutes
```

and determine Zeabur's practical deployment timeout.

Do **not** falsely report application readiness merely to keep the deployment alive.

Desired lifecycle:

```text
old version continues serving
          │
new version waits for vault approval
          │
admin approves
          │
application starts
          │
health check succeeds
          │
traffic switches
```

Services using volumes may behave differently because Zeabur documents a recreate strategy for those deployments.

This should be an explicit integration test before calling V1 production-ready.

---

# 34. Approval screen

The approval screen is the most security-sensitive UI.

Display:

```text
PRODUCTION
Project: my-app

BOOT REQUEST
Token              zeabur-prod-01
Source IP           203.0.113.42
CIDR policy         ✓

CLAIMED WORKLOAD
Repository          github.com/acme/foo
Commit              abc123
OCI                  ghcr.io/acme/foo
Digest               sha256:def

VERIFIED EVIDENCE
Signed manifest      ✓ VERIFIED
Repository match     ✓
Commit match         ✓
OCI digest match     ✓
Signer               acme-ci-prod

RUNTIME
Running OCI identity ? not independently attested

BOOT IDENTITY
Signing key          52:32:...
Encryption key       92:CA:...

Requested            37 seconds ago

[Decline]                   [Approve]
```

Failed cryptographic evidence should be highly visible:

```text
✗ SIGNATURE VERIFICATION FAILED
```

not a subtle warning.

---

# 35. Audit events

Audit at least:

```text
project.created
project.deleted

environment.created
environment.deleted

secret.created
secret.updated
secret.deleted

bootstrap-token.created
bootstrap-token.revoked
bootstrap-token.cidrs-changed

provenance-policy.changed
trusted-signer.added
trusted-signer.revoked

boot.requested
boot.reconnected
boot.approved
boot.declined
boot.expired
boot.delivered
boot.consumed

project-key.rotated
environment-key.rotated
master-key-rewrapped
```

Never log:

```text
bootstrap secret
environment DEK
project key
master key
secret plaintext
key-encryption shared secret
```

Store fingerprints/hashes instead.

---

# 36. Logging rules

Build a redaction layer before implementing business logic.

Explicitly blacklist:

```text
Authorization
Cookie
Set-Cookie
secret values
plaintext imported dotenv
key material
WebAuthn responses where unnecessary
```

Worker exceptions must never serialize complete request bodies for bootstrap/admin secret routes.

Client logs should use:

```text
boot request created: boot_123
waiting for approval
approval received
environment decrypted
starting application
```

never:

```text
received DATABASE_URL=...
```

---

# 37. Rate limiting and abuse handling

Per bootstrap token:

```text
maximum concurrent pending boots
```

Default:

```text
3
```

Per source address:

```text
boot request creation threshold
```

The exact rate mechanism is abuse protection only.

It must never replace the Durable Object state machine for authorization.

If an attacker steals a bootstrap token and floods requests, the dashboard should collapse them under the token/environment and clearly indicate unusual activity.

---

# 38. Revocation semantics

Revoking a bootstrap token should:

```text
prevent new WebSockets
prevent reconnect
cancel all PENDING requests from that token
```

Decision for APPROVED but not delivered:

```text
cancel them too
```

Safest V1 behavior is fail closed.

Already CONSUMED sessions cannot be retroactively revoked because the workload already possesses its environment values.

---

# 39. Key rotation

These procedures describe the intended result. The current implementation does
not serialize the snapshot and commit against concurrent secret writes or key
creation. Follow the coordination requirements in [key rotation](key-rotation.md)
and the unresolved finding in [the audit](./audit-2026-09-09.md).

## Environment key

Used after suspected environment-key exposure.

Procedure:

```text
unwrap current env key
generate ENV_KEY_vNext
decrypt every environment secret
reencrypt every secret under new key
wrap new environment key
atomically switch current version
retire previous key
```

This is the only rotation requiring secret plaintext to exist transiently in the Worker.

## Project key

No secret re-encryption required:

```text
unwrap environment keys
generate project key vNext
rewrap environment keys
activate
```

## Master key

Support master-key versioning from day one.

Example:

```text
VAULT_MASTER_KEY_V1
VAULT_MASTER_KEY_V2
```

Rotation runbook:

```text
1. Add V2 Worker Secret.
2. Deploy Worker capable of reading V1 + V2.
3. Rewrap every active project key under V2.
4. Confirm no project key references V1.
5. Mark V2 active.
6. Remove V1 in a later deployment.
```

Never perform master rotation as an irreversible one-shot operation.

---

# 40. Error/failure behavior

## Worker/Cloudflare unavailable

Bootstrap reconnects with exponential backoff until pending timeout.

Application does not start.

## WebSocket disconnects while pending

Reconnect and prove boot-key ownership.

## Disconnect immediately after approval

Reconnect and receive the same encrypted payload if still within delivery TTL.

## Private boot key lost

Existing request is unusable.

Create a fresh request requiring new approval.

## Admin declines

Server sends:

```text
boot.declined
```

and closes.

Bootstrap exits non-zero.

## Provenance REQUIRED but verification unavailable

Approval disabled.

## Provenance ADVISORY and unavailable

Warning displayed; approval allowed.

## Token revoked while waiting

Boot becomes canceled.

Connection closes.

## Environment deleted

Pending requests canceled first, then key material removed.

---

# 41. Better Auth hardening

Use:

```text
Secure cookies
HttpOnly
SameSite=Strict where compatible
HTTPS only
strict trusted origins
short administrative sessions
step-up passkey requirement
```

Better Auth's passkey integration is based on WebAuthn/passkey authentication.

Do not enable authentication methods you don't need.

Ideal production dashboard login for V1:

```text
passkey only
```

Keep emergency account recovery as an explicit operator procedure rather than silently falling back to a weak password.

---

# 42. Cloudflare Free-tier viability

V1 should fit easily at small/personal scale.

Current Workers Free limits include 100,000 Worker requests/day, 10 ms CPU per invocation, 128 MB memory, and a 3 MB Worker bundle limit.

D1 Free currently includes:

```text
5 million rows read/day
100,000 rows written/day
5 GB total storage
500 MB/database
```

with up to ten databases/account.

SQLite-backed Durable Objects are also available on Workers Free.

Add CI checks for:

```text
Worker compressed/upload bundle size
D1 migration size
bootstrap binary size
```

because Better Auth + provenance libraries could otherwise push the Worker bundle toward the Free-plan size limit.

Keep heavyweight Sigstore verifier dependencies optional/separate if necessary.

---

# 43. Implementation phases

## Phase 0 — protocol and threat-model freeze

Deliver:

```text
docs/threat-model.md
protocol/websocket-v1.md
crypto envelope specification
state-machine specification
```

Define exact canonical encodings before writing crypto code.

Acceptance criteria:

```text
Every trust boundary documented.
Every claim identified as trusted/untrusted.
Every state transition specified.
No ambiguous "single-use" semantics.
```

---

## Phase 1 — cryptographic core

Implement TypeScript and Go:

```text
AES-GCM secret encryption
master→project wrapping
project→environment wrapping
X25519 agreement
HKDF
boot environment-key wrapping
Ed25519 reconnect signatures
```

Create cross-language test vectors.

Acceptance criterion:

```text
TS creates envelope → Go decrypts.
Go test vector → TS verifies.
Tampered ciphertext/AAD always fails.
```

Do not continue until this is solid.

---

## Phase 2 — D1 vault

Implement:

```text
projects
project keys
environments
environment keys
secrets
tokens
audit schema
migrations
```

Dashboard-independent unit tests for:

```text
create project
create environment
write secret
replace secret
delete secret
token creation/revocation
key rewrapping
```

Verify raw D1 contents contain no plaintext secret material.

---

## Phase 3 — bootstrap authentication

Implement token generation:

```text
vlt_boot_<id>.<secret>
```

Implement:

```text
hash storage
CIDR policy
expiration
revocation
CF-Connecting-IP validation
```

Acceptance criteria:

```text
wrong secret → reject
revoked token → reject
expired token → reject
incorrect IP → reject
valid token → resolves exactly one environment
```

---

## Phase 4 — Environment Durable Object

Implement hibernating WebSockets.

Implement:

```text
PENDING
APPROVED
DELIVERED
CONSUMED
DECLINED
EXPIRED
CANCELED
```

Persist state to DO SQLite.

Acceptance criteria include killing/restarting/hibernating the DO between every possible transition.

---

## Phase 5 — Go bootstrapper

Implement:

```text
WebSocket handshake
hello
pending wait
reconnect
challenge signing
approval decryption
secret decryption
ACK
exec target
```

Support Linux:

```text
amd64
arm64
```

Acceptance criterion:

```text
kill network repeatedly during pending/approved states
and boot must either resume safely or fail closed.
```

---

## Phase 6 — Better Auth dashboard auth

Set up separate `AUTH_DB`.

Implement:

```text
first-owner ceremony
passkey registration
passkey login
admin sessions
roles
step-up authorization
```

Disable public registration after setup.

---

## Phase 7 — core dashboard

Implement pages:

```text
Projects
Project
Environment
Secrets
Bootstrap tokens
Pending boots
Audit log
Settings
```

Implement dotenv import.

Do not implement secret reveal.

---

## Phase 8 — approval workflow

Dashboard pending-boots page reads D1 index.

Approval calls authoritative Environment DO.

DO validates:

```text
still pending
not expired
token still valid
policy still satisfied
approval user authorized
```

Then wrap the env key and notify the workload.

Acceptance test must include two admins attempting to approve/decline the same request simultaneously.

Exactly one state transition wins.

---

## Phase 9 — provenance framework

Implement interfaces:

```text
WorkloadClaims
Evidence
ProvenanceVerifier
VerificationResult
EnvironmentProvenancePolicy
```

Ship:

```text
claims-only
signed-build-manifest-v1
```

Implement trusted signing-key management in dashboard.

---

## Phase 10 — Zeabur integration

Build example Docker image:

```text
keevault
+
sample Node/dotenv app
```

Test:

```text
Zeabur native Git build
prebuilt OCI deployment
static outbound IP if available
WebSocket disconnect/reconnect
long approval delay
redeploy
restart
health checks
```

Document exactly which Zeabur metadata is available and which is merely claimed.

---

## Phase 11 — security testing

Mandatory test classes:

```text
cryptographic mutation tests
authorization tests
state-machine race tests
replay tests
reconnect takeover tests
token leakage simulation
D1 leak simulation
IP-bypass tests
CSRF tests
session fixation tests
WebAuthn/step-up tests
logging redaction tests
provenance spoofing tests
```

Specifically simulate:

```text
attacker has full D1 export
attacker has Docker image
attacker has Zeabur env dump
attacker has bootstrap token
attacker knows approved commit/digest
attacker races legitimate boot
```

Verify none can obtain plaintext secrets without administrator approval to their own ephemeral key.

---

# 44. Required adversarial tests

Before production, these cases must pass.

### Stolen token creates fake request

Expected:

```text
dashboard sees separate boot key
legitimate request unaffected
attacker gets no secret
```

### Attacker copies legitimate boot ID

Expected:

```text
reconnect challenge fails
```

### Attacker copies encrypted approval response

Expected:

```text
X25519 unwrap fails
```

### Attacker changes ciphertext secret name

Expected:

```text
AES-GCM/AAD validation fails
```

### Attacker replaces one environment's ciphertext with another

Expected:

```text
AAD/env identity mismatch
```

### Two simultaneous approval operations

Expected:

```text
one wins
one gets conflict
```

### Approval response lost

Expected:

```text
same boot reconnects
same approved payload can be redelivered
no second human approval necessary
```

### Client crashes after approval

Expected:

```text
ephemeral private key gone
request expires
new boot requires new approval
```

---

# 45. Operational monitoring

Metrics:

```text
pending boots
approval latency
declines
expired boots
reconnect count
invalid token attempts
CIDR failures
provenance failures
D1 failures
DO failures
key rotations
```

Alert-worthy events:

```text
many invalid bootstrap requests
many boot requests from unexpected IPs
multiple simultaneous boots using one token
required provenance suddenly unavailable
repeated failed provenance signatures
admin authentication anomalies
```

Never include secret values in telemetry.

---

# 46. Backup strategy

D1 supports point-in-time recovery/Time Travel, including a Free-plan retention window currently documented as seven days.

Backups contain ciphertext, which is useful.

The critical recovery dependency is the master key.

Therefore maintain a secure offline recovery copy of:

```text
VAULT_MASTER_KEY
```

outside Cloudflare.

For example:

```text
hardware password manager
offline encrypted recovery archive
organizational secrets manager
```

Losing D1 can be restored.

Losing the sole master key means all vault ciphertext is intentionally unrecoverable.

Document this prominently.

---

# 47. Production launch criteria

V1 is production-ready only when all are true:

```text
[ ] no plaintext vault values visible in raw D1
[ ] no plaintext secrets in Worker logs
[ ] no plaintext secrets in Docker image
[ ] bootstrap token cannot retrieve secrets directly
[ ] IP policy tested
[ ] passkey approval tested
[ ] WS hibernation tested
[ ] reconnect proof tested
[ ] network-loss-after-approval tested
[ ] concurrent approval race tested
[ ] token revocation tested
[ ] D1 compromise simulation tested
[ ] Zeabur env-dump simulation tested
[ ] provenance failure states tested
[ ] key rotation runbook tested
[ ] master-key backup verified
[ ] Zeabur long-start behavior validated
```

---

# 48. V2 compatibility boundary

Do not design V2 around “WebSockets on Lambda”.

Instead generalize:

```text
BootAuthorization
```

into:

```text
WorkloadAuthorization
```

V1 workload identity:

```text
human-approved ephemeral boot key
```

V2 can add:

```text
provider-issued OIDC
signed deployment identity
serverless revision identity
confidential-computing attestation
TPM attestation
```

The authorization engine remains:

```text
Workload claims
      +
Evidence/verifiers
      +
Environment policy
      ↓
Authorization subject
      ↓
Environment-key envelope
```

Only the identity adapter changes.

---

# 49. V2 serverless direction

A future serverless provider adapter should ideally prove:

```text
provider identity
project/service
deployment/revision
artifact
```

Provenance separately proves:

```text
Git source
      ↓
trusted build
      ↓
artifact/deployment
```

Keep these distinct:

```text
BUILD PROVENANCE
"What was built?"

RUNTIME IDENTITY
"Who is asking right now?"
```

Some providers will support both strongly.

Some will only provide unsigned environment metadata.

The verifier architecture must allow the UI to represent this difference accurately.

---

# 50. Core V1 principle

The final system should always reason about these objects separately:

```text
BOOTSTRAP AUTHENTICATION
"This credential may ask for production."

WORKLOAD CLAIMS
"This process says it is commit ABC/image XYZ."

PROVENANCE
"Trusted evidence says artifact XYZ came from commit ABC."

RUNTIME ATTESTATION
"Can we prove artifact XYZ is actually executing?"
(optional/not generally available in V1)

ADMIN APPROVAL
"I authorize this exact ephemeral boot key."

SECRET DELIVERY
"Only that boot key can unwrap this environment key."
```

Never collapse those into one generic concept of “trusted workload”.

That separation is what will let V1 remain secure and let V2 add serverless/runtime-attestation mechanisms without rewriting the vault.
