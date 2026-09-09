# Keevault v2 draft

Status: proposal for discussion, 2026-09-09. The two key modes and approval CLI
described here are not implemented. Client build reporting is an incremental v1
change and provides no runtime attestation.

## Product direction

Keep the existing workflow: an application requests its environment, a person
reviews the request, and the application starts after approval. Offer two key
modes per environment, with the choice visible wherever secrets are imported
or a boot is approved.

|                        | Cloud-managed keys                                        | Cold key mode                                                       |
| ---------------------- | --------------------------------------------------------- | ------------------------------------------------------------------- |
| Account authentication | Passkey                                                   | Passkey                                                             |
| Approval               | Dashboard with recent passkey authentication              | Local CLI with private key and authenticated account                |
| Who can decrypt        | Keevault infrastructure and approved workloads            | User's local key holder and approved workloads                      |
| Secret entry           | Dashboard or CLI                                          | Local CLI for the initial release                                   |
| Key recovery           | Keevault-managed key availability and recovery procedures | User-held backup or an explicitly authorized recovery key           |
| Main trust dependency  | Keevault operators, deployed code, and hosting security   | Local CLI, user's device, recipient verification, and workload host |

Passkeys authenticate the account. They do not, in this proposal, derive or
unlock environment encryption keys. Account recovery and decryption recovery
are separate operations.

"Cold key" means Keevault does not hold the private key. A key unlocked by an
online CLI is not air-gapped or permanently offline. Consider "local key mode"
as the final product name.

## Cloud-managed keys

Retain the current encryption hierarchy and server-side approval flow. A master
key available to the Worker unwraps project keys, which unwrap environment keys.
The Worker encrypts incoming secret values and wraps environment keys for
approved workloads.

The onboarding disclosure should say:

> Keevault manages your encryption keys. Passkeys protect account access.
> Keevault infrastructure can decrypt your secret values, so this mode requires
> trust in Keevault's operators and software.

Protecting the key with a KMS, reducing administrative access, and auditing key
use improve operations. They do not remove operator access if operator-controlled
code can request decryption. Do not describe this mode as end-to-end encrypted
or inaccessible to Keevault.

## Cold key setup and storage

Proposed command names below illustrate the intended UX. They are not available
commands or confirmation that the npm package name is owned or published.

```sh
npx keevault init
npx keevault keys create
npx keevault env import production --file .env
```

The CLI opens the browser for passkey authentication and obtains a short-lived,
scoped CLI session through a device authorization flow. Do not ask users to
paste browser cookies into the terminal.

The CLI generates an encryption key pair locally, plus a separate signing key
pair for authenticating environment snapshots and approvals. Private keys stay
on the user's device, encrypted at rest with restrictive file permissions.
Never put private keys in command arguments, environment variables, telemetry,
or the project repository. Choose the local keystore and unlock method during
implementation; do not reuse the account password as an unstated key scheme.

Keevault stores public keys, key IDs, fingerprints, and ciphertext. The CLI pins
the enrolled public keys locally. Enrollment and replacement need explicit
verification; a database edit must not silently change a trusted key.

Use envelope encryption rather than encrypting a whole env directly with a
public-key algorithm:

1. For each new environment snapshot, the CLI generates a fresh random data
   encryption key and encrypts the complete env locally using authenticated
   encryption.
2. It encrypts that data key to the owner's pinned public encryption key using
   a reviewed public-key envelope scheme.
3. It signs the snapshot manifest, binding the environment ID, snapshot version,
   key IDs, encrypted key envelope, and ciphertext digest. It uploads only
   ciphertext, envelopes, and the signed manifest.

For the first release, imports replace the entire environment snapshot. Editing
an existing value requires the CLI to unlock and read the old snapshot locally,
merge the edit, and produce a new snapshot. Decide partial-update and multi-writer
behavior later, before introducing shared data-key or nonce state.

Possessing a public encryption key lets anyone create ciphertext for it. It does
not authenticate the writer. Pinned signing keys and signed snapshots stop the
server from fabricating a valid replacement. The CLI and workload also need
version checks and a signed complete manifest to detect rollback and omission.
An existing device can remember its latest accepted version; a new device must
obtain a trusted checkpoint during enrollment. Server timestamps alone do not
provide freshness against a malicious server.

The control plane can still see account and environment metadata, ciphertext
sizes, boot times, and source addresses. Encrypt names inside the snapshot if
secret-name confidentiality is part of the promise. It can also deny service or
delete ciphertext; encryption does not provide availability.

## What happens during cold key approval

```sh
npx keevault approve <boot-id>
```

The CLI decrypts the environment's data key locally and re-encrypts that key for
the waiting workload. The workload decrypts the env values. Approval does not
upload plaintext or the user's private key, and it does not print secret values.

1. The workload generates ephemeral signing and encryption keys and starts a
   boot request. It shows the boot ID and encryption-key fingerprint in its
   terminal or deployment logs.
2. The approval CLI fetches the pending request and shows the environment,
   recipient fingerprint, snapshot version, claims, and available evidence.
3. The user verifies the recipient fingerprint through a trusted workload
   channel. For the initial release, require this comparison before release.
   An ID copied only from the Keevault dashboard is insufficient: the server
   could substitute its own recipient key and display its own request.
4. The CLI verifies the signed snapshot against its pinned owner key, unlocks
   the local private key, and decrypts the data-key envelope.
5. The CLI encrypts the data key to the verified workload public key and signs
   an approval binding the environment, boot ID, boot nonce, recipient keys,
   snapshot version and digest, key version, and expiry.
6. The control plane checks account permissions and boot state, then relays
   the signed approval, encrypted data key, and encrypted snapshot.
7. The workload independently checks the signature against an owner key pinned
   during deployment, the recipient binding, snapshot digest, and expiry. It
   decrypts the data key with its ephemeral private key, decrypts the env, then
   starts the configured application.

Workload owner-key pins must come from user-controlled deployment configuration,
not a key fetched without verification from the same control plane. A bootstrap
token still admits requests and limits abuse; it does not grant cold-key
decryption authority. Server-side approval alone cannot release a cold key.

The implementation must use a reviewed, versioned protocol with domain-separated
signatures, authenticated metadata, fresh nonces, replay checks, and cross-language
test vectors. The existing X25519/HKDF/AES-GCM envelope is a starting point, not
an already complete cold-key protocol. Server checks and local signature checks
are both necessary, but only the latter protect against a malicious server.

## Client distribution is part of the trust model

Unversioned `npx keevault` is a convenient entry point, but npm execution can
resolve or install package code. A malicious update running locally could read
the unlocked private key or secret values. Calling the key local does not remove
trust in that code. See [npm's npx documentation](https://docs.npmjs.com/cli/v11/commands/npx/).

Before real cold keys are used, ship a reviewed client with explicit update
control. Document an exact-version invocation such as `npx keevault@<version>`
and an installed binary with independently pinned checksums. Version pinning is
only one measure: review dependencies, avoid mutable runtime downloads, publish
source and reproducible build instructions, and protect release signing.

Keep cold-mode import and approval out of server-delivered JavaScript for the
first release. The dashboard can show metadata and instructions for the CLI.
Moving cryptography into a page Keevault can replace does not protect the next
unlock against a malicious deployment.

## Recovery, revocation, and unattended workloads

- Create an encrypted offline backup before relying on a cold key. If every
  private-key copy and authorized recovery key is lost, Keevault cannot recover
  the secrets. A passkey reset cannot bypass this.
- Begin with one owner key set per cold environment. Team members and recovery
  recipients need authenticated enrollment and separately wrapped data keys.
  Do not silently add recipients after a server-side account recovery.
- Rotate keys and re-encrypt snapshots when removing access. A previously
  approved workload may already have copied plaintext or keys. Expiry and
  revocation cannot erase those copies.
- A fresh boot needs an online approving key holder. A later customer-operated
  approval agent can automate this, but its key is online and its policies
  become part of the customer's security boundary.
- The launched application and a privileged workload host can read delivered
  env values. Cold mode protects against the Keevault control plane, not against
  every recipient or host compromise.

## Migration and implementation scope

Keep v1 environments in cloud-managed mode. Create cold environments explicitly;
do not infer mode from whether a key record happens to exist. No fallback from
cold mode to server-side key wrapping is allowed.

Moving to cold mode requires local encryption under new keys. Existing v1 has no
secret reveal endpoint, so the first migration path is a local re-import from
the user's source of truth. Existing values were accessible under the old
architecture and may remain in backups. Users needing a fresh confidentiality
guarantee must also rotate credentials at their issuers. Moving back to cloud
mode explicitly grants Keevault decryption access and requires a reviewed export
from the local CLI.

Implement v2 in separately reviewed stages:

1. Specify the key hierarchy, recipient verification, signed snapshot and
   approval formats, recovery behavior, and hostile-server tests.
2. Build the local key lifecycle and encrypted snapshot import.
3. Add cold-key boot delivery, local approval, and independent workload checks.
4. Add mode selection, migration guidance, and release verification instructions.

Before shipping, decide npm package ownership and distribution, supported owner
platforms, local key protection, and the exact pairing UX. Test public-key
substitution, snapshot replacement/rollback, replay, omitted records, lost keys,
and a server attempting approval without the user's key.

## Immediate v1 change: client reports

Send `claims.client` with `version`, `os`, `arch`, and executable `sha256`. Store
it with the boot's existing claims in Durable Object SQLite and display it as
client-reported. An unreadable executable leaves the digest absent; an old client
may omit the whole block. Tagged release builds embed their version; unstamped
builds report `dev`.

This is informational only. Do not promote a matching hash to verified runtime
identity, use it to authorize key release, or add a silent fallback to older
servers that reject the new claim. Deploy the compatible control plane before
distributing updated clients. A release catalog and hardware-backed attestation
remain separate future work.

## References

- [Current secret ingestion](../apps/control-plane/src/server/vault/secrets.ts)
- [Current boot approval](../apps/control-plane/src/server/durable-objects/boot-session-core.ts)
- [Current envelope implementation](../packages/crypto/src/envelope.ts)
- [Public-key substitution considerations](https://1password.com/blog/eth-zurich-zero-knowledge-malicious-server-review)
- [Client-side key wrapping and device approval](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Reproducible build definition](https://reproducible-builds.org/docs/definition/)
- [Remote attestation architecture](https://www.rfc-editor.org/rfc/rfc9334.html)
