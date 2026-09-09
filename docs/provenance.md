# Provenance

## The model: claims, evidence, verifiers, facts, policy, decision

Spec sections 24 through 29 define six distinct objects. The vault keeps them separate rather than collapsing them into one idea of a trusted workload.

Claims are what the workload itself says about itself: repository, commit, OCI repository, digest, deployment ID, provider name. A workload supplies claims in the `claims` field of `boot.hello`. Claims are untrusted by definition. Nothing in the system treats a claim as true until a verifier confirms it.

Evidence is material a verifier can check. V1 implements `claims-only` and `signed-build-manifest-v1`; it does not implement OCI registry, GitHub Artifact Attestation, Sigstore, or provider-attestation adapters. A workload supplies evidence in the `evidence` array of `boot.hello`, alongside its claims.

Verifier adapters take claims and evidence for one environment and return a normalized verification result. Each verifier is independent and interface-driven, so a new evidence source only requires a new adapter, not a change to the approval flow.

Normalized verified facts are what a verifier actually establishes: this OCI digest was produced from this commit, signed by this identity. The vault never assigns those facts a numeric trust score. It returns individual facts and warnings, and leaves interpretation to the policy layer and the human approver.

Environment policy decides how much a verifier's result matters for a given environment: `OFF`, `ADVISORY`, or `REQUIRED`.

Human decision is the administrator approving or declining a boot on the approval screen, which shows claims, verified facts, and policy status together.

## Verifier statuses

Every verifier returns one of four statuses, per spec section 25.

| Status        | What it means to an approver                                                                                                                                                                          |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VERIFIED`    | The evidence supplied was checked and it validates. The stated fact, for example that this commit produced this OCI digest, is confirmed by a trusted signer.                                         |
| `UNVERIFIED`  | No cryptographic evidence was available to check. The claim is displayed as information only. This is the claims-only verifier's permanent output, since it merely normalizes what the workload said. |
| `FAILED`      | Cryptographic evidence was supplied but did not validate. This must be shown as a clear failure, not a subtle warning, per spec section 34: `SIGNATURE VERIFICATION FAILED`.                          |
| `UNAVAILABLE` | The verifier has no supported evidence to check for this request. This is distinct from `FAILED`. `UNAVAILABLE` means nothing was checked. `FAILED` means something was checked and it was wrong.     |

The dashboard must show these four statuses distinctly. Rendering `UNAVAILABLE` and `FAILED` the same way would hide an actual signature failure behind a merely-missing-evidence look.

## Environment provenance policy

Each environment selects one policy, per spec section 26.

`OFF` means no provenance requirement. Claims are displayed but never block approval.

`ADVISORY` means every configured verifier runs and its result is displayed prominently, but an administrator may approve despite missing or unverified provenance. This is the recommended default for native Zeabur builds, since a native Zeabur Git build has no cryptographic build evidence to offer.

`REQUIRED` blocks approval unless each enabled required verifier reports `VERIFIED` and none of its facts contradicts a workload claim. With no enabled required policy rows, it requires at least one `VERIFIED` result, no `FAILED` result, and no mismatched fact. The current evaluator does not enforce repository or digest allow lists from policy configuration. The dashboard edits the mode, not per-verifier rules.

Approval reruns verification and checks the evidence-summary digest the operator viewed. A changed result requires review again.

## The signed-build-manifest-v1 format

This is the first cryptographically useful V1 verifier, per spec section 27. The manifest:

```json
{
  "version": 1,
  "source": { "repository": "github.com/acme/foo", "commit": "<40 or 64 hex>" },
  "artifact": { "type": "oci", "repository": "ghcr.io/acme/foo", "digest": "sha256:<64 hex>" },
  "builder": "acme-ci",
  "issuedAt": "2026-09-05T10:00:00.000Z"
}
```

Canonicalisation rule, per the engineering brief: rebuild the object with keys sorted by UTF-16 code unit order at every nesting level, then serialize with no whitespace. Values are limited to strings and the integer `1`. A Go implementation must use an encoder with `SetEscapeHTML(false)`, since Go's default JSON encoder escapes characters like `<` and `>` that would otherwise change the canonical byte sequence. A JavaScript implementation calls `JSON.stringify` on a key-sorted rebuilt object, since `JSON.stringify` alone does not sort keys.

The signed message is the UTF-8 bytes of a fixed prefix string followed by the canonical JSON, with no separator beyond the newline already in the prefix:

```
vault:signed-build-manifest:v1
```

That is, the exact bytes signed are `"vault:signed-build-manifest:v1\n"` concatenated with the canonical JSON bytes.

The signature is Ed25519 over those bytes. `signerFingerprint` is the lowercase hex SHA-256 of the signer's raw 32-byte public key. The vault looks up `trusted_signers` by that fingerprint to decide whether the signature is from a signer this environment or project trusts.

## CI example: signing a manifest with an Ed25519 key

The canonical JSON for the manifest above, with keys already sorted:

```
{"artifact":{"digest":"sha256:aaaa...","repository":"ghcr.io/acme/foo","type":"oci"},"builder":"acme-ci","issuedAt":"2026-09-05T10:00:00.000Z","source":{"commit":"abc123abc123abc123abc123abc123abc123abc1","repository":"github.com/acme/foo"},"version":1}
```

The exact bytes a CI job signs are the prefix plus that JSON, with no characters in between:

```
vault:signed-build-manifest:v1
{"artifact":{"digest":"sha256:aaaa...","repository":"ghcr.io/acme/foo","type":"oci"},"builder":"acme-ci","issuedAt":"2026-09-05T10:00:00.000Z","source":{"commit":"abc123abc123abc123abc123abc123abc123abc1","repository":"github.com/acme/foo"},"version":1}
```

A Node CI step that builds the canonical JSON and signs it:

```js
const crypto = require("node:crypto");

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value !== null && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortKeysDeep(value[key]);
    }
    return sorted;
  }
  return value;
}

function canonicalize(manifest) {
  return JSON.stringify(sortKeysDeep(manifest));
}

function signManifest(manifest, privateKey) {
  const canonical = canonicalize(manifest);
  const message = Buffer.from(`vault:signed-build-manifest:v1\n${canonical}`, "utf8");
  const signature = crypto.sign(null, message, privateKey);
  return signature.toString("base64url");
}
```

`Object.keys(value).sort()` sorts by UTF-16 code unit order for the ASCII field names this manifest uses. A CI pipeline calls `signManifest` with the private key held as a CI secret and attaches the base64url signature, the manifest, and the signer fingerprint as the `evidence` entry of type `signed-build-manifest-v1` in the boot request.

## Zeabur native build versus prebuilt OCI

Zeabur exposes Git metadata during its build phase, including commit SHA, repository owner and name, and branch. Spec section 29 is explicit that those values count as metadata, not independent cryptographic attestation.

For a native Zeabur Git build, bootstrap claims may contain the Git repository, commit, and provider deployment metadata, but there is no cryptographic evidence behind them. The dashboard shows:

```
Bootstrap authentication    ✓
Source IP                   ✓

Git commit claimed          abc123
Git repository claimed      acme/foo

Cryptographic provenance    unavailable
Runtime image identity      unverified

Policy: ADVISORY
```

Human approval remains available under this policy, since `ADVISORY` never blocks approval on missing provenance.

For a prebuilt OCI deployment, a separate CI pipeline builds the OCI image, obtains its immutable digest, and signs a build manifest before Zeabur ever pulls it. Zeabur supports prebuilt Docker-image deployments for exactly this path. The dashboard can then show verified Git-to-OCI provenance independently of Zeabur:

```
Build provenance           VERIFIED
Runtime image identity     CLAIMED / not remotely attested
```

## Build provenance is not runtime attestation

The dashboard displays "Running OCI identity: not independently attested". Build provenance answers what was built: a trusted signer says this commit produced this OCI digest. It does not answer what is currently running. Nothing in V1 remotely confirms that the process currently connected to the bootstrap WebSocket is executing that exact image.

Spec section 50 keeps these as separate objects: workload claims, provenance, and runtime attestation. Runtime attestation is explicitly optional and not generally available in V1. V2 may add provider-issued OIDC, signed deployment identity, or hardware attestation to close this gap, but V1 does not attempt it. A `VERIFIED` build-provenance status must never be presented or read as proof of what is executing right now.
