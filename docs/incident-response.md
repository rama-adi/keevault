# Incident response

Each runbook below covers detect, contain, eradicate, recover, and what to write in the post-incident note. Audit event names come from spec section 35. Metrics and alert-worthy events come from spec section 45.

## Leaked bootstrap token

**Detect.** Watch for `boot.requested` events from an unfamiliar source IP against a token's environment, a spike in the `invalid token attempts` or `CIDR failures` metrics, or a report that a token value appeared in a public repository, log, or chat.

**Contain.** Revoke the token immediately by setting `bootstrap_tokens.revoked_at`. Revocation, per spec section 38, prevents new WebSockets, prevents reconnect, and cancels every `PENDING` request from that token. Cancel `APPROVED` but not yet delivered requests from that token as well, since the safest V1 behavior is fail closed. Requests already `CONSUMED` cannot be revoked retroactively, since that workload already holds its environment values.

**Eradicate.** Issue a new bootstrap token for the affected environment and update the deployment's `VAULT_BOOTSTRAP_TOKEN` configuration. Confirm the old token's `token_hash` can no longer authenticate by checking `revoked_at` is set and attempting a WebSocket upgrade with the old value returns close code 4403.

**Recover.** Confirm the legitimate workload reconnects and completes a fresh boot against the new token. Confirm any workload still holding the old token fails closed rather than retrying indefinitely.

**Post-incident note.** Record how the token leaked, the time between leak and revocation, every boot request the leaked token created before revocation, and whether any of those requests reached `APPROVED` before being canceled.

## Leaked D1 export

**Detect.** This usually surfaces externally, through a cloud storage misconfiguration report, a backup-access audit, or a Cloudflare account compromise notice. There is no in-vault signal for a passive export leak, since reading a backup does not touch the live system.

**Contain.** Confirm the master key was not also exposed. If the master key is intact, the exported ciphertext, wrapped keys, and token hashes are useless to the attacker. Rotate any bootstrap token whose plaintext might have been reconstructable from other leaked material, though `token_hash` alone does not allow that.

**Eradicate.** Fix the access-control gap that allowed the export to leak, whether that is a storage bucket permission, an over-broad Cloudflare API token, or a compromised backup credential.

**Recover.** No vault-side recovery action is required if the master key remains secret, since D1 compromise alone is insufficient per spec section 3. If there is any doubt the master key was exposed alongside the D1 export, treat this as a master key rotation event instead and follow that runbook in `docs/key-rotation.md`.

**Post-incident note.** Record what was exported, when, who had access to the leak location, whether the master key was potentially co-located with the export, and the access-control fix applied.

## Leaked Docker image or Zeabur environment dump

**Detect.** A report that an image was pushed to a public registry by mistake, or that a Zeabur environment-variable dump was pasted somewhere it should not have been.

**Contain.** The Docker image itself contains no plaintext environment values and no long-term decryption keys, per spec section 3, so the image leak alone is not a secrets leak. If the leak includes `VAULT_BOOTSTRAP_TOKEN` from the Zeabur dump, treat this as the leaked bootstrap token runbook above and revoke that token immediately.

**Eradicate.** Remove the leaked image from any public registry it reached. Rotate the leaked token per the runbook above.

**Recover.** Confirm the workload reconnects with a freshly issued token.

**Post-incident note.** Record what the leak contained, whether it included a bootstrap token, and the revocation timeline if it did.

## Suspected environment key exposure

**Detect.** A report of anomalous decrypted secret access, a compromised Worker deployment, or any indication that the environment DEK was observed in plaintext outside an authorized boot, rather than only wrapped ciphertext.

**Contain.** Cancel any `PENDING` or `APPROVED` boot request for the affected environment to prevent further delivery under the exposed key while rotation is prepared.

**Eradicate.** Run the environment key rotation runbook in `docs/key-rotation.md`. This decrypts and re-encrypts every secret under a new environment key, which invalidates the exposed key for any future use.

**Recover.** Confirm every secret's `env_key_version` reflects the new version, per the verification queries in that runbook. Confirm any legitimate workload reconnecting after rotation receives the new environment key version.

**Post-incident note.** Record how the exposure was suspected or confirmed, the environment affected, the old and new `environment_keys` version numbers, and whether any secret values are known to have been read by an unauthorized party during the exposure window.

## Compromised admin account

**Detect.** Watch the `admin authentication anomalies` alert category from spec section 45: logins from unexpected locations, repeated failed step-up attempts, or a report from the account owner that their passkey device was lost or stolen.

**Contain.** Revoke the account's active Better Auth sessions immediately. If the compromise involves a specific passkey credential, remove that credential from the account so it can no longer satisfy login or step-up.

**Eradicate.** Require the account owner to register a new passkey from a trusted device before restoring access. Review `audit_events` for every action taken under that account's session during the suspected compromise window, specifically `secret.updated`, `secret.deleted`, `bootstrap-token.created`, `provenance-policy.changed`, `trusted-signer.added`, and any `boot.approved` event.

**Recover.** For any `boot.approved` event found during the compromise window that the legitimate owner did not intend, treat the corresponding boot as compromised. If it already reached `CONSUMED`, treat the delivered environment as exposed and rotate that environment's key per the runbook above. If it has not yet been delivered, cancel it.

**Contain, further.** If the account is an owner and no other owner exists, do not lock the account out without first confirming another owner or the emergency operator procedure below is available, since owner-only actions include rotating project and environment keys and managing administrators.

**Post-incident note.** Record which credential was compromised, every action attributed to the compromised session, which of those actions were reviewed and confirmed benign or malicious, and any key rotation or boot cancellation performed as a result.

## Lost passkey for the only owner

This is the emergency operator procedure from spec section 41. Better Auth hardening keeps emergency account recovery an explicit operator procedure rather than a silent fallback to a weak password, so there is no self-service recovery path by design.

**Detect.** The sole owner reports losing their passkey device with no other registered credential and no other owner account.

**Contain.** Confirm no other owner or admin account exists that could instead be promoted, since promoting an existing admin to owner is preferable to an out-of-band recovery.

**Eradicate.** There is no in-product self-service reset for this case, since public signup and unauthenticated recovery are both disabled by design. Recovery requires an operator with direct access to the Cloudflare account and D1 database to perform a manual credential reset for the affected Better Auth user record, following whatever manual procedure the operator has documented outside the dashboard. Decide before launch exactly what that manual procedure is and who is authorized to run it, since the brief and the spec do not define its mechanics.

**Recover.** Once access is restored, require the owner to register a new passkey immediately and confirm login and step-up both succeed with it.

**Post-incident note.** Record how the loss was confirmed to be genuine, who performed the manual recovery, what evidence of identity was required before recovery was granted, and the new credential's registration time.

## Flood of boot requests

See spec section 37. This may be an attack using a stolen token, or an application-level bug causing a workload to retry boot creation aggressively.

**Detect.** Watch `pending boots`, `invalid token attempts`, and `multiple simultaneous boots using one token` from the metrics and alert list in spec section 45. The per-token limit on concurrent pending boots, default three, and the per-source-address boot request creation threshold, are the first line of defense, and hitting either limit repeatedly is itself a detection signal.

**Contain.** If the flood traces to a single token, revoke it per the leaked bootstrap token runbook. If it traces to a legitimate workload retrying due to a bug, fix the retry behavior at the source, since rate limiting is abuse protection only and must never substitute for the Durable Object's authorization state machine.

**Eradicate.** Cancel any excess `PENDING` requests the flood created beyond the legitimate one, if a legitimate request exists among them.

**Recover.** Confirm the dashboard collapses the remaining requests from that token clearly and confirm an administrator can distinguish the legitimate request, if any, from the flood.

**Post-incident note.** Record the token or source address responsible, the request volume observed, whether any flooded request reached `APPROVED`, and whether the cause was malicious or a client-side retry bug.

## Stale dashboard state disagreeing with the Durable Object

See spec section 20. This is a consistency incident rather than an attack, but it must be handled carefully since an approval decision made against stale state can authorize the wrong boot or fail to authorize the right one.

**Detect.** An administrator reports the dashboard shows a boot as `PENDING` when it can no longer be approved, or an approval attempt fails with a conflict the dashboard did not warn about. Watch `D1 failures` and `DO failures` in the metrics from spec section 45 for a systemic cause.

**Contain.** Treat the Durable Object as authoritative in every case. If the dashboard says `PENDING` but the DO says `EXPIRED`, the approval must be rejected and the dashboard refreshed. Never allow a stale D1 row to authorize delivery.

**Eradicate.** If this is an isolated one-off refresh lag, no code change is needed beyond confirming the dashboard re-fetches DO state before rendering the approve action. If it recurs, investigate whether the D1 projection write from DO state transitions is failing or delayed, since D1 is meant to be an index of DO state, not a second source of truth.

**Recover.** Confirm the dashboard, after refresh, shows the DO's actual current state for the affected boot request.

**Post-incident note.** Record which boot request showed disagreement, what the dashboard displayed versus what the DO reported, whether any approval action was attempted against the stale state, and whether that action was correctly rejected.
