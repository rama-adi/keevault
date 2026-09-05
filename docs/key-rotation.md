# Key rotation

Losing the sole master key makes every piece of vault ciphertext permanently unrecoverable. Before running any procedure below, confirm a secure offline copy of the current `VAULT_MASTER_KEY_V<n>` exists outside Cloudflare, per spec section 46.

This document covers the three rotation procedures from spec section 39: environment key, project key, and master key. Master-key versioning uses `VAULT_MASTER_KEY_V<n>` Worker secrets selected by `VAULT_MASTER_KEY_ACTIVE_VERSION`, per the engineering brief.

## Runbook 1: environment key rotation

Use after suspected environment-key exposure. This is the only rotation that requires secret plaintext to exist transiently inside the Worker, since every secret value must be decrypted and re-encrypted under the new key.

### Preconditions

- The current environment key unwraps successfully under the active project key.
- No boot is `APPROVED` or `DELIVERED` for this environment. Wait for those to reach `CONSUMED`, `EXPIRED`, or `CANCELED`, or cancel them, before starting. A boot mid-delivery is wrapped to the old environment key version and cannot be salvaged after rotation.
- An administrator has recent step-up passkey authentication, since key rotation is a step-up-gated action per spec section 22.

### Steps

1. Unwrap the current environment key using the active project key.
2. Generate a new environment key, `ENV_KEY_vNext`, from a CSPRNG. Do not derive it from the old key or from any hash of project or environment identity.
3. Decrypt every secret in `secrets` for this `environment_id` under the current environment key.
4. Re-encrypt every secret under `ENV_KEY_vNext` with a fresh 96-bit nonce per value, using the AAD from the engineering brief's secret-value wrap, incrementing `env_key_version` and `secret_version` for each row.
5. Wrap `ENV_KEY_vNext` under the current project key, writing a new row to `environment_keys` with the incremented `version` and `status` set to active.
6. Atomically switch `environments.current_env_key_version` to the new version in the same transaction that marks the previous `environment_keys` row `status = 'retired'`.
7. Retire the previous environment key row. Do not delete it. Keep it for audit and for decrypting any historical D1 export made before rotation.

### Verification queries

- Query `environments` for the rotated row and confirm `current_env_key_version` equals the new version.
- Query `environment_keys` for this `environment_id` and confirm exactly one row has `status = 'active'` at the new version, and every prior version has `status = 'retired'`.
- Query `secrets` for this `environment_id` and confirm every row's `env_key_version` equals the new version and no row still references the retired version.
- Query `boot_requests` for this `environment_id` and confirm no row is `PENDING`, `APPROVED`, or `DELIVERED` referencing the old environment key version.

### Rollback

If re-encryption fails partway, do not switch `current_env_key_version`. The previous environment key remains active and untouched until the transaction in step 6 commits. Because step 6 is a single atomic transaction, there is no partially-rotated state visible to readers. If a bug is discovered after the switch has committed, restore from the retired `environment_keys` row and the pre-rotation `secrets` ciphertext using D1 point-in-time recovery, since the retired key is still available to decrypt that older ciphertext.

### What is logged

Write `environment-key.rotated` to `audit_events` with `environment_id`, the old and new `environment_keys` version numbers, and the admin's actor ID. Never log the environment key itself, the decrypted secret plaintext, or the wrapping shared secret.

## Runbook 2: project key rotation

No secret re-encryption is required, since only the wrapping layer above the environment key changes.

### Preconditions

- The current project key unwraps successfully under the active master key version.
- An administrator has recent step-up passkey authentication.

### Steps

1. Unwrap every active `environment_keys` row under this project's current project key.
2. Generate a new project key, `PROJECT_KEY_vNext`, from a CSPRNG.
3. Rewrap every environment key under `PROJECT_KEY_vNext`, writing new `environment_keys` rows with `project_key_version` set to the new version and the same `wrapped_key` content re-encrypted, or updating the existing rows' wrap in place if the schema treats wrap as mutable per version. Keep `env_key_version` unchanged, since the environment key material itself does not change.
4. Wrap `PROJECT_KEY_vNext` under the active master key version, writing a new row to `project_keys` with the incremented `version`.
5. Atomically switch `projects.current_project_key_version` to the new version and mark the previous `project_keys` row `status = 'retired'`.

### Verification queries

- Query `projects` for the rotated row and confirm `current_project_key_version` equals the new version.
- Query `project_keys` for this `project_id` and confirm exactly one row has `status = 'active'`.
- Query `environment_keys` for every environment under this project and confirm `project_key_version` equals the new version on every active row.

### Rollback

The previous project key row stays in `project_keys` with `status = 'retired'`. If the switch has not yet committed, no environment key has lost its old wrap, since step 3 writes new wraps without deleting the old ones until the transaction commits. If a problem surfaces after commit, the retired project key can still unwrap the environment keys it wrapped historically, so restoring from a pre-rotation D1 snapshot recovers a working state.

### What is logged

Write `project-key.rotated` to `audit_events` with `project_id`, old and new `project_keys` version numbers, and the admin's actor ID.

## Runbook 3: master key rotation

Support master-key versioning from day one using `VAULT_MASTER_KEY_V1`, `VAULT_MASTER_KEY_V2`, and so on as separate Cloudflare Worker secrets, with `VAULT_MASTER_KEY_ACTIVE_VERSION` selecting which version wraps new project keys. Never perform this as a single irreversible step.

### Preconditions

- A secure offline copy of the current active master key version already exists, per spec section 46.
- The new master key version has been generated with a CSPRNG and is ready to add as a Worker secret before this runbook starts.

### Steps

1. Add the new Worker secret, for example `VAULT_MASTER_KEY_V2`, alongside the existing `VAULT_MASTER_KEY_V1`. Do not remove `V1` yet.
2. Deploy a Worker build capable of reading both `V1` and `V2`, so in-flight requests against project keys still wrapped under `V1` continue to succeed during the rewrap.
3. Rewrap every active project key: unwrap under the master key version recorded in its `project_keys.master_key_version` column, then wrap under `V2`, writing the updated `master_key_version` and `wrapped_key` for each row.
4. Confirm no `project_keys` row with `status = 'active'` still references the old master key version.
5. Set `VAULT_MASTER_KEY_ACTIVE_VERSION` to the new version, so newly created project keys wrap under `V2` going forward.
6. Remove the old master key Worker secret in a later, separate deployment, only after confirming step 4 and after a safe waiting period in case a rollback is needed.

### Verification queries

- Query `project_keys` for every row with `status = 'active'` and confirm `master_key_version` equals the new version.
- Count rows in `project_keys` where `master_key_version` equals the old version and `status = 'active'`. This count must be zero before proceeding to step 5.
- After step 5, confirm the Worker's active configuration reads `VAULT_MASTER_KEY_ACTIVE_VERSION` as the new version.

### Rollback

Because both master key secrets remain present through step 5, rolling back before step 6 means reverting `VAULT_MASTER_KEY_ACTIVE_VERSION` to the old version and leaving both secrets in place. Once the old secret is removed in step 6, rollback requires restoring it from the offline backup, since no active code path can otherwise unwrap project keys that still reference the removed version. This is why step 4 must confirm zero remaining references before step 6 runs.

### What is logged

Write `master-key-rewrapped` to `audit_events` for each project key rewrapped, with `project_id`, old and new `master_key_version`, and the admin's actor ID. Never log either master key value.
