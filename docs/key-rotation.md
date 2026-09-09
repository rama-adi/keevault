# Key rotation

Back up every required `VAULT_MASTER_KEY_V<n>` outside Cloudflare before rotation. A database backup cannot replace a lost wrapping key.

Environment and project rotation are implemented as owner-only dashboard actions with recent passkey verification. Master-key rewrap is not implemented as a service, command, or dashboard action. The procedure below describes the requirements for an operator migration, not an available button.

## Current concurrency limitation

The [2026-09-09 audit](audit-2026-09-09.md) found unresolved rotation races. Environment rotation reads a secret snapshot, encrypts it, then updates rows by id without checking the snapshot's versions. A competing secret write can be overwritten with ciphertext authenticated for an older version; a new secret can miss the snapshot entirely. Project rotation also needs coordination with environment creation and environment-key rotation.

Arrange a maintenance window and prevent other operators or automation from writing secrets, importing dotenv files, creating environments, or rotating keys in the affected project. Let in-flight mutations finish first. The application does not enforce this pause. If you cannot exclude competing mutations, postpone rotation until the implementation coordinates them. Record a recoverable pre-rotation database snapshot and keep all wrapping keys required to read it.

## Environment key rotation

Use the environment page's rotation action as an owner after passkey verification. Stop new boot approvals and finish or cancel live boots before maintenance. Rotation itself does not drain or cancel boots, and it cannot revoke secrets already delivered.

The service in `src/server/vault/rotation.ts` performs these operations:

1. Unwrap the current environment and project keys.
2. Generate a new random environment key and encrypt each secret with a fresh nonce. `env_key_version` increases; `secret_version` stays unchanged.
3. Insert the new environment-key row.
4. Batch the secret rewrites, retirement of the old environment-key row, and update of `environments.current_env_key_version`.
5. Write `environment-key.rotated` with version numbers and the number of secrets re-encrypted.

The batch does not protect the earlier reads from concurrent changes. The new key insertion occurs before the batch, so a failed batch can leave an extra key row. Do not retry blindly after failure; inspect the key rows and active pointer first.

Verify that the environment points to the new version, exactly one environment-key row is active, and every current secret references the new key version. Confirm a controlled boot can decrypt the resulting values without printing them. Keep retired keys and the pre-rotation database snapshot for recovery.

If a committed rotation produces unreadable data, restore a consistent database snapshot with its required wrapping keys. Changing only the active version or restoring only a key row does not restore overwritten ciphertext. Keep competing writes paused until verification or recovery finishes.

## Project key rotation

Use the project page's rotation action as an owner after passkey verification. Apply the same maintenance precautions above.

The service generates a new project key and rewraps every environment-key row for that project, including retired versions. It updates those wraps in place without changing the environment-key material or version. It inserts the new project-key row before batching the rewraps, retirement of the old project key, and current-version switch. Secret ciphertext is unchanged. The service then writes `project-key.rotated`.

Verify the project points to the new version, exactly one project-key row is active, and every environment-key row in the snapshot now references that version. Confirm the environments still decrypt. A failed batch can leave the separately inserted project-key row; inspect it before retrying. For a failure after commit, restore the database snapshot and required master keys together. The retired project key alone cannot reverse wraps updated in place.

## Master key migration requirements

There is no implemented master-key rewrap operation. The `master-key-rewrapped` audit name exists, but no current service emits it. A migration must use the cryptographic wrapping functions with the correct authenticated metadata; changing `master_key_version` in SQL alone breaks decryption.

Before implementing and rehearsing a migration:

1. Back up the old key and generate and back up a new independent 32-byte key.
2. Add the new Worker secret alongside the old one. Keep every referenced master-key version available.
3. Prevent project creation and rotations during migration, or implement coordination that prevents old-version rows appearing after the migration scan.
4. Rewrap project-key rows under the new master key, updating the ciphertext, nonce, and authenticated version metadata together. Account for retired project keys as well as active ones.
5. Verify all retained rows decrypt and select the new `VAULT_MASTER_KEY_ACTIVE_VERSION` before resuming writes.
6. Remove an old Worker secret only after confirming no live or retained database row needs it. Keep its offline backup for historical database restores.

Changing the active version only controls new project-key wraps; it does not migrate existing rows. Reverting that setting also does not reverse a rewrap. Keep both master keys during rollback and recovery. Rehearse the migration and restore against a scratch deployment before using it on production data.
