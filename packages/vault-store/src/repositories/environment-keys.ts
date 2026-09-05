import { z } from "zod";

import { integerColumn, keyStatusColumn, nullableTextColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

export const environmentKeyRowSchema = z.object({
  environmentId: z.string(),
  version: integerColumn,
  projectKeyVersion: integerColumn,
  wrappedKey: z.string(),
  nonce: z.string(),
  status: keyStatusColumn,
  createdAt: timestampColumn,
  retiredAt: nullableTextColumn,
});

export type EnvironmentKeyRow = z.infer<typeof environmentKeyRowSchema>;

const environmentKeyColumns = `
  environment_id AS environmentId,
  version AS version,
  project_key_version AS projectKeyVersion,
  wrapped_key AS wrappedKey,
  nonce AS nonce,
  status AS status,
  created_at AS createdAt,
  retired_at AS retiredAt
`;

export interface InsertEnvironmentKeyInput {
  environmentId: string;
  version: number;
  projectKeyVersion: number;
  wrappedKey: string;
  nonce: string;
  now: string;
}

export async function insertEnvironmentKey(
  db: VaultDatabase,
  input: InsertEnvironmentKeyInput,
): Promise<EnvironmentKeyRow> {
  const statement = db
    .prepare(
      `INSERT INTO environment_keys
         (environment_id, version, project_key_version, wrapped_key, nonce, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?)
       RETURNING ${environmentKeyColumns}`,
    )
    .bind(
      input.environmentId,
      input.version,
      input.projectKeyVersion,
      input.wrappedKey,
      input.nonce,
      input.now,
    );
  return await selectRequired(statement, environmentKeyRowSchema);
}

export async function getCurrentEnvironmentKey(
  db: VaultDatabase,
  environmentId: string,
): Promise<EnvironmentKeyRow | null> {
  const statement = db
    .prepare(
      `SELECT
         environment_keys.environment_id AS environmentId,
         environment_keys.version AS version,
         environment_keys.project_key_version AS projectKeyVersion,
         environment_keys.wrapped_key AS wrappedKey,
         environment_keys.nonce AS nonce,
         environment_keys.status AS status,
         environment_keys.created_at AS createdAt,
         environment_keys.retired_at AS retiredAt
       FROM environment_keys
       JOIN environments ON environments.id = environment_keys.environment_id
       WHERE environment_keys.environment_id = ?
         AND environment_keys.version = environments.current_env_key_version`,
    )
    .bind(environmentId);
  return await selectOne(statement, environmentKeyRowSchema);
}

export async function listEnvironmentKeys(
  db: VaultDatabase,
  environmentId: string,
): Promise<EnvironmentKeyRow[]> {
  const statement = db
    .prepare(
      `SELECT ${environmentKeyColumns}
       FROM environment_keys WHERE environment_id = ? ORDER BY version`,
    )
    .bind(environmentId);
  return await selectMany(statement, environmentKeyRowSchema);
}

export interface RetireEnvironmentKeyInput {
  environmentId: string;
  version: number;
  now: string;
}

export async function retireEnvironmentKey(
  db: VaultDatabase,
  input: RetireEnvironmentKeyInput,
): Promise<void> {
  await execute(
    db
      .prepare(
        `UPDATE environment_keys SET status = 'retired', retired_at = ?
         WHERE environment_id = ? AND version = ?`,
      )
      .bind(input.now, input.environmentId, input.version),
  );
}

export interface SwitchCurrentEnvironmentKeyInput {
  environmentId: string;
  previousVersion: number;
  nextVersion: number;
  now: string;
}

/**
 * Retire the previous environment key and point the environment at the next one
 * in a single batch, so no reader sees a half-applied rotation.
 */
export async function switchCurrentEnvironmentKey(
  db: VaultDatabase,
  input: SwitchCurrentEnvironmentKeyInput,
): Promise<void> {
  await db.batch([
    db
      .prepare(
        `UPDATE environment_keys SET status = 'retired', retired_at = ?
         WHERE environment_id = ? AND version = ?`,
      )
      .bind(input.now, input.environmentId, input.previousVersion),
    db
      .prepare(
        `UPDATE environment_keys SET status = 'active', retired_at = NULL
         WHERE environment_id = ? AND version = ?`,
      )
      .bind(input.environmentId, input.nextVersion),
    db
      .prepare("UPDATE environments SET current_env_key_version = ?, updated_at = ? WHERE id = ?")
      .bind(input.nextVersion, input.now, input.environmentId),
  ]);
}
