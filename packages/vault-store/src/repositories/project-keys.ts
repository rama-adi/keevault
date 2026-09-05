import { z } from "zod";

import { integerColumn, keyStatusColumn, nullableTextColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

export const projectKeyRowSchema = z.object({
  projectId: z.string(),
  version: integerColumn,
  masterKeyVersion: integerColumn,
  wrappedKey: z.string(),
  nonce: z.string(),
  status: keyStatusColumn,
  createdAt: timestampColumn,
  retiredAt: nullableTextColumn,
});

export type ProjectKeyRow = z.infer<typeof projectKeyRowSchema>;

const projectKeyColumns = `
  project_id AS projectId,
  version AS version,
  master_key_version AS masterKeyVersion,
  wrapped_key AS wrappedKey,
  nonce AS nonce,
  status AS status,
  created_at AS createdAt,
  retired_at AS retiredAt
`;

export interface InsertProjectKeyInput {
  projectId: string;
  version: number;
  masterKeyVersion: number;
  wrappedKey: string;
  nonce: string;
  now: string;
}

export async function insertProjectKey(
  db: VaultDatabase,
  input: InsertProjectKeyInput,
): Promise<ProjectKeyRow> {
  const statement = db
    .prepare(
      `INSERT INTO project_keys
         (project_id, version, master_key_version, wrapped_key, nonce, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?)
       RETURNING ${projectKeyColumns}`,
    )
    .bind(
      input.projectId,
      input.version,
      input.masterKeyVersion,
      input.wrappedKey,
      input.nonce,
      input.now,
    );
  return await selectRequired(statement, projectKeyRowSchema);
}

/** The key version the project currently wraps new environment keys with. */
export async function getCurrentProjectKey(
  db: VaultDatabase,
  projectId: string,
): Promise<ProjectKeyRow | null> {
  const statement = db
    .prepare(
      `SELECT
         project_keys.project_id AS projectId,
         project_keys.version AS version,
         project_keys.master_key_version AS masterKeyVersion,
         project_keys.wrapped_key AS wrappedKey,
         project_keys.nonce AS nonce,
         project_keys.status AS status,
         project_keys.created_at AS createdAt,
         project_keys.retired_at AS retiredAt
       FROM project_keys
       JOIN projects ON projects.id = project_keys.project_id
       WHERE project_keys.project_id = ?
         AND project_keys.version = projects.current_project_key_version`,
    )
    .bind(projectId);
  return await selectOne(statement, projectKeyRowSchema);
}

export async function listProjectKeys(
  db: VaultDatabase,
  projectId: string,
): Promise<ProjectKeyRow[]> {
  const statement = db
    .prepare(`SELECT ${projectKeyColumns} FROM project_keys WHERE project_id = ? ORDER BY version`)
    .bind(projectId);
  return await selectMany(statement, projectKeyRowSchema);
}

export interface RetireProjectKeyInput {
  projectId: string;
  version: number;
  now: string;
}

export async function retireProjectKey(
  db: VaultDatabase,
  input: RetireProjectKeyInput,
): Promise<void> {
  await execute(
    db
      .prepare(
        `UPDATE project_keys SET status = 'retired', retired_at = ?
         WHERE project_id = ? AND version = ?`,
      )
      .bind(input.now, input.projectId, input.version),
  );
}
