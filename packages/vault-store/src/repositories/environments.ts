import { z } from "zod";

import { integerColumn, keyModeColumn, provenanceModeColumn, timestampColumn } from "../columns.ts";
import type { KeyMode, ProvenanceMode } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

export const environmentRowSchema = z.object({
  id: z.string(),
  projectId: z.string(),
  slug: z.string(),
  name: z.string(),
  keyMode: keyModeColumn,
  ownerEncryptionPublicKey: z.string().nullable(),
  ownerSigningPublicKey: z.string().nullable(),
  currentEnvKeyVersion: integerColumn,
  provenanceMode: provenanceModeColumn,
  pendingTtlSeconds: integerColumn,
  approvedTtlSeconds: integerColumn,
  createdAt: timestampColumn,
  updatedAt: timestampColumn,
});

export type EnvironmentRow = z.infer<typeof environmentRowSchema>;

const environmentColumns = `
  id AS id,
  project_id AS projectId,
  slug AS slug,
  name AS name,
  key_mode AS keyMode,
  owner_encryption_public_key AS ownerEncryptionPublicKey,
  owner_signing_public_key AS ownerSigningPublicKey,
  current_env_key_version AS currentEnvKeyVersion,
  provenance_mode AS provenanceMode,
  pending_ttl_seconds AS pendingTtlSeconds,
  approved_ttl_seconds AS approvedTtlSeconds,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

export interface CreateEnvironmentInput {
  id: string;
  projectId: string;
  slug: string;
  name: string;
  keyMode?: KeyMode;
  ownerEncryptionPublicKey?: string | null;
  ownerSigningPublicKey?: string | null;
  provenanceMode: ProvenanceMode;
  pendingTtlSeconds: number;
  approvedTtlSeconds: number;
  now: string;
}

export async function createEnvironment(
  db: VaultDatabase,
  input: CreateEnvironmentInput,
): Promise<EnvironmentRow> {
  const statement = db
    .prepare(
      `INSERT INTO environments
         (id, project_id, slug, name, key_mode, owner_encryption_public_key, owner_signing_public_key, current_env_key_version, provenance_mode,
          pending_ttl_seconds, approved_ttl_seconds, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
       RETURNING ${environmentColumns}`,
    )
    .bind(
      input.id,
      input.projectId,
      input.slug,
      input.name,
      input.keyMode ?? "CLOUD",
      input.ownerEncryptionPublicKey ?? null,
      input.ownerSigningPublicKey ?? null,
      input.provenanceMode,
      input.pendingTtlSeconds,
      input.approvedTtlSeconds,
      input.now,
      input.now,
    );
  return await selectRequired(statement, environmentRowSchema);
}

export async function getEnvironment(
  db: VaultDatabase,
  environmentId: string,
): Promise<EnvironmentRow | null> {
  const statement = db
    .prepare(`SELECT ${environmentColumns} FROM environments WHERE id = ?`)
    .bind(environmentId);
  return await selectOne(statement, environmentRowSchema);
}

export async function listEnvironmentsByProject(
  db: VaultDatabase,
  projectId: string,
): Promise<EnvironmentRow[]> {
  const statement = db
    .prepare(`SELECT ${environmentColumns} FROM environments WHERE project_id = ? ORDER BY slug`)
    .bind(projectId);
  return await selectMany(statement, environmentRowSchema);
}

export interface UpdateEnvironmentPolicyInput {
  environmentId: string;
  provenanceMode: ProvenanceMode;
  pendingTtlSeconds: number;
  approvedTtlSeconds: number;
  now: string;
}

/** Update the provenance mode and the two boot TTLs. */
export async function updateEnvironmentPolicy(
  db: VaultDatabase,
  input: UpdateEnvironmentPolicyInput,
): Promise<EnvironmentRow> {
  const statement = db
    .prepare(
      `UPDATE environments
       SET provenance_mode = ?, pending_ttl_seconds = ?, approved_ttl_seconds = ?, updated_at = ?
       WHERE id = ?
       RETURNING ${environmentColumns}`,
    )
    .bind(
      input.provenanceMode,
      input.pendingTtlSeconds,
      input.approvedTtlSeconds,
      input.now,
      input.environmentId,
    );
  return await selectRequired(statement, environmentRowSchema);
}

export async function deleteEnvironment(db: VaultDatabase, environmentId: string): Promise<void> {
  await execute(db.prepare("DELETE FROM environments WHERE id = ?").bind(environmentId));
}
