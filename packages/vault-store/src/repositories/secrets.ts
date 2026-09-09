import { z } from "zod";

import { integerColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase, VaultPreparedStatement } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

/** Secret metadata for the dashboard. Never carries ciphertext. */
export const secretMetadataRowSchema = z.object({
  id: z.string(),
  environmentId: z.string(),
  name: z.string(),
  envKeyVersion: integerColumn,
  secretVersion: integerColumn,
  createdAt: timestampColumn,
  updatedAt: timestampColumn,
});

export type SecretMetadataRow = z.infer<typeof secretMetadataRowSchema>;

/** Secret record for delivery to a boot. Carries the sealed value. */
export const secretDeliveryRowSchema = secretMetadataRowSchema.extend({
  ciphertext: z.string(),
  nonce: z.string(),
});

export type SecretDeliveryRow = z.infer<typeof secretDeliveryRowSchema>;

const secretMetadataColumns = `
  id AS id,
  environment_id AS environmentId,
  name AS name,
  env_key_version AS envKeyVersion,
  secret_version AS secretVersion,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

const secretDeliveryColumns = `${secretMetadataColumns},
  ciphertext AS ciphertext,
  nonce AS nonce
`;

export interface UpsertSecretInput {
  /** Zero for creation, otherwise the version used to encrypt the replacement. */
  expectedVersion: number;
  /** The row id authenticated by the ciphertext. */
  id: string;
  environmentId: string;
  name: string;
  ciphertext: string;
  nonce: string;
  envKeyVersion: number;
  now: string;
}

/**
 * Write a secret value. An existing (environment, name) row is replaced in place
 * and its version is incremented; the row id stays stable. A stale expected
 * version or row id rejects the write before ciphertext can lose its AAD binding.
 */
export async function upsertSecretReplace(
  db: VaultDatabase,
  input: UpsertSecretInput,
): Promise<SecretMetadataRow> {
  const statement = db
    .prepare(
      `INSERT INTO secrets
         (id, environment_id, name, ciphertext, nonce, env_key_version, secret_version,
          created_at, updated_at)
       SELECT ?, ?, ?, ?, ?, ?, 1, ?, ?
       WHERE ? = 0 OR EXISTS (
         SELECT 1 FROM secrets WHERE id = ? AND secret_version = ?
       )
       ON CONFLICT (environment_id, name) DO UPDATE SET
         ciphertext = excluded.ciphertext,
         nonce = excluded.nonce,
         env_key_version = excluded.env_key_version,
         secret_version = secrets.secret_version + 1,
         updated_at = excluded.updated_at
       WHERE secrets.id = excluded.id AND secrets.secret_version = ?
       RETURNING ${secretMetadataColumns}`,
    )
    .bind(
      input.id,
      input.environmentId,
      input.name,
      input.ciphertext,
      input.nonce,
      input.envKeyVersion,
      input.now,
      input.now,
      input.expectedVersion,
      input.id,
      input.expectedVersion,
      input.expectedVersion,
    );
  return await selectRequired(statement, secretMetadataRowSchema);
}

/** Dashboard listing. Ciphertext is deliberately not selected. */
export async function listSecretMetadata(
  db: VaultDatabase,
  environmentId: string,
): Promise<SecretMetadataRow[]> {
  const statement = db
    .prepare(`SELECT ${secretMetadataColumns} FROM secrets WHERE environment_id = ? ORDER BY name`)
    .bind(environmentId);
  return await selectMany(statement, secretMetadataRowSchema);
}

/** Delivery listing for the Durable Object. Carries ciphertext and nonce. */
export async function listSecretsForDelivery(
  db: VaultDatabase,
  environmentId: string,
): Promise<SecretDeliveryRow[]> {
  const statement = db
    .prepare(`SELECT ${secretDeliveryColumns} FROM secrets WHERE environment_id = ? ORDER BY name`)
    .bind(environmentId);
  return await selectMany(statement, secretDeliveryRowSchema);
}

export interface GetSecretInput {
  environmentId: string;
  name: string;
}

export async function getSecretForDelivery(
  db: VaultDatabase,
  input: GetSecretInput,
): Promise<SecretDeliveryRow | null> {
  const statement = db
    .prepare(`SELECT ${secretDeliveryColumns} FROM secrets WHERE environment_id = ? AND name = ?`)
    .bind(input.environmentId, input.name);
  return await selectOne(statement, secretDeliveryRowSchema);
}

export async function deleteSecret(db: VaultDatabase, input: GetSecretInput): Promise<void> {
  await execute(
    db
      .prepare("DELETE FROM secrets WHERE environment_id = ? AND name = ?")
      .bind(input.environmentId, input.name),
  );
}

export interface ReencryptSecretInput {
  id: string;
  ciphertext: string;
  nonce: string;
  envKeyVersion: number;
  now: string;
}

/**
 * Replace the sealed bytes of one secret after an environment-key rotation.
 *
 * `secret_version` does not change: the value is the same, only the key that
 * protects it is new. Returned as a statement so the whole rotation, including
 * the key switch, goes into one batch.
 */
export function buildReencryptSecretStatement(
  db: VaultDatabase,
  input: ReencryptSecretInput,
): VaultPreparedStatement {
  return db
    .prepare(
      `UPDATE secrets SET ciphertext = ?, nonce = ?, env_key_version = ?, updated_at = ?
       WHERE id = ?`,
    )
    .bind(input.ciphertext, input.nonce, input.envKeyVersion, input.now, input.id);
}
