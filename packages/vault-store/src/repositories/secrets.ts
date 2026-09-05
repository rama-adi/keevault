import { z } from "zod";

import { integerColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
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
  /** Used only when the secret name is new in this environment. */
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
 * and its version is incremented; the row id stays stable.
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
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
       ON CONFLICT (environment_id, name) DO UPDATE SET
         ciphertext = excluded.ciphertext,
         nonce = excluded.nonce,
         env_key_version = excluded.env_key_version,
         secret_version = secrets.secret_version + 1,
         updated_at = excluded.updated_at
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
