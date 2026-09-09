import { z } from "zod";
import { integerColumn, keyStatusColumn, nullableTextColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { selectRequired, selectOne, selectMany } from "../sql.ts";

export const coldEnvironmentKeyRowSchema = z.object({
  environmentId: z.string(),
  version: integerColumn,
  recipientPublicKey: z.string(),
  ephemeralPublicKey: z.string(),
  salt: z.string(),
  nonce: z.string(),
  wrappedKey: z.string(),
  status: keyStatusColumn,
  createdAt: timestampColumn,
  retiredAt: nullableTextColumn,
});
export type ColdEnvironmentKeyRow = z.infer<typeof coldEnvironmentKeyRowSchema>;
const columns = `environment_id AS environmentId, version, recipient_public_key AS recipientPublicKey,
  ephemeral_public_key AS ephemeralPublicKey, salt, nonce, wrapped_key AS wrappedKey, status,
  created_at AS createdAt, retired_at AS retiredAt`;
export interface InsertColdEnvironmentKeyInput {
  environmentId: string;
  version: number;
  recipientPublicKey: string;
  ephemeralPublicKey: string;
  salt: string;
  nonce: string;
  wrappedKey: string;
  now: string;
}
export async function insertColdEnvironmentKey(
  db: VaultDatabase,
  input: InsertColdEnvironmentKeyInput,
): Promise<ColdEnvironmentKeyRow> {
  return await selectRequired(
    db
      .prepare(`INSERT INTO cold_environment_keys
    (environment_id, key_mode, version, recipient_public_key, ephemeral_public_key, salt, nonce, wrapped_key, status, created_at)
    VALUES (?, 'COLD', ?, ?, ?, ?, ?, ?, 'active', ?) RETURNING ${columns}`)
      .bind(
        input.environmentId,
        input.version,
        input.recipientPublicKey,
        input.ephemeralPublicKey,
        input.salt,
        input.nonce,
        input.wrappedKey,
        input.now,
      ),
    coldEnvironmentKeyRowSchema,
  );
}

/** Read client-wrapped material only. No server unwrap operation exists. */
export async function listColdEnvironmentKeys(
  db: VaultDatabase,
  environmentId: string,
): Promise<ColdEnvironmentKeyRow[]> {
  return await selectMany(
    db
      .prepare(
        `SELECT ${columns} FROM cold_environment_keys WHERE environment_id = ? ORDER BY version`,
      )
      .bind(environmentId),
    coldEnvironmentKeyRowSchema,
  );
}

export async function getCurrentColdEnvironmentKey(
  db: VaultDatabase,
  environmentId: string,
): Promise<ColdEnvironmentKeyRow | null> {
  return await selectOne(
    db
      .prepare(`SELECT ${columns} FROM cold_environment_keys
    WHERE environment_id = ? AND version = (
      SELECT current_env_key_version FROM environments WHERE id = ? AND key_mode = 'COLD'
    )`)
      .bind(environmentId, environmentId),
    coldEnvironmentKeyRowSchema,
  );
}
