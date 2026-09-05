import { z } from "zod";

import { integerColumn, nullableTextColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

/** Token record without the hash, for dashboard listings. */
export const bootstrapTokenRowSchema = z.object({
  id: z.string(),
  environmentId: z.string(),
  label: z.string(),
  allowedCidrsJson: z.string(),
  maxPendingBoots: integerColumn,
  expiresAt: nullableTextColumn,
  revokedAt: nullableTextColumn,
  lastSeenAt: nullableTextColumn,
  createdAt: timestampColumn,
});

export type BootstrapTokenRow = z.infer<typeof bootstrapTokenRowSchema>;

/** Token record including the stored hash, for authentication only. */
export const bootstrapTokenWithHashRowSchema = bootstrapTokenRowSchema.extend({
  tokenHash: z.string(),
});

export type BootstrapTokenWithHashRow = z.infer<typeof bootstrapTokenWithHashRowSchema>;

const bootstrapTokenColumns = `
  id AS id,
  environment_id AS environmentId,
  label AS label,
  allowed_cidrs_json AS allowedCidrsJson,
  max_pending_boots AS maxPendingBoots,
  expires_at AS expiresAt,
  revoked_at AS revokedAt,
  last_seen_at AS lastSeenAt,
  created_at AS createdAt
`;

const bootstrapTokenWithHashColumns = `${bootstrapTokenColumns},
  token_hash AS tokenHash
`;

export interface CreateBootstrapTokenInput {
  /** Row id, `tok_` followed by the 26-character token id. */
  id: string;
  environmentId: string;
  label: string;
  /** Lowercase hex SHA-256 of the token secret. The token itself is never stored. */
  tokenHash: string;
  allowedCidrsJson: string;
  maxPendingBoots: number;
  expiresAt: string | null;
  now: string;
}

export async function createBootstrapToken(
  db: VaultDatabase,
  input: CreateBootstrapTokenInput,
): Promise<BootstrapTokenRow> {
  const statement = db
    .prepare(
      `INSERT INTO bootstrap_tokens
         (id, environment_id, label, token_hash, allowed_cidrs_json, max_pending_boots,
          expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       RETURNING ${bootstrapTokenColumns}`,
    )
    .bind(
      input.id,
      input.environmentId,
      input.label,
      input.tokenHash,
      input.allowedCidrsJson,
      input.maxPendingBoots,
      input.expiresAt,
      input.now,
    );
  return await selectRequired(statement, bootstrapTokenRowSchema);
}

/**
 * Look a token up by the id carried inside the presented token. Callers compare
 * the returned hash against the presented secret in constant time.
 */
export async function getBootstrapTokenByTokenId(
  db: VaultDatabase,
  tokenId: string,
): Promise<BootstrapTokenWithHashRow | null> {
  const statement = db
    .prepare(`SELECT ${bootstrapTokenWithHashColumns} FROM bootstrap_tokens WHERE id = ?`)
    .bind(`tok_${tokenId}`);
  return await selectOne(statement, bootstrapTokenWithHashRowSchema);
}

/** Dashboard listing. The stored hash is never selected. */
export async function listBootstrapTokensByEnvironment(
  db: VaultDatabase,
  environmentId: string,
): Promise<BootstrapTokenRow[]> {
  const statement = db
    .prepare(
      `SELECT ${bootstrapTokenColumns}
       FROM bootstrap_tokens WHERE environment_id = ? ORDER BY created_at, id`,
    )
    .bind(environmentId);
  return await selectMany(statement, bootstrapTokenRowSchema);
}

export interface RevokeBootstrapTokenInput {
  tokenRowId: string;
  now: string;
}

export async function revokeBootstrapToken(
  db: VaultDatabase,
  input: RevokeBootstrapTokenInput,
): Promise<void> {
  await execute(
    db
      .prepare("UPDATE bootstrap_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
      .bind(input.now, input.tokenRowId),
  );
}

export interface TouchBootstrapTokenInput {
  tokenRowId: string;
  now: string;
}

export async function touchBootstrapTokenLastSeen(
  db: VaultDatabase,
  input: TouchBootstrapTokenInput,
): Promise<void> {
  await execute(
    db
      .prepare("UPDATE bootstrap_tokens SET last_seen_at = ? WHERE id = ?")
      .bind(input.now, input.tokenRowId),
  );
}

export interface UpdateBootstrapTokenCidrsInput {
  tokenRowId: string;
  allowedCidrsJson: string;
}

export async function updateBootstrapTokenCidrs(
  db: VaultDatabase,
  input: UpdateBootstrapTokenCidrsInput,
): Promise<BootstrapTokenRow> {
  const statement = db
    .prepare(
      `UPDATE bootstrap_tokens SET allowed_cidrs_json = ? WHERE id = ?
       RETURNING ${bootstrapTokenColumns}`,
    )
    .bind(input.allowedCidrsJson, input.tokenRowId);
  return await selectRequired(statement, bootstrapTokenRowSchema);
}
