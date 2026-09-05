import { z } from "zod";

import {
  bootStatusColumn,
  integerColumn,
  nullableTextColumn,
  timestampColumn,
} from "../columns.ts";
import type { BootStatus } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

/**
 * The D1 index row for a boot request. The Durable Object stays authoritative for
 * live authorization state (spec section 20); this row exists for the dashboard
 * and for history.
 */
export const bootRequestRowSchema = z.object({
  id: z.string(),
  environmentId: z.string(),
  bootstrapTokenId: z.string(),
  status: bootStatusColumn,
  sourceIp: nullableTextColumn,
  signingPublicKey: z.string(),
  encryptionPublicKey: z.string(),
  claimedGitRepository: nullableTextColumn,
  claimedGitCommit: nullableTextColumn,
  claimedOciRepository: nullableTextColumn,
  claimedOciDigest: nullableTextColumn,
  provenanceSummaryJson: nullableTextColumn,
  createdAt: timestampColumn,
  updatedAt: timestampColumn,
  approvedAt: nullableTextColumn,
  approvedBy: nullableTextColumn,
  declinedAt: nullableTextColumn,
  deliveredAt: nullableTextColumn,
  consumedAt: nullableTextColumn,
  expiredAt: nullableTextColumn,
  canceledAt: nullableTextColumn,
});

export type BootRequestRow = z.infer<typeof bootRequestRowSchema>;

const bootRequestColumns = `
  id AS id,
  environment_id AS environmentId,
  bootstrap_token_id AS bootstrapTokenId,
  status AS status,
  source_ip AS sourceIp,
  signing_public_key AS signingPublicKey,
  encryption_public_key AS encryptionPublicKey,
  claimed_git_repository AS claimedGitRepository,
  claimed_git_commit AS claimedGitCommit,
  claimed_oci_repository AS claimedOciRepository,
  claimed_oci_digest AS claimedOciDigest,
  provenance_summary_json AS provenanceSummaryJson,
  created_at AS createdAt,
  updated_at AS updatedAt,
  approved_at AS approvedAt,
  approved_by AS approvedBy,
  declined_at AS declinedAt,
  delivered_at AS deliveredAt,
  consumed_at AS consumedAt,
  expired_at AS expiredAt,
  canceled_at AS canceledAt
`;

export interface InsertBootRequestInput {
  id: string;
  environmentId: string;
  bootstrapTokenId: string;
  status: BootStatus;
  sourceIp: string | null;
  signingPublicKey: string;
  encryptionPublicKey: string;
  claimedGitRepository: string | null;
  claimedGitCommit: string | null;
  claimedOciRepository: string | null;
  claimedOciDigest: string | null;
  provenanceSummaryJson: string | null;
  now: string;
}

export async function insertBootRequest(
  db: VaultDatabase,
  input: InsertBootRequestInput,
): Promise<BootRequestRow> {
  const statement = db
    .prepare(
      `INSERT INTO boot_requests
         (id, environment_id, bootstrap_token_id, status, source_ip, signing_public_key,
          encryption_public_key, claimed_git_repository, claimed_git_commit,
          claimed_oci_repository, claimed_oci_digest, provenance_summary_json,
          created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       RETURNING ${bootRequestColumns}`,
    )
    .bind(
      input.id,
      input.environmentId,
      input.bootstrapTokenId,
      input.status,
      input.sourceIp,
      input.signingPublicKey,
      input.encryptionPublicKey,
      input.claimedGitRepository,
      input.claimedGitCommit,
      input.claimedOciRepository,
      input.claimedOciDigest,
      input.provenanceSummaryJson,
      input.now,
      input.now,
    );
  return await selectRequired(statement, bootRequestRowSchema);
}

export interface UpdateBootRequestStatusInput {
  bootId: string;
  status: BootStatus;
  now: string;
  approvedAt?: string | null;
  approvedBy?: string | null;
  declinedAt?: string | null;
  deliveredAt?: string | null;
  consumedAt?: string | null;
  expiredAt?: string | null;
  canceledAt?: string | null;
  provenanceSummaryJson?: string | null;
}

/**
 * Move the index row to a new status. Timestamps left out keep whatever value the
 * row already has.
 */
export async function updateBootRequestStatus(
  db: VaultDatabase,
  input: UpdateBootRequestStatusInput,
): Promise<BootRequestRow> {
  const statement = db
    .prepare(
      `UPDATE boot_requests SET
         status = ?,
         updated_at = ?,
         approved_at = COALESCE(?, approved_at),
         approved_by = COALESCE(?, approved_by),
         declined_at = COALESCE(?, declined_at),
         delivered_at = COALESCE(?, delivered_at),
         consumed_at = COALESCE(?, consumed_at),
         expired_at = COALESCE(?, expired_at),
         canceled_at = COALESCE(?, canceled_at),
         provenance_summary_json = COALESCE(?, provenance_summary_json)
       WHERE id = ?
       RETURNING ${bootRequestColumns}`,
    )
    .bind(
      input.status,
      input.now,
      input.approvedAt ?? null,
      input.approvedBy ?? null,
      input.declinedAt ?? null,
      input.deliveredAt ?? null,
      input.consumedAt ?? null,
      input.expiredAt ?? null,
      input.canceledAt ?? null,
      input.provenanceSummaryJson ?? null,
      input.bootId,
    );
  return await selectRequired(statement, bootRequestRowSchema);
}

export async function getBootRequest(
  db: VaultDatabase,
  bootId: string,
): Promise<BootRequestRow | null> {
  const statement = db
    .prepare(`SELECT ${bootRequestColumns} FROM boot_requests WHERE id = ?`)
    .bind(bootId);
  return await selectOne(statement, bootRequestRowSchema);
}

export async function listPendingBootRequestsByEnvironment(
  db: VaultDatabase,
  environmentId: string,
): Promise<BootRequestRow[]> {
  const statement = db
    .prepare(
      `SELECT ${bootRequestColumns}
       FROM boot_requests
       WHERE environment_id = ? AND status = 'PENDING'
       ORDER BY created_at, id`,
    )
    .bind(environmentId);
  return await selectMany(statement, bootRequestRowSchema);
}

export interface ListRecentBootRequestsInput {
  environmentId: string;
  limit: number;
}

export async function listRecentBootRequestsByEnvironment(
  db: VaultDatabase,
  input: ListRecentBootRequestsInput,
): Promise<BootRequestRow[]> {
  const statement = db
    .prepare(
      `SELECT ${bootRequestColumns}
       FROM boot_requests
       WHERE environment_id = ?
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
    )
    .bind(input.environmentId, input.limit);
  return await selectMany(statement, bootRequestRowSchema);
}

const countRowSchema = z.object({ pendingCount: integerColumn });

/** Used to enforce the per-token concurrent pending boot limit. */
export async function countPendingBootRequestsByToken(
  db: VaultDatabase,
  bootstrapTokenId: string,
): Promise<number> {
  const statement = db
    .prepare(
      `SELECT COUNT(*) AS pendingCount
       FROM boot_requests WHERE bootstrap_token_id = ? AND status = 'PENDING'`,
    )
    .bind(bootstrapTokenId);
  const row = await selectRequired(statement, countRowSchema);
  return row.pendingCount;
}

export interface CancelBootRequestsForTokenInput {
  bootstrapTokenId: string;
  now: string;
}

/**
 * Revoking a token cancels every PENDING and APPROVED boot from it (spec section 38).
 */
export async function cancelBootRequestsForToken(
  db: VaultDatabase,
  input: CancelBootRequestsForTokenInput,
): Promise<void> {
  await execute(
    db
      .prepare(
        `UPDATE boot_requests
         SET status = 'CANCELED', canceled_at = ?, updated_at = ?
         WHERE bootstrap_token_id = ? AND status IN ('PENDING', 'APPROVED')`,
      )
      .bind(input.now, input.now, input.bootstrapTokenId),
  );
}
