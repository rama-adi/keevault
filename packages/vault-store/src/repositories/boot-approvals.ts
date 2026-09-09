import { z } from "zod";

import { timestampColumn, keyModeColumn, integerColumn, type KeyMode } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { selectOne, selectRequired } from "../sql.ts";

/** The record binding one approval to one boot (spec section 22). */
export const bootApprovalRowSchema = z.object({
  bootId: z.string(),
  approverUserId: z.string(),
  approverCredentialId: z.string(),
  approvedAt: timestampColumn,
  clientSigningFingerprint: z.string(),
  clientEncryptionFingerprint: z.string(),
  evidenceDigest: z.string(),
  keyMode: keyModeColumn,
  environmentKeyVersion: integerColumn,
  releaseContextDigest: z.string(),
});

export type BootApprovalRow = z.infer<typeof bootApprovalRowSchema>;

const bootApprovalColumns = `
  boot_id AS bootId,
  approver_user_id AS approverUserId,
  approver_credential_id AS approverCredentialId,
  approved_at AS approvedAt,
  client_signing_fingerprint AS clientSigningFingerprint,
  client_encryption_fingerprint AS clientEncryptionFingerprint,
  evidence_digest AS evidenceDigest,
  key_mode AS keyMode,
  environment_key_version AS environmentKeyVersion,
  release_context_digest AS releaseContextDigest
`;

export interface InsertBootApprovalInput {
  bootId: string;
  approverUserId: string;
  approverCredentialId: string;
  approvedAt: string;
  /** Hex SHA-256 fingerprint of the client Ed25519 signing key. */
  clientSigningFingerprint: string;
  /** Hex SHA-256 fingerprint of the client X25519 encryption key. */
  clientEncryptionFingerprint: string;
  /** Hex SHA-256 of the stored provenance summary JSON. */
  evidenceDigest: string;
  keyMode: KeyMode;
  environmentKeyVersion: number;
  releaseContextDigest: string;
}

export async function insertBootApproval(
  db: VaultDatabase,
  input: InsertBootApprovalInput,
): Promise<BootApprovalRow> {
  const statement = db
    .prepare(
      `INSERT INTO boot_approvals
         (boot_id, approver_user_id, approver_credential_id, approved_at,
          client_signing_fingerprint, client_encryption_fingerprint, evidence_digest,
          key_mode, environment_key_version, release_context_digest)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       RETURNING ${bootApprovalColumns}`,
    )
    .bind(
      input.bootId,
      input.approverUserId,
      input.approverCredentialId,
      input.approvedAt,
      input.clientSigningFingerprint,
      input.clientEncryptionFingerprint,
      input.evidenceDigest,
      input.keyMode,
      input.environmentKeyVersion,
      input.releaseContextDigest,
    );
  return await selectRequired(statement, bootApprovalRowSchema);
}

export async function getBootApproval(
  db: VaultDatabase,
  bootId: string,
): Promise<BootApprovalRow | null> {
  const statement = db
    .prepare(`SELECT ${bootApprovalColumns} FROM boot_approvals WHERE boot_id = ?`)
    .bind(bootId);
  return await selectOne(statement, bootApprovalRowSchema);
}
