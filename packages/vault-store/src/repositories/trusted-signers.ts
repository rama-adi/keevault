import { z } from "zod";

import { booleanColumn, nullableTextColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectRequired } from "../sql.ts";

export const trustedSignerRowSchema = z.object({
  id: z.string(),
  projectId: nullableTextColumn,
  environmentId: nullableTextColumn,
  type: z.string(),
  label: z.string(),
  publicKey: z.string(),
  fingerprint: z.string(),
  enabled: booleanColumn,
  createdAt: timestampColumn,
  revokedAt: nullableTextColumn,
});

export type TrustedSignerRow = z.infer<typeof trustedSignerRowSchema>;

const trustedSignerColumns = `
  id AS id,
  project_id AS projectId,
  environment_id AS environmentId,
  type AS type,
  label AS label,
  public_key AS publicKey,
  fingerprint AS fingerprint,
  enabled AS enabled,
  created_at AS createdAt,
  revoked_at AS revokedAt
`;

export interface AddTrustedSignerInput {
  id: string;
  /** Set for a project-wide signer, otherwise null. */
  projectId: string | null;
  /** Set for an environment-scoped signer, otherwise null. */
  environmentId: string | null;
  type: string;
  label: string;
  publicKey: string;
  fingerprint: string;
  now: string;
}

export async function addTrustedSigner(
  db: VaultDatabase,
  input: AddTrustedSignerInput,
): Promise<TrustedSignerRow> {
  const statement = db
    .prepare(
      `INSERT INTO trusted_signers
         (id, project_id, environment_id, type, label, public_key, fingerprint, enabled, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
       RETURNING ${trustedSignerColumns}`,
    )
    .bind(
      input.id,
      input.projectId,
      input.environmentId,
      input.type,
      input.label,
      input.publicKey,
      input.fingerprint,
      input.now,
    );
  return await selectRequired(statement, trustedSignerRowSchema);
}

/** Signers usable by one environment: its own plus the project-wide ones. */
export async function listTrustedSignersForEnvironment(
  db: VaultDatabase,
  environmentId: string,
): Promise<TrustedSignerRow[]> {
  const statement = db
    .prepare(
      `SELECT ${trustedSignerColumns}
       FROM trusted_signers
       WHERE environment_id = ?1
          OR (environment_id IS NULL
              AND project_id = (SELECT project_id FROM environments WHERE id = ?1))
       ORDER BY created_at, id`,
    )
    .bind(environmentId);
  return await selectMany(statement, trustedSignerRowSchema);
}

export interface FindTrustedSignersByFingerprintInput {
  environmentId: string;
  fingerprint: string;
}

/** Enabled signers with this fingerprint that the environment may use. */
export async function findTrustedSignersByFingerprint(
  db: VaultDatabase,
  input: FindTrustedSignersByFingerprintInput,
): Promise<TrustedSignerRow[]> {
  const statement = db
    .prepare(
      `SELECT ${trustedSignerColumns}
       FROM trusted_signers
       WHERE fingerprint = ?2
         AND enabled = 1
         AND (environment_id = ?1
              OR (environment_id IS NULL
                  AND project_id = (SELECT project_id FROM environments WHERE id = ?1)))
       ORDER BY created_at, id`,
    )
    .bind(input.environmentId, input.fingerprint);
  return await selectMany(statement, trustedSignerRowSchema);
}

export interface RevokeTrustedSignerInput {
  signerId: string;
  now: string;
}

export async function revokeTrustedSigner(
  db: VaultDatabase,
  input: RevokeTrustedSignerInput,
): Promise<void> {
  await execute(
    db
      .prepare(
        "UPDATE trusted_signers SET enabled = 0, revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
      )
      .bind(input.now, input.signerId),
  );
}
