import { z } from "zod";

import { booleanColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

export const provenancePolicyRowSchema = z.object({
  id: z.string(),
  environmentId: z.string(),
  verifierType: z.string(),
  configurationJson: z.string(),
  required: booleanColumn,
  enabled: booleanColumn,
  createdAt: timestampColumn,
  updatedAt: timestampColumn,
});

export type ProvenancePolicyRow = z.infer<typeof provenancePolicyRowSchema>;

const provenancePolicyColumns = `
  id AS id,
  environment_id AS environmentId,
  verifier_type AS verifierType,
  configuration_json AS configurationJson,
  required AS required,
  enabled AS enabled,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

export interface UpsertProvenancePolicyInput {
  /** Used only when this environment has no policy for the verifier type yet. */
  id: string;
  environmentId: string;
  verifierType: string;
  configurationJson: string;
  required: boolean;
  enabled: boolean;
  now: string;
}

export async function upsertProvenancePolicy(
  db: VaultDatabase,
  input: UpsertProvenancePolicyInput,
): Promise<ProvenancePolicyRow> {
  const statement = db
    .prepare(
      `INSERT INTO provenance_policies
         (id, environment_id, verifier_type, configuration_json, required, enabled,
          created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (environment_id, verifier_type) DO UPDATE SET
         configuration_json = excluded.configuration_json,
         required = excluded.required,
         enabled = excluded.enabled,
         updated_at = excluded.updated_at
       RETURNING ${provenancePolicyColumns}`,
    )
    .bind(
      input.id,
      input.environmentId,
      input.verifierType,
      input.configurationJson,
      input.required ? 1 : 0,
      input.enabled ? 1 : 0,
      input.now,
      input.now,
    );
  return await selectRequired(statement, provenancePolicyRowSchema);
}

export interface GetProvenancePolicyInput {
  environmentId: string;
  verifierType: string;
}

export async function getProvenancePolicy(
  db: VaultDatabase,
  input: GetProvenancePolicyInput,
): Promise<ProvenancePolicyRow | null> {
  const statement = db
    .prepare(
      `SELECT ${provenancePolicyColumns}
       FROM provenance_policies WHERE environment_id = ? AND verifier_type = ?`,
    )
    .bind(input.environmentId, input.verifierType);
  return await selectOne(statement, provenancePolicyRowSchema);
}

export async function listProvenancePoliciesByEnvironment(
  db: VaultDatabase,
  environmentId: string,
): Promise<ProvenancePolicyRow[]> {
  const statement = db
    .prepare(
      `SELECT ${provenancePolicyColumns}
       FROM provenance_policies WHERE environment_id = ? ORDER BY verifier_type`,
    )
    .bind(environmentId);
  return await selectMany(statement, provenancePolicyRowSchema);
}

export interface SetProvenancePolicyEnabledInput {
  policyId: string;
  enabled: boolean;
  now: string;
}

export async function setProvenancePolicyEnabled(
  db: VaultDatabase,
  input: SetProvenancePolicyEnabledInput,
): Promise<void> {
  await execute(
    db
      .prepare("UPDATE provenance_policies SET enabled = ?, updated_at = ? WHERE id = ?")
      .bind(input.enabled ? 1 : 0, input.now, input.policyId),
  );
}

export async function deleteProvenancePolicy(db: VaultDatabase, policyId: string): Promise<void> {
  await execute(db.prepare("DELETE FROM provenance_policies WHERE id = ?").bind(policyId));
}
