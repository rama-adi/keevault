import {
  listProvenancePoliciesByEnvironment,
  listTrustedSignersForEnvironment,
  type ProvenanceMode,
  type VaultDatabase,
} from "@env-vault/vault-store";

import type { ProvenancePolicyEntry, TrustedSigner } from "./types.ts";

/**
 * Everything the verifiers and the policy check read from D1 for one
 * environment. It is loaded fresh on every approval, so a signer revoked while
 * an approval screen was open takes effect immediately.
 */
export interface ProvenanceContext {
  readonly mode: ProvenanceMode;
  readonly signers: readonly TrustedSigner[];
  readonly policies: readonly ProvenancePolicyEntry[];
}

export async function loadProvenanceContext(
  db: VaultDatabase,
  environmentId: string,
  mode: ProvenanceMode,
): Promise<ProvenanceContext> {
  const signerRows = await listTrustedSignersForEnvironment(db, environmentId);
  const policyRows = await listProvenancePoliciesByEnvironment(db, environmentId);
  return {
    mode,
    signers: signerRows
      .filter((row) => row.enabled && row.revokedAt === null)
      .map((row) => ({
        id: row.id,
        label: row.label,
        publicKey: row.publicKey,
        fingerprint: row.fingerprint,
        type: row.type,
      })),
    policies: policyRows.map((row) => ({
      verifierType: row.verifierType,
      required: row.required,
      enabled: row.enabled,
    })),
  };
}
