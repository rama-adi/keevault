import type { WorkloadClaims } from "@env-vault/protocol";

import type { ProvenanceVerifier, VerificationFact, VerificationResult } from "./types.ts";

/** The verifier id used in policy rows and in the stored summary. */
export const CLAIMS_ONLY_VERIFIER_ID = "claims-only";

/**
 * Normalize the workload's own statements about itself. Nothing here is
 * checked against anything, so the status is always UNVERIFIED (spec section
 * 27A). It exists so a deployment with no attestation still produces a
 * readable approval screen.
 */
export function normalizeClaims(claims: WorkloadClaims): VerificationFact[] {
  const facts: VerificationFact[] = [];
  const git = claims.git;
  if (git !== undefined) {
    facts.push({ key: "source.repository", value: git.repository, matchesClaim: null });
    facts.push({ key: "source.commit", value: git.commit, matchesClaim: null });
  }
  const oci = claims.oci;
  if (oci !== undefined) {
    facts.push({ key: "artifact.repository", value: oci.repository, matchesClaim: null });
    facts.push({ key: "artifact.digest", value: oci.digest, matchesClaim: null });
  }
  const provider = claims.provider;
  if (provider !== undefined) {
    facts.push({ key: "provider.name", value: provider.name, matchesClaim: null });
    const deploymentId = provider.deploymentId;
    if (deploymentId !== undefined) {
      facts.push({ key: "provider.deploymentId", value: deploymentId, matchesClaim: null });
    }
    const region = provider.region;
    if (region !== undefined) {
      facts.push({ key: "provider.region", value: region, matchesClaim: null });
    }
  }
  return facts;
}

/** Verifier A from spec section 27. Supports every deployment. */
export const claimsOnlyVerifier: ProvenanceVerifier = {
  id: CLAIMS_ONLY_VERIFIER_ID,
  verify(input): Promise<VerificationResult> {
    const facts = normalizeClaims(input.claims);
    const warnings =
      facts.length === 0
        ? ["the workload sent no claims about itself"]
        : ["claims are not attested"];
    return Promise.resolve({
      verifier: CLAIMS_ONLY_VERIFIER_ID,
      status: "UNVERIFIED",
      facts,
      warnings,
    });
  },
};
