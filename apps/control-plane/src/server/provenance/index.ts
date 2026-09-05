import { claimsOnlyVerifier } from "./claims-only.ts";
import { signedBuildManifestVerifier } from "./signed-build-manifest.ts";
import type { ProvenanceVerifier, VerificationResult, VerifierInput } from "./types.ts";

export { claimsOnlyVerifier, CLAIMS_ONLY_VERIFIER_ID, normalizeClaims } from "./claims-only.ts";
export { loadProvenanceContext, type ProvenanceContext } from "./context.ts";
export { evaluatePolicy } from "./policy.ts";
export {
  signedBuildManifestVerifier,
  SIGNATURE_FAILURE_WARNING,
  SIGNED_BUILD_MANIFEST_VERIFIER_ID,
} from "./signed-build-manifest.ts";
export {
  canonicalSummary,
  parseSummary,
  provenanceSummarySchema,
  summaryDigest,
} from "./summary.ts";
export { VERIFICATION_STATUSES } from "./types.ts";
export type {
  PolicyEvaluation,
  ProvenancePolicyEntry,
  ProvenanceVerifier,
  TrustedSigner,
  VerificationFact,
  VerificationResult,
  VerificationStatus,
  VerifierInput,
} from "./types.ts";

/** Every verifier shipped in V1, in the order the approval screen shows them. */
export const V1_VERIFIERS: readonly ProvenanceVerifier[] = [
  claimsOnlyVerifier,
  signedBuildManifestVerifier,
];

/** Run a set of verifiers over one boot. Order follows the verifier list. */
export async function runVerifiers(
  verifiers: readonly ProvenanceVerifier[],
  input: VerifierInput,
): Promise<VerificationResult[]> {
  const results: VerificationResult[] = [];
  for (const verifier of verifiers) {
    results.push(await verifier.verify(input));
  }
  return results;
}
