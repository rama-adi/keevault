import type { ProvenanceMode } from "@keevault/vault-store";

import type { PolicyEvaluation, ProvenancePolicyEntry, VerificationResult } from "./types.ts";

/**
 * Turn verifier output into an approve-or-not decision (spec section 26).
 *
 * OFF and ADVISORY never block: the results are still shown, and the operator
 * decides. REQUIRED blocks unless every required verifier reported VERIFIED
 * with no fact contradicting a workload claim.
 *
 * When an environment is REQUIRED but has no enabled required policy row, the
 * rule falls back to "at least one VERIFIED result, nothing FAILED, no
 * mismatched fact". An environment that demands provenance must not become
 * permissive because nobody configured a row.
 */
export function evaluatePolicy(
  mode: ProvenanceMode,
  results: readonly VerificationResult[],
  policies: readonly ProvenancePolicyEntry[],
): PolicyEvaluation {
  if (mode !== "REQUIRED") {
    return { approvable: true, blockers: [] };
  }

  const blockers: string[] = [];
  const required = policies.filter((policy) => policy.enabled && policy.required);

  if (required.length === 0) {
    const verified = results.filter((result) => result.status === "VERIFIED");
    if (verified.length === 0) {
      blockers.push("no verifier reported VERIFIED and this environment requires provenance");
    }
    for (const result of results) {
      if (result.status === "FAILED") {
        blockers.push(`${result.verifier} reported FAILED`);
      }
    }
  }

  for (const policy of required) {
    const result = results.find((candidate) => candidate.verifier === policy.verifierType);
    if (result === undefined) {
      blockers.push(`${policy.verifierType} is required but did not run`);
      continue;
    }
    if (result.status !== "VERIFIED") {
      blockers.push(`${policy.verifierType} is required and reported ${result.status}`);
    }
  }

  const checked =
    required.length === 0
      ? results
      : required.flatMap((policy) => {
          const result = results.find((candidate) => candidate.verifier === policy.verifierType);
          return result === undefined ? [] : [result];
        });
  for (const result of checked) {
    for (const entry of result.facts) {
      if (entry.matchesClaim === false) {
        blockers.push(`${result.verifier}: ${entry.key} does not match the workload claim`);
      }
    }
  }

  return { approvable: blockers.length === 0, blockers };
}
