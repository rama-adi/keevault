import type { Evidence, WorkloadClaims } from "@env-vault/protocol";

/**
 * Provenance verification interfaces (spec sections 24 and 25).
 *
 * A verifier reports a status and a list of normalized facts. There is no
 * numeric trust score anywhere in this module, by design: the approval screen
 * shows the facts and a human decides.
 */

/** The four outcomes a verifier can report. They mean different things. */
export const VERIFICATION_STATUSES = ["VERIFIED", "UNVERIFIED", "FAILED", "UNAVAILABLE"] as const;

/**
 * VERIFIED: cryptographic evidence validated.
 * UNVERIFIED: information was normalized but nothing was cryptographically checked.
 * FAILED: evidence was supplied and did not validate.
 * UNAVAILABLE: no attestation exists for this deployment.
 */
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

/**
 * One normalized statement produced by a verifier. `matchesClaim` is null when
 * the workload made no comparable claim, true when the claim and the fact agree
 * and false when they disagree.
 */
export interface VerificationFact {
  readonly key: string;
  readonly value: string;
  readonly matchesClaim: boolean | null;
}

/** What one verifier concluded about one boot. */
export interface VerificationResult {
  readonly verifier: string;
  readonly status: VerificationStatus;
  readonly facts: readonly VerificationFact[];
  readonly warnings: readonly string[];
}

/** A signer the environment trusts, as stored in D1. */
export interface TrustedSigner {
  readonly id: string;
  readonly label: string;
  /** Ed25519 public key as b64u. */
  readonly publicKey: string;
  /** Lowercase hex SHA-256 of the raw public key. */
  readonly fingerprint: string;
  readonly type: string;
}

/** Everything a verifier is allowed to look at. */
export interface VerifierInput {
  readonly environmentId: string;
  readonly claims: WorkloadClaims;
  readonly evidence: readonly Evidence[];
  /** Enabled signers usable by this environment: its own plus project-wide ones. */
  readonly signers: readonly TrustedSigner[];
}

/** One adapter that turns claims and evidence into a normalized result. */
export interface ProvenanceVerifier {
  readonly id: string;
  verify(input: VerifierInput): Promise<VerificationResult>;
}

/** One row of an environment's provenance policy configuration. */
export interface ProvenancePolicyEntry {
  readonly verifierType: string;
  readonly required: boolean;
  readonly enabled: boolean;
}

/** Whether approval may proceed, and why not when it may not. */
export interface PolicyEvaluation {
  readonly approvable: boolean;
  readonly blockers: readonly string[];
}
