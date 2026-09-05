import { b64uDecode, signedBuildManifestNode, verifyManifest } from "@env-vault/crypto";
import type { Evidence, SignedBuildManifestEvidence } from "@env-vault/protocol";

import type {
  ProvenanceVerifier,
  TrustedSigner,
  VerificationFact,
  VerificationResult,
  VerifierInput,
} from "./types.ts";

/** The verifier id, which is also the evidence `type` it consumes. */
export const SIGNED_BUILD_MANIFEST_VERIFIER_ID = "signed-build-manifest-v1";

/** The exact text the approval screen renders in red when a signature is bad. */
export const SIGNATURE_FAILURE_WARNING = "SIGNATURE VERIFICATION FAILED";

function isSignedBuildManifest(evidence: Evidence): evidence is SignedBuildManifestEvidence {
  return evidence.type === SIGNED_BUILD_MANIFEST_VERIFIER_ID;
}

function findManifest(evidence: readonly Evidence[]): SignedBuildManifestEvidence | null {
  for (const item of evidence) {
    if (isSignedBuildManifest(item)) return item;
  }
  return null;
}

function findSigner(signers: readonly TrustedSigner[], fingerprint: string): TrustedSigner | null {
  for (const signer of signers) {
    if (signer.fingerprint === fingerprint) return signer;
  }
  return null;
}

/**
 * Compare one verified fact against the matching workload claim. A claim the
 * workload did not send leaves `matchesClaim` null rather than false: nothing
 * disagreed, there was simply nothing to compare.
 */
function fact(key: string, value: string, claim: string | undefined): VerificationFact {
  return { key, value, matchesClaim: claim === undefined ? null : claim === value };
}

function unavailable(warning: string): VerificationResult {
  return {
    verifier: SIGNED_BUILD_MANIFEST_VERIFIER_ID,
    status: "UNAVAILABLE",
    facts: [],
    warnings: [warning],
  };
}

/**
 * Verifier B from spec section 27: a provider-neutral statement, signed by a
 * trusted CI key, that a source commit produced an artifact digest.
 *
 * UNAVAILABLE when no manifest was supplied, UNVERIFIED when the signer is not
 * trusted here, FAILED when the signature does not verify, VERIFIED otherwise.
 * A VERIFIED result still reports every claim mismatch as a fact and a warning,
 * because a valid signature over a different artifact is not an approval.
 */
export const signedBuildManifestVerifier: ProvenanceVerifier = {
  id: SIGNED_BUILD_MANIFEST_VERIFIER_ID,
  async verify(input: VerifierInput): Promise<VerificationResult> {
    const evidence = findManifest(input.evidence);
    if (evidence === null) {
      return unavailable("no signed build manifest was supplied with this boot");
    }
    const signer = findSigner(input.signers, evidence.signerFingerprint);
    if (signer === null) {
      return {
        verifier: SIGNED_BUILD_MANIFEST_VERIFIER_ID,
        status: "UNVERIFIED",
        facts: [],
        warnings: [
          `the manifest was signed by ${evidence.signerFingerprint}, which this environment does not trust`,
        ],
      };
    }

    const node = signedBuildManifestNode(evidence.manifest);
    const valid = await verifyManifest({
      publicKey: b64uDecode(signer.publicKey),
      manifest: node,
      signature: evidence.signature,
    });
    if (!valid) {
      return {
        verifier: SIGNED_BUILD_MANIFEST_VERIFIER_ID,
        status: "FAILED",
        facts: [],
        warnings: [SIGNATURE_FAILURE_WARNING],
      };
    }

    const manifest = evidence.manifest;
    const facts: VerificationFact[] = [
      fact("source.repository", manifest.source.repository, input.claims.git?.repository),
      fact("source.commit", manifest.source.commit, input.claims.git?.commit),
      fact("artifact.repository", manifest.artifact.repository, input.claims.oci?.repository),
      fact("artifact.digest", manifest.artifact.digest, input.claims.oci?.digest),
      { key: "builder", value: manifest.builder, matchesClaim: null },
      { key: "signer.label", value: signer.label, matchesClaim: null },
      { key: "signer.fingerprint", value: signer.fingerprint, matchesClaim: null },
    ];
    const warnings = facts
      .filter((entry) => entry.matchesClaim === false)
      .map((entry) => `${entry.key} in the manifest does not match the workload claim`);

    return {
      verifier: SIGNED_BUILD_MANIFEST_VERIFIER_ID,
      status: "VERIFIED",
      facts,
      warnings,
    };
  },
};
