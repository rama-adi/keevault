import {
  b64uEncode,
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  keyFingerprint,
  signManifest,
  signedBuildManifestNode,
} from "@keevault/crypto";
import type { SignedBuildManifestEvidence, WorkloadClaims } from "@keevault/protocol";
import { describe, expect, it } from "vite-plus/test";

import { claimsOnlyVerifier } from "./claims-only.ts";
import { evaluatePolicy } from "./policy.ts";
import {
  SIGNATURE_FAILURE_WARNING,
  SIGNED_BUILD_MANIFEST_VERIFIER_ID,
  signedBuildManifestVerifier,
} from "./signed-build-manifest.ts";
import { canonicalSummary, summaryDigest } from "./summary.ts";
import type { TrustedSigner, VerificationResult } from "./types.ts";

const COMMIT = "a".repeat(40);
const DIGEST = `sha256:${"b".repeat(64)}`;
const ENVIRONMENT_ID = "env_01JQ8Z5K7N2P4R6T8V0X2Z4A6C";

const CLAIMS: WorkloadClaims = {
  git: { repository: "github.com/acme/foo", commit: COMMIT },
  oci: { repository: "ghcr.io/acme/foo", digest: DIGEST },
  provider: { name: "zeabur", deploymentId: "dep-1234" },
};

interface SignedEvidence {
  evidence: SignedBuildManifestEvidence;
  signer: TrustedSigner;
}

async function buildEvidence(
  repository = "github.com/acme/foo",
  digest = DIGEST,
): Promise<SignedEvidence> {
  const seed = generateEd25519Seed();
  const publicKey = await ed25519PublicKeyFromSeed(seed);
  const fingerprint = await keyFingerprint(publicKey);
  const manifest = {
    version: 1,
    source: { repository, commit: COMMIT },
    artifact: { type: "oci", repository: "ghcr.io/acme/foo", digest },
    builder: "acme-ci",
    issuedAt: "2026-09-05T10:00:00.000Z",
  } as const;
  const signature = await signManifest({ seed, manifest: signedBuildManifestNode(manifest) });
  return {
    evidence: {
      type: SIGNED_BUILD_MANIFEST_VERIFIER_ID,
      manifest,
      signature,
      signerFingerprint: fingerprint,
    },
    signer: {
      id: "sig_01JQ8Z5K7N2P4R6T8V0X2Z4A6C",
      label: "acme-ci-prod",
      publicKey: b64uEncode(publicKey),
      fingerprint,
      type: "ed25519",
    },
  };
}

function tamper(signature: string): string {
  const first = signature.slice(0, 1);
  return `${first === "A" ? "B" : "A"}${signature.slice(1)}`;
}

describe("claimsOnlyVerifier", () => {
  it("normalises claims and never reports more than UNVERIFIED", async () => {
    const result = await claimsOnlyVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: CLAIMS,
      evidence: [],
      signers: [],
    });

    expect(result.status).toBe("UNVERIFIED");
    expect(result.facts.map((entry) => entry.key)).toStrictEqual([
      "source.repository",
      "source.commit",
      "artifact.repository",
      "artifact.digest",
      "provider.name",
      "provider.deploymentId",
    ]);
    expect(result.facts.every((entry) => entry.matchesClaim === null)).toBe(true);
  });

  it("still returns UNVERIFIED when the workload sent nothing", async () => {
    const result = await claimsOnlyVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: {},
      evidence: [],
      signers: [],
    });

    expect(result.status).toBe("UNVERIFIED");
    expect(result.facts).toStrictEqual([]);
  });
});

describe("signedBuildManifestVerifier", () => {
  it("verifies a good manifest and reports each claim match as a fact", async () => {
    const signed = await buildEvidence();

    const result = await signedBuildManifestVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: CLAIMS,
      evidence: [signed.evidence],
      signers: [signed.signer],
    });

    expect(result.status).toBe("VERIFIED");
    expect(result.warnings).toStrictEqual([]);
    const matches = new Map(result.facts.map((entry) => [entry.key, entry.matchesClaim]));
    expect(matches.get("source.repository")).toBe(true);
    expect(matches.get("source.commit")).toBe(true);
    expect(matches.get("artifact.repository")).toBe(true);
    expect(matches.get("artifact.digest")).toBe(true);
    const values = new Map(result.facts.map((entry) => [entry.key, entry.value]));
    expect(values.get("signer.label")).toBe("acme-ci-prod");
  });

  it("reports FAILED for a tampered signature", async () => {
    const signed = await buildEvidence();
    const evidence: SignedBuildManifestEvidence = {
      ...signed.evidence,
      signature: tamper(signed.evidence.signature),
    };

    const result = await signedBuildManifestVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: CLAIMS,
      evidence: [evidence],
      signers: [signed.signer],
    });

    expect(result.status).toBe("FAILED");
    expect(result.warnings).toContain(SIGNATURE_FAILURE_WARNING);
  });

  it("reports UNVERIFIED when the signer is unknown to the environment", async () => {
    const signed = await buildEvidence();

    const result = await signedBuildManifestVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: CLAIMS,
      evidence: [signed.evidence],
      signers: [],
    });

    expect(result.status).toBe("UNVERIFIED");
    expect(result.warnings[0]).toContain("does not trust");
  });

  it("reports UNAVAILABLE when no manifest was supplied", async () => {
    const result = await signedBuildManifestVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: CLAIMS,
      evidence: [],
      signers: [],
    });

    expect(result.status).toBe("UNAVAILABLE");
    expect(result.facts).toStrictEqual([]);
  });

  it("reports a mismatch between the claim and the signed manifest", async () => {
    const signed = await buildEvidence("github.com/attacker/foo");

    const result = await signedBuildManifestVerifier.verify({
      environmentId: ENVIRONMENT_ID,
      claims: CLAIMS,
      evidence: [signed.evidence],
      signers: [signed.signer],
    });

    expect(result.status).toBe("VERIFIED");
    const repository = result.facts.find((entry) => entry.key === "source.repository");
    expect(repository?.matchesClaim).toBe(false);
    expect(result.warnings).toContain(
      "source.repository in the manifest does not match the workload claim",
    );
  });
});

function result(
  verifier: string,
  status: VerificationResult["status"],
  matchesClaim: boolean | null = null,
): VerificationResult {
  return {
    verifier,
    status,
    facts: [{ key: "artifact.digest", value: DIGEST, matchesClaim }],
    warnings: [],
  };
}

describe("evaluatePolicy", () => {
  const required = [
    { verifierType: SIGNED_BUILD_MANIFEST_VERIFIER_ID, required: true, enabled: true },
  ];

  it("never blocks under OFF or ADVISORY", () => {
    const results = [result(SIGNED_BUILD_MANIFEST_VERIFIER_ID, "FAILED")];

    expect(evaluatePolicy("OFF", results, required).approvable).toBe(true);
    expect(evaluatePolicy("ADVISORY", results, required)).toStrictEqual({
      approvable: true,
      blockers: [],
    });
  });

  it("allows approval under REQUIRED when the verifier is VERIFIED and matches", () => {
    const results = [result(SIGNED_BUILD_MANIFEST_VERIFIER_ID, "VERIFIED", true)];

    expect(evaluatePolicy("REQUIRED", results, required)).toStrictEqual({
      approvable: true,
      blockers: [],
    });
  });

  it("blocks under REQUIRED for every status other than VERIFIED", () => {
    for (const status of ["UNVERIFIED", "FAILED", "UNAVAILABLE"] as const) {
      const evaluation = evaluatePolicy(
        "REQUIRED",
        [result(SIGNED_BUILD_MANIFEST_VERIFIER_ID, status, true)],
        required,
      );
      expect(evaluation.approvable).toBe(false);
      expect(evaluation.blockers[0]).toContain(status);
    }
  });

  it("blocks under REQUIRED when a required verifier did not run", () => {
    const evaluation = evaluatePolicy("REQUIRED", [result("claims-only", "UNVERIFIED")], required);

    expect(evaluation.approvable).toBe(false);
    expect(evaluation.blockers[0]).toContain("did not run");
  });

  it("blocks under REQUIRED when a verified fact contradicts a claim", () => {
    const evaluation = evaluatePolicy(
      "REQUIRED",
      [result(SIGNED_BUILD_MANIFEST_VERIFIER_ID, "VERIFIED", false)],
      required,
    );

    expect(evaluation.approvable).toBe(false);
    expect(evaluation.blockers[0]).toContain("does not match the workload claim");
  });

  it("still demands a VERIFIED result under REQUIRED with no configured rows", () => {
    expect(evaluatePolicy("REQUIRED", [result("claims-only", "UNVERIFIED")], []).approvable).toBe(
      false,
    );
    expect(
      evaluatePolicy("REQUIRED", [result("claims-only", "VERIFIED", true)], []).approvable,
    ).toBe(true);
  });
});

describe("summaryDigest", () => {
  it("sorts keys and is stable across equal summaries", async () => {
    const results = [result("claims-only", "UNVERIFIED")];

    expect(canonicalSummary(results)).toBe(
      `{"results":[{"facts":[{"key":"artifact.digest","matchesClaim":null,"value":${JSON.stringify(DIGEST)}}],"status":"UNVERIFIED","verifier":"claims-only","warnings":[]}]}`,
    );
    expect(await summaryDigest(results)).toBe(await summaryDigest([...results]));
    expect(await summaryDigest(results)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when a status changes", async () => {
    const before = await summaryDigest([result("claims-only", "UNVERIFIED")]);
    const after = await summaryDigest([result("claims-only", "VERIFIED")]);

    expect(before).not.toBe(after);
  });
});
