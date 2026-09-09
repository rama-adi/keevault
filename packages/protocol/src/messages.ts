import { z } from "zod";

import { CLOSE_CODES, PROTOCOL_VERSION } from "./constants.ts";
import {
  B64U_12_BYTES,
  B64U_16_TO_64_BYTES,
  B64U_32_BYTES,
  B64U_48_BYTES,
  B64U_64_BYTES,
  B64U_SECRET_CIPHERTEXT,
  BOOT_ID,
  BUILDER_NAME,
  ENVIRONMENT_ID,
  GIT_COMMIT,
  HEX_SHA256,
  OCI_DIGEST,
  OCI_REPOSITORY,
  PROJECT_ID,
  PROVIDER_IDENTIFIER,
  PROVIDER_REGION,
  REPOSITORY_REFERENCE,
  RFC3339_MILLIS,
  SECRET_ID,
  SECRET_NAME,
  SLUG,
  versionNumber,
} from "./formats.ts";

const bootId = z.string().regex(BOOT_ID);
const timestamp = z.string().regex(RFC3339_MILLIS);
const b64u32Bytes = z.string().regex(B64U_32_BYTES);
const hexDigest = z.string().regex(HEX_SHA256);

/** Workload-supplied git claim. Untrusted. */
export const GitClaim = z.strictObject({
  repository: z.string().regex(REPOSITORY_REFERENCE),
  commit: z.string().regex(GIT_COMMIT),
});

/** Workload-supplied container image claim. Untrusted. */
export const OciClaim = z.strictObject({
  repository: z.string().regex(OCI_REPOSITORY),
  digest: z.string().regex(OCI_DIGEST),
});

/** Workload-supplied hosting provider claim. Untrusted. */
export const ProviderClaim = z.strictObject({
  name: z.string().regex(SLUG),
  deploymentId: z.string().regex(PROVIDER_IDENTIFIER).optional(),
  region: z.string().regex(PROVIDER_REGION).optional(),
});

/** Client-reported executable metadata. This is not runtime attestation. */
export const ClientClaim = z.strictObject({
  version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/),
  os: z.string().regex(/^[a-z0-9]{1,32}$/),
  arch: z.string().regex(/^[a-z0-9]{1,32}$/),
  /** Omitted when the client cannot read its executable. */
  sha256: hexDigest.optional(),
});

/**
 * Everything the workload says about itself. The server stores these, shows
 * them on the approval screen and never treats them as verified.
 */
export const WorkloadClaims = z.strictObject({
  client: ClientClaim.optional(),
  git: GitClaim.optional(),
  oci: OciClaim.optional(),
  provider: ProviderClaim.optional(),
});

/** The payload a CI system signs to state that a commit produced an artifact. */
export const SignedBuildManifestV1 = z.strictObject({
  version: z.literal(1),
  source: z.strictObject({
    repository: z.string().regex(REPOSITORY_REFERENCE),
    commit: z.string().regex(GIT_COMMIT),
  }),
  artifact: z.strictObject({
    type: z.literal("oci"),
    repository: z.string().regex(OCI_REPOSITORY),
    digest: z.string().regex(OCI_DIGEST),
  }),
  builder: z.string().regex(BUILDER_NAME),
  issuedAt: timestamp,
});

/** A signed build manifest and the Ed25519 signature over its canonical bytes. */
export const SignedBuildManifestEvidence = z.strictObject({
  type: z.literal("signed-build-manifest-v1"),
  manifest: SignedBuildManifestV1,
  signature: z.string().regex(B64U_64_BYTES),
  signerFingerprint: hexDigest,
});

/**
 * Evidence this version does not know how to check. The server keeps the item
 * as sent and reports UNAVAILABLE for it.
 */
export const UnknownEvidence = z
  .looseObject({ type: z.string().regex(SLUG) })
  .refine((evidence) => evidence.type !== "signed-build-manifest-v1", {
    error: "malformed signed-build-manifest-v1 evidence",
  });

/** One evidence item attached to a hello. */
export const Evidence = z.union([SignedBuildManifestEvidence, UnknownEvidence]);

/** One encrypted secret record inside boot.approved. */
export const SecretRecord = z.strictObject({
  id: z.string().regex(SECRET_ID),
  name: z.string().regex(SECRET_NAME),
  version: versionNumber,
  envKeyVersion: versionNumber,
  nonce: z.string().regex(B64U_12_BYTES),
  ciphertext: z.string().regex(B64U_SECRET_CIPHERTEXT),
});

/** The X25519 envelope that carries the environment data key to one boot. */
export const KeyEnvelope = z.strictObject({
  serverPublicKey: b64u32Bytes,
  salt: b64u32Bytes,
  nonce: z.string().regex(B64U_12_BYTES),
  ciphertext: z.string().regex(B64U_48_BYTES),
});

/** First frame of a new boot. Opens a boot request on the environment. */
export const BootHello = z.strictObject({
  type: z.literal("boot.hello"),
  protocol: z.literal(PROTOCOL_VERSION),
  bootNonce: z.string().regex(B64U_16_TO_64_BYTES),
  signingPublicKey: b64u32Bytes,
  encryptionPublicKey: b64u32Bytes,
  claims: WorkloadClaims,
  evidence: z.array(Evidence).max(32),
});

/** First frame after a reconnect. Names the boot the client wants back. */
export const BootResume = z.strictObject({
  type: z.literal("boot.resume"),
  protocol: z.literal(PROTOCOL_VERSION),
  bootId,
});

/** Ed25519 signature over the resume message, proving boot key ownership. */
export const BootChallengeResponse = z.strictObject({
  type: z.literal("boot.challenge-response"),
  bootId,
  signature: z.string().regex(B64U_64_BYTES),
});

/** Acknowledgement sent after the client decrypted and validated every record. */
export const BootReceived = z.strictObject({
  type: z.literal("boot.received"),
  bootId,
  payloadDigest: hexDigest,
});

/** The boot was created and is waiting for an approval decision. */
export const BootPending = z.strictObject({
  type: z.literal("boot.pending"),
  bootId,
  expiresAt: timestamp,
});

/** A single-use random challenge the client must sign to finish a resume. */
export const BootChallenge = z.strictObject({
  type: z.literal("boot.challenge"),
  bootId,
  challenge: b64u32Bytes,
});

/** The resume succeeded. The socket is now attached to the boot. */
export const BootResumed = z.strictObject({
  type: z.literal("boot.resumed"),
  bootId,
  status: z.enum(["PENDING", "APPROVED", "DELIVERED"]),
  expiresAt: timestamp,
});

/** The approved payload: the wrapped environment key and every secret record. */
export const BootApproved = z.strictObject({
  type: z.literal("boot.approved"),
  bootId,
  projectId: z.string().regex(PROJECT_ID),
  environmentId: z.string().regex(ENVIRONMENT_ID),
  environmentKeyVersion: versionNumber,
  payloadExpiresAt: timestamp,
  keyEnvelope: KeyEnvelope,
  secrets: z.array(SecretRecord).max(4096),
});

/** An administrator refused the boot. */
export const BootDeclined = z.strictObject({
  type: z.literal("boot.declined"),
  bootId,
  reason: z.string().max(256).optional(),
});

/** The pending or payload TTL elapsed. */
export const BootExpired = z.strictObject({
  type: z.literal("boot.expired"),
  bootId,
});

/** The token was revoked, the environment was deleted, or an admin canceled. */
export const BootCanceled = z.strictObject({
  type: z.literal("boot.canceled"),
  bootId,
  reason: z.string().max(256),
});

/** The acknowledgement was accepted. The boot is finished. */
export const BootConsumed = z.strictObject({
  type: z.literal("boot.consumed"),
  bootId,
});

/** A failure the server reports before closing with the same code. */
export const BootError = z.strictObject({
  type: z.literal("boot.error"),
  code: z.literal([
    CLOSE_CODES.PROTOCOL_ERROR,
    CLOSE_CODES.UNAUTHORIZED,
    CLOSE_CODES.FORBIDDEN,
    CLOSE_CODES.UNKNOWN_BOOT,
    CLOSE_CODES.CONFLICT,
    CLOSE_CODES.TERMINAL,
    CLOSE_CODES.RATE_LIMITED,
  ]),
  message: z.string().min(1).max(512),
});

/** Every frame a client may send. */
export const ClientMessage = z.discriminatedUnion("type", [
  BootHello,
  BootResume,
  BootChallengeResponse,
  BootReceived,
]);

/** Every frame a server may send. */
export const ServerMessage = z.discriminatedUnion("type", [
  BootPending,
  BootChallenge,
  BootResumed,
  BootApproved,
  BootDeclined,
  BootExpired,
  BootCanceled,
  BootConsumed,
  BootError,
]);

export type GitClaim = z.infer<typeof GitClaim>;
export type ClientClaim = z.infer<typeof ClientClaim>;
export type OciClaim = z.infer<typeof OciClaim>;
export type ProviderClaim = z.infer<typeof ProviderClaim>;
export type WorkloadClaims = z.infer<typeof WorkloadClaims>;
export type SignedBuildManifestV1 = z.infer<typeof SignedBuildManifestV1>;
export type SignedBuildManifestEvidence = z.infer<typeof SignedBuildManifestEvidence>;
export type UnknownEvidence = z.infer<typeof UnknownEvidence>;
export type Evidence = z.infer<typeof Evidence>;
export type SecretRecord = z.infer<typeof SecretRecord>;
export type KeyEnvelope = z.infer<typeof KeyEnvelope>;
export type BootHello = z.infer<typeof BootHello>;
export type BootResume = z.infer<typeof BootResume>;
export type BootChallengeResponse = z.infer<typeof BootChallengeResponse>;
export type BootReceived = z.infer<typeof BootReceived>;
export type BootPending = z.infer<typeof BootPending>;
export type BootChallenge = z.infer<typeof BootChallenge>;
export type BootResumed = z.infer<typeof BootResumed>;
export type BootApproved = z.infer<typeof BootApproved>;
export type BootDeclined = z.infer<typeof BootDeclined>;
export type BootExpired = z.infer<typeof BootExpired>;
export type BootCanceled = z.infer<typeof BootCanceled>;
export type BootConsumed = z.infer<typeof BootConsumed>;
export type BootError = z.infer<typeof BootError>;
export type ClientMessage = z.infer<typeof ClientMessage>;
export type ServerMessage = z.infer<typeof ServerMessage>;
