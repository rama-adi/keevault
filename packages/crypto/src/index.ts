/**
 * @keevault/crypto
 *
 * Web Crypto only. No runtime dependencies. The same source runs in Cloudflare
 * Workers and in Node 22 or newer.
 */

export {
  b64uDecode,
  b64uEncode,
  concatBytes,
  constantTimeEqual,
  constantTimeEqualText,
  hexDecode,
  hexEncode,
  randomBytes,
  utf8Decode,
  utf8Encode,
  type Bytes,
} from "./encoding.ts";

export {
  bootEnvelopeInfo,
  canonicalInteger,
  environmentKeyAad,
  projectKeyAad,
  secretValueAad,
  type BootEnvelopeInfoInput,
  type EnvironmentKeyAadInput,
  type ProjectKeyAadInput,
  type SecretValueAadInput,
} from "./aad.ts";

export {
  aesGcmDecrypt,
  aesGcmEncrypt,
  generateNonce,
  importAesGcmKey,
  AES_KEY_LENGTH,
  AES_NONCE_LENGTH,
  AES_TAG_LENGTH,
  type AesGcmDecryptInput,
  type AesGcmEncryptInput,
  type SealedBytes,
} from "./aesgcm.ts";

export {
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  generateX25519PrivateKey,
  importEd25519PrivateKey,
  importEd25519PublicKey,
  importX25519PrivateKey,
  importX25519PublicKey,
  x25519PublicKeyFromPrivate,
  KEY_LENGTH,
  SIGNATURE_LENGTH,
} from "./keys.ts";

export {
  formatFingerprint,
  keyFingerprint,
  sha256,
  sha256Hex,
  sha256HexOfText,
} from "./fingerprint.ts";

export {
  decryptSecret,
  encryptSecret,
  generateKey32,
  unwrapEnvironmentKey,
  unwrapProjectKey,
  wrapEnvironmentKey,
  wrapProjectKey,
  type DecryptSecretInput,
  type EncryptSecretInput,
  type UnwrapEnvironmentKeyInput,
  type UnwrapProjectKeyInput,
  type WrapEnvironmentKeyInput,
  type WrapProjectKeyInput,
} from "./hierarchy.ts";

export {
  createBootEnvelope,
  deriveEnvelopeWrapKey,
  openBootEnvelope,
  ENVELOPE_SALT_LENGTH,
  type BootEnvelope,
  type BootEnvelopeMaterial,
  type CreateBootEnvelopeInput,
  type CreatedBootEnvelope,
  type DeriveEnvelopeWrapKeyInput,
  type OpenBootEnvelopeInput,
} from "./envelope.ts";

export {
  buildResumeMessage,
  generateResumeChallenge,
  signResume,
  verifyResume,
  RESUME_CHALLENGE_LENGTH,
  type SignResumeInput,
  type VerifyResumeInput,
} from "./resume.ts";

export {
  generateBootstrapToken,
  hashTokenSecret,
  parseBootstrapToken,
  verifyTokenSecret,
  BOOTSTRAP_TOKEN_PATTERN,
  BOOTSTRAP_TOKEN_PREFIX,
  BOOTSTRAP_TOKEN_SECRET_BYTES,
  type GeneratedBootstrapToken,
  type ParsedBootstrapToken,
} from "./token.ts";

export {
  ipAllowed,
  ipInCidr,
  normalizeIpAddress,
  parseCidr,
  parseIpAddress,
  parseIpv4,
  parseIpv6,
  type ParsedCidr,
} from "./cidr.ts";

export {
  canonicalizeManifest,
  canonicalizeManifestNode,
  manifestInteger,
  manifestNode,
  manifestSigningMessage,
  manifestText,
  signManifest,
  signedBuildManifestNode,
  verifyManifest,
  MANIFEST_SIGNING_PREFIX,
  MANIFEST_VERSION,
  type ManifestArtifact,
  type ManifestEntry,
  type ManifestInteger,
  type ManifestNode,
  type ManifestSource,
  type ManifestText,
  type ManifestValue,
  type SignManifestInput,
  type SignedBuildManifest,
  type VerifyManifestInput,
} from "./manifest.ts";

export {
  generatePrefixedUlid,
  generateUlid,
  isPrefixedUlid,
  isUlid,
  ULID_LENGTH,
  ULID_PATTERN,
  ULID_PREFIXES,
  type UlidPrefix,
} from "./ulid.ts";
