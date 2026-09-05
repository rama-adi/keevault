import { z } from "zod";

/**
 * Field formats for protocol v1. Every binary value on the wire is base64url
 * without padding (RFC 4648 section 5), written b64u below. Digests are
 * lowercase hex. Timestamps are RFC 3339 UTC with exactly three fractional
 * digits.
 *
 * A b64u string of n bytes is ceil(n * 8 / 6) characters long. When 6 times
 * that count exceeds 8n the final character carries zero bits in its low end,
 * so the last character comes from a restricted set: two slack bits for 32
 * byte values, four slack bits for 64 byte values.
 */

const B64U_CHARS = "[A-Za-z0-9_-]";

/** b64u of exactly 32 bytes, such as a public key or a salt. */
export const B64U_32_BYTES = new RegExp(`^${B64U_CHARS}{42}[AEIMQUYcgkosw048]$`);

/** b64u of exactly 12 bytes, the AES-GCM nonce. */
export const B64U_12_BYTES = new RegExp(`^${B64U_CHARS}{16}$`);

/** b64u of exactly 64 bytes, an Ed25519 signature. */
export const B64U_64_BYTES = new RegExp(`^${B64U_CHARS}{85}[AQgw]$`);

/** b64u of exactly 48 bytes, the boot envelope ciphertext: 32 byte DEK plus a
 * 16 byte GCM tag. */
export const B64U_48_BYTES = new RegExp(`^${B64U_CHARS}{64}$`);

/** b64u of 16 to 64 bytes, the client boot nonce. */
export const B64U_16_TO_64_BYTES = new RegExp(`^${B64U_CHARS}{22,86}$`);

/** b64u of a secret ciphertext: at least the 16 byte GCM tag, at most a 64 KiB
 * value plus its tag. */
export const B64U_SECRET_CIPHERTEXT = new RegExp(`^${B64U_CHARS}{22,87404}$`);

/** Lowercase hex SHA-256, such as a fingerprint or a payload digest. */
export const HEX_SHA256 = /^[0-9a-f]{64}$/;

/** A git commit as a full SHA-1 or SHA-256 hex digest. */
export const GIT_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/** An OCI content digest. */
export const OCI_DIGEST = /^sha256:[0-9a-f]{64}$/;

/** RFC 3339 UTC with millisecond precision, for example 2026-09-05T10:00:00.000Z. */
export const RFC3339_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Crockford base32 ULID with a boot prefix. */
export const BOOT_ID = /^boot_[0-9A-HJKMNP-TV-Z]{26}$/;

/** Crockford base32 ULID with an environment prefix. */
export const ENVIRONMENT_ID = /^env_[0-9A-HJKMNP-TV-Z]{26}$/;

/** Crockford base32 ULID with a project prefix. */
export const PROJECT_ID = /^proj_[0-9A-HJKMNP-TV-Z]{26}$/;

/** Crockford base32 ULID with a secret prefix. */
export const SECRET_ID = /^sec_[0-9A-HJKMNP-TV-Z]{26}$/;

/** POSIX environment variable name. */
export const SECRET_NAME = /^[A-Z_][A-Z0-9_]{0,255}$/;

/** Lowercase slug, used for provider and verifier names. */
export const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** A source repository reference: printable ASCII without spaces. Both
 * "github.com/acme/foo" and "https://github.com/acme/foo" are accepted. */
export const REPOSITORY_REFERENCE = /^[\x21-\x7E]{1,512}$/;

/** An OCI repository reference such as ghcr.io/acme/foo. */
export const OCI_REPOSITORY = /^[a-z0-9][a-z0-9._:/-]{0,254}$/;

/** A short opaque identifier supplied by a deployment provider. */
export const PROVIDER_IDENTIFIER = /^[\x21-\x7E]{1,128}$/;

/** A provider region name. */
export const PROVIDER_REGION = /^[\x21-\x7E]{1,64}$/;

/** A build system name, spaces allowed. */
export const BUILDER_NAME = /^[\x20-\x7E]{1,128}$/;

/** A version counter for a key or a secret. Decimal, starts at 1. */
export const versionNumber = z.int().min(1).max(2_147_483_647);
