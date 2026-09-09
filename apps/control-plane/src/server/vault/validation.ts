/**
 * Input schemas shared by the vault service and the server functions.
 *
 * Formats come from the engineering brief: slugs, POSIX secret names, prefixed
 * ULIDs, base64url key material and CIDR strings.
 */

import { parseCidr, isPrefixedUlid, type UlidPrefix } from "@keevault/crypto";
import { z } from "zod";

/** Thrown when caller input is well formed JSON but not acceptable to the vault. */
export class VaultInputError extends Error {
  readonly field: string;

  constructor(field: string, message: string) {
    super(message);
    this.name = "VaultInputError";
    this.field = field;
  }
}

export function isVaultInputError(error: Error): error is VaultInputError {
  return error instanceof VaultInputError;
}

export const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const SECRET_NAME_PATTERN = /^[A-Z_][A-Z0-9_]{0,255}$/;

/** Maximum size of one secret value in bytes (engineering brief). */
export const SECRET_VALUE_MAX_BYTES = 64 * 1024;

export const slugSchema = z
  .string()
  .regex(
    SLUG_PATTERN,
    "Use lower-case letters, digits and hyphens, starting with a letter or digit.",
  );

export const displayNameSchema = z.string().trim().min(1).max(128);

export const secretNameSchema = z
  .string()
  .regex(SECRET_NAME_PATTERN, "Use A-Z, 0-9 and underscore, starting with a letter or underscore.");

export const secretValueSchema = z
  .string()
  .max(SECRET_VALUE_MAX_BYTES, "A secret value may be at most 64 KiB.");

function prefixedIdSchema(prefix: UlidPrefix) {
  return z.string().refine((value) => isPrefixedUlid(prefix, value), {
    message: `Expected a ${prefix}_ identifier.`,
  });
}

export const projectIdSchema = prefixedIdSchema("proj");
export const environmentIdSchema = prefixedIdSchema("env");
export const tokenIdSchema = prefixedIdSchema("tok");
export const signerIdSchema = prefixedIdSchema("sig");
export const auditIdSchema = prefixedIdSchema("aud");

export const provenanceModeSchema = z.enum(["OFF", "ADVISORY", "REQUIRED"]);

/** Boot TTL bounds. The defaults are 1800 s pending and 300 s approved. */
export const pendingTtlSecondsSchema = z.number().int().min(60).max(86400);
export const approvedTtlSecondsSchema = z.number().int().min(30).max(3600);

export const maxPendingBootsSchema = z.number().int().min(1).max(64);

/** A single CIDR, checked with the crypto package's parser. */
export const cidrSchema = z.string().refine((value) => parseCidr(value) !== null, {
  message: "Expected an IPv4 or IPv6 CIDR such as 203.0.113.44/32.",
});

export const cidrListSchema = z.array(cidrSchema).max(64);

/** Base64url without padding, decoding to exactly 32 bytes. */
export const publicKeyB64uSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/, "Expected 32 bytes as base64url without padding.");

export const rfc3339Schema = z
  .string()
  .refine((value) => Number.isFinite(Date.parse(value)), { message: "Expected an RFC 3339 time." });
