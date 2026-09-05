/**
 * Prefixed ULIDs.
 *
 * 26 characters of Crockford base32: 48 bits of millisecond timestamp followed by
 * 80 random bits. Uniqueness matters more than monotonicity, so no sequence counter
 * is kept between calls.
 */

import { randomBytes } from "./encoding.ts";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export const ULID_LENGTH = 26;
export const ULID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/** The identifier prefixes used across the vault. The stored id is `<prefix>_<ulid>`. */
export const ULID_PREFIXES = ["proj", "env", "sec", "tok", "boot", "aud", "pol", "sig"] as const;

export type UlidPrefix = (typeof ULID_PREFIXES)[number];

function encodeCrockford(value: bigint, length: number): string {
  let remaining = value;
  let out = "";
  for (let index = 0; index < length; index += 1) {
    const digit = Number(remaining & 31n);
    out = CROCKFORD.charAt(digit) + out;
    remaining >>= 5n;
  }
  return out;
}

/** Generate a bare 26-character ULID. */
export function generateUlid(): string {
  const timestamp = BigInt(Date.now()) & 0xffffffffffffn;
  const random = randomBytes(10);
  let randomValue = 0n;
  for (const byte of random) {
    randomValue = (randomValue << 8n) | BigInt(byte);
  }
  return encodeCrockford(timestamp, 10) + encodeCrockford(randomValue, 16);
}

/** Generate a prefixed identifier such as `boot_01K4...`. */
export function generatePrefixedUlid(prefix: UlidPrefix): string {
  return `${prefix}_${generateUlid()}`;
}

/** Return whether a string is a well-formed bare ULID. */
export function isUlid(value: string): boolean {
  return ULID_PATTERN.test(value);
}

/** Return whether a string is a well-formed `<prefix>_<ulid>` identifier. */
export function isPrefixedUlid(prefix: UlidPrefix, value: string): boolean {
  const marker = `${prefix}_`;
  if (!value.startsWith(marker)) return false;
  return isUlid(value.slice(marker.length));
}
