/**
 * Bootstrap tokens.
 *
 * Format: `vlt_boot_<tokenId>.<secret>` where tokenId is a bare 26-character ULID and
 * secret is 32 random bytes as b64u (43 characters). D1 stores only the lowercase hex
 * SHA-256 over the UTF-8 bytes of the secret string.
 */

import { b64uEncode, constantTimeEqualText, randomBytes } from "./encoding.ts";
import { sha256HexOfText } from "./fingerprint.ts";
import { generateUlid } from "./ulid.ts";

export const BOOTSTRAP_TOKEN_PREFIX = "vlt_boot_";
export const BOOTSTRAP_TOKEN_SECRET_BYTES = 32;
export const BOOTSTRAP_TOKEN_PATTERN = /^vlt_boot_([0-9A-HJKMNP-TV-Z]{26})\.([A-Za-z0-9_-]{43})$/;

/** A token id and the secret half of the token it belongs to. */
export interface ParsedBootstrapToken {
  readonly tokenId: string;
  readonly secret: string;
}

/** A newly minted token. The plaintext token is shown once and never stored. */
export interface GeneratedBootstrapToken {
  readonly token: string;
  readonly tokenId: string;
  readonly secretHash: string;
}

/** Lowercase hex SHA-256 over the UTF-8 bytes of the 43-character secret. */
export async function hashTokenSecret(secret: string): Promise<string> {
  return await sha256HexOfText(secret);
}

/** Mint a bootstrap token. The caller stores `tokenId` and `secretHash` only. */
export async function generateBootstrapToken(): Promise<GeneratedBootstrapToken> {
  const tokenId = generateUlid();
  const secret = b64uEncode(randomBytes(BOOTSTRAP_TOKEN_SECRET_BYTES));
  return {
    token: `${BOOTSTRAP_TOKEN_PREFIX}${tokenId}.${secret}`,
    tokenId,
    secretHash: await hashTokenSecret(secret),
  };
}

/** Parse a presented token. Returns null when the format does not match exactly. */
export function parseBootstrapToken(token: string): ParsedBootstrapToken | null {
  const match = BOOTSTRAP_TOKEN_PATTERN.exec(token);
  if (match === null) return null;
  const tokenId = match[1];
  const secret = match[2];
  if (tokenId === undefined || secret === undefined) return null;
  return { tokenId, secret };
}

/** Compare a presented secret against a stored hash in constant time. */
export async function verifyTokenSecret(secret: string, storedHash: string): Promise<boolean> {
  return constantTimeEqualText(await hashTokenSecret(secret), storedHash);
}
