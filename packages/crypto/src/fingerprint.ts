/**
 * SHA-256 helpers and the public-key fingerprint used on the wire and in storage.
 */

import { hexEncode, utf8Encode, type Bytes } from "./encoding.ts";

/** SHA-256 of raw bytes. */
export async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

/** Lowercase hex SHA-256 of raw bytes. */
export async function sha256Hex(bytes: Bytes): Promise<string> {
  return hexEncode(await sha256(bytes));
}

/** Lowercase hex SHA-256 of the UTF-8 bytes of a string. */
export async function sha256HexOfText(text: string): Promise<string> {
  return await sha256Hex(utf8Encode(text));
}

/**
 * Key fingerprint: lowercase hex SHA-256 over the raw 32-byte public key.
 *
 * The UI may group the hex with colons. The wire and D1 always use plain hex.
 */
export async function keyFingerprint(rawPublicKey: Bytes): Promise<string> {
  return await sha256Hex(rawPublicKey);
}

/** Group a hex fingerprint into colon-separated byte pairs for display. */
export function formatFingerprint(fingerprint: string): string {
  const pairs: string[] = [];
  for (let index = 0; index < fingerprint.length; index += 2) {
    pairs.push(fingerprint.slice(index, index + 2));
  }
  return pairs.join(":");
}
