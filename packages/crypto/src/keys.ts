/**
 * Ed25519 and X25519 key handling through Web Crypto only.
 *
 * Web Crypto cannot import a raw private scalar, so raw 32-byte private keys are
 * wrapped in the fixed PKCS#8 prefix for their curve before import. The prefixes are
 * constant because the algorithm identifier and the lengths are constant.
 */

import { b64uDecode, concatBytes, randomBytes, type Bytes } from "./encoding.ts";

export const KEY_LENGTH = 32;
export const SIGNATURE_LENGTH = 64;

/** SEQUENCE, version 0, AlgorithmIdentifier 1.3.101.112 (Ed25519), OCTET STRING(34) wrapping OCTET STRING(32). */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** The same envelope with the 1.3.101.110 (X25519) algorithm identifier. */
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function requireKeyLength(key: Bytes, label: string): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`${label} must be ${KEY_LENGTH} bytes`);
  }
}

async function publicKeyBytesFromPrivate(privateKey: CryptoKey): Promise<Bytes> {
  const jwk = await globalThis.crypto.subtle.exportKey("jwk", privateKey);
  const publicComponent = jwk.x;
  if (publicComponent === undefined) {
    throw new Error("private key export is missing its public component");
  }
  return b64uDecode(publicComponent);
}

/** Import a 32-byte Ed25519 seed as a signing key. */
export async function importEd25519PrivateKey(seed: Bytes): Promise<CryptoKey> {
  requireKeyLength(seed, "Ed25519 seed");
  return await globalThis.crypto.subtle.importKey(
    "pkcs8",
    concatBytes([ED25519_PKCS8_PREFIX, seed]),
    { name: "Ed25519" },
    true,
    ["sign"],
  );
}

/** Import a 32-byte Ed25519 public key. */
export async function importEd25519PublicKey(publicKey: Bytes): Promise<CryptoKey> {
  requireKeyLength(publicKey, "Ed25519 public key");
  return await globalThis.crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, true, [
    "verify",
  ]);
}

/** Derive the Ed25519 public key that belongs to a seed. */
export async function ed25519PublicKeyFromSeed(seed: Bytes): Promise<Bytes> {
  return await publicKeyBytesFromPrivate(await importEd25519PrivateKey(seed));
}

/** Import a 32-byte X25519 private scalar. */
export async function importX25519PrivateKey(privateKey: Bytes): Promise<CryptoKey> {
  requireKeyLength(privateKey, "X25519 private key");
  return await globalThis.crypto.subtle.importKey(
    "pkcs8",
    concatBytes([X25519_PKCS8_PREFIX, privateKey]),
    { name: "X25519" },
    true,
    ["deriveBits"],
  );
}

/** Import a 32-byte X25519 public key. */
export async function importX25519PublicKey(publicKey: Bytes): Promise<CryptoKey> {
  requireKeyLength(publicKey, "X25519 public key");
  return await globalThis.crypto.subtle.importKey("raw", publicKey, { name: "X25519" }, true, []);
}

/** Derive the X25519 public key that belongs to a private scalar. */
export async function x25519PublicKeyFromPrivate(privateKey: Bytes): Promise<Bytes> {
  return await publicKeyBytesFromPrivate(await importX25519PrivateKey(privateKey));
}

/** Generate a 32-byte Ed25519 seed. */
export function generateEd25519Seed(): Bytes {
  return randomBytes(KEY_LENGTH);
}

/** Generate a 32-byte X25519 private scalar. */
export function generateX25519PrivateKey(): Bytes {
  return randomBytes(KEY_LENGTH);
}
