/**
 * AES-256-GCM with a 96-bit nonce and the 128-bit tag appended to the ciphertext.
 *
 * This matches the Web Crypto default and Go's `cipher.NewGCM(...).Seal`.
 */

import { randomBytes, utf8Encode, type Bytes } from "./encoding.ts";

export const AES_KEY_LENGTH = 32;
export const AES_NONCE_LENGTH = 12;
export const AES_TAG_LENGTH = 16;

const TAG_BITS = AES_TAG_LENGTH * 8;

/** Generate a fresh 96-bit nonce. */
export function generateNonce(): Bytes {
  return randomBytes(AES_NONCE_LENGTH);
}

/** Import 32 raw key bytes as an AES-GCM key. */
export async function importAesGcmKey(key: Bytes): Promise<CryptoKey> {
  if (key.length !== AES_KEY_LENGTH) {
    throw new Error("AES-GCM key must be 32 bytes");
  }
  return await globalThis.crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export interface AesGcmEncryptInput {
  readonly key: Bytes;
  readonly nonce: Bytes;
  readonly plaintext: Bytes;
  readonly aad: string;
}

/** Encrypt and return ciphertext||tag. */
export async function aesGcmEncrypt(input: AesGcmEncryptInput): Promise<Bytes> {
  if (input.nonce.length !== AES_NONCE_LENGTH) {
    throw new Error("AES-GCM nonce must be 12 bytes");
  }
  const key = await importAesGcmKey(input.key);
  const sealed = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: input.nonce,
      additionalData: utf8Encode(input.aad),
      tagLength: TAG_BITS,
    },
    key,
    input.plaintext,
  );
  return new Uint8Array(sealed);
}

export interface AesGcmDecryptInput {
  readonly key: Bytes;
  readonly nonce: Bytes;
  readonly ciphertext: Bytes;
  readonly aad: string;
}

/** Decrypt ciphertext||tag. Throws if the tag, the nonce or the AAD does not match. */
export async function aesGcmDecrypt(input: AesGcmDecryptInput): Promise<Bytes> {
  if (input.nonce.length !== AES_NONCE_LENGTH) {
    throw new Error("AES-GCM nonce must be 12 bytes");
  }
  if (input.ciphertext.length < AES_TAG_LENGTH) {
    throw new Error("AES-GCM ciphertext is shorter than the tag");
  }
  const key = await importAesGcmKey(input.key);
  const opened = await globalThis.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: input.nonce,
      additionalData: utf8Encode(input.aad),
      tagLength: TAG_BITS,
    },
    key,
    input.ciphertext,
  );
  return new Uint8Array(opened);
}

/** A nonce and the ciphertext||tag it produced. */
export interface SealedBytes {
  readonly nonce: Bytes;
  readonly ciphertext: Bytes;
}
