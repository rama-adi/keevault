/**
 * Boot key envelope: delivery of one environment DEK to one boot process.
 *
 * The server generates a fresh X25519 key pair per approval, derives a wrapping key
 * with HKDF-SHA256 over the raw shared secret, and encrypts the DEK with AES-256-GCM
 * using the same info string as the AAD.
 */

import { bootEnvelopeInfo } from "./aad.ts";
import { aesGcmDecrypt, aesGcmEncrypt, AES_NONCE_LENGTH } from "./aesgcm.ts";
import { b64uDecode, b64uEncode, randomBytes, utf8Encode, type Bytes } from "./encoding.ts";
import { keyFingerprint } from "./fingerprint.ts";
import {
  generateX25519PrivateKey,
  importX25519PrivateKey,
  importX25519PublicKey,
  x25519PublicKeyFromPrivate,
  KEY_LENGTH,
} from "./keys.ts";

export const ENVELOPE_SALT_LENGTH = 32;

/** The `keyEnvelope` object as it appears in a `boot.approved` frame. */
export interface BootEnvelope {
  readonly serverPublicKey: string;
  readonly salt: string;
  readonly nonce: string;
  readonly ciphertext: string;
}

export interface DeriveEnvelopeWrapKeyInput {
  readonly privateKey: Bytes;
  readonly peerPublicKey: Bytes;
  readonly salt: Bytes;
  readonly info: string;
}

/**
 * X25519 then HKDF-SHA256 to a 256-bit wrapping key.
 *
 * An all-zero shared secret means the peer sent a low-order point. Reject it.
 */
export async function deriveEnvelopeWrapKey(input: DeriveEnvelopeWrapKeyInput): Promise<Bytes> {
  const privateKey = await importX25519PrivateKey(input.privateKey);
  const peerPublicKey = await importX25519PublicKey(input.peerPublicKey);
  const shared = new Uint8Array(
    await globalThis.crypto.subtle.deriveBits(
      { name: "X25519", public: peerPublicKey },
      privateKey,
      KEY_LENGTH * 8,
    ),
  );
  let sharedBits = 0;
  for (const byte of shared) sharedBits |= byte;
  if (sharedBits === 0) {
    throw new Error("X25519 produced an all-zero shared secret");
  }
  const hkdfKey = await globalThis.crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveBits",
  ]);
  const wrapKey = await globalThis.crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: input.salt, info: utf8Encode(input.info) },
    hkdfKey,
    KEY_LENGTH * 8,
  );
  return new Uint8Array(wrapKey);
}

/** Fixed randomness for a deterministic envelope. Test vectors only; never pass this in production. */
export interface BootEnvelopeMaterial {
  readonly serverPrivateKey: Bytes;
  readonly salt: Bytes;
  readonly nonce: Bytes;
}

export interface CreateBootEnvelopeInput {
  readonly bootId: string;
  readonly environmentId: string;
  readonly environmentKeyVersion: number;
  readonly environmentKey: Bytes;
  readonly clientPublicKey: Bytes;
  readonly material?: BootEnvelopeMaterial;
}

/** The envelope plus the info string it was bound to. */
export interface CreatedBootEnvelope {
  readonly envelope: BootEnvelope;
  readonly info: string;
}

/** Build the `keyEnvelope` for an approved boot. Runs on the server. */
export async function createBootEnvelope(
  input: CreateBootEnvelopeInput,
): Promise<CreatedBootEnvelope> {
  const material = input.material;
  const serverPrivateKey = material?.serverPrivateKey ?? generateX25519PrivateKey();
  const serverPublicKey = await x25519PublicKeyFromPrivate(serverPrivateKey);
  const salt = material?.salt ?? randomBytes(ENVELOPE_SALT_LENGTH);
  const nonce = material?.nonce ?? randomBytes(AES_NONCE_LENGTH);

  const info = bootEnvelopeInfo({
    bootId: input.bootId,
    environmentId: input.environmentId,
    environmentKeyVersion: input.environmentKeyVersion,
    clientPublicKeyFingerprint: await keyFingerprint(input.clientPublicKey),
    serverPublicKeyFingerprint: await keyFingerprint(serverPublicKey),
  });
  const wrapKey = await deriveEnvelopeWrapKey({
    privateKey: serverPrivateKey,
    peerPublicKey: input.clientPublicKey,
    salt,
    info,
  });
  const ciphertext = await aesGcmEncrypt({
    key: wrapKey,
    nonce,
    plaintext: input.environmentKey,
    aad: info,
  });
  return {
    envelope: {
      serverPublicKey: b64uEncode(serverPublicKey),
      salt: b64uEncode(salt),
      nonce: b64uEncode(nonce),
      ciphertext: b64uEncode(ciphertext),
    },
    info,
  };
}

export interface OpenBootEnvelopeInput {
  readonly bootId: string;
  readonly environmentId: string;
  readonly environmentKeyVersion: number;
  readonly clientPrivateKey: Bytes;
  readonly envelope: BootEnvelope;
}

/** Open the envelope with the boot's X25519 private key. Runs on the client. */
export async function openBootEnvelope(input: OpenBootEnvelopeInput): Promise<Bytes> {
  const serverPublicKey = b64uDecode(input.envelope.serverPublicKey);
  const clientPublicKey = await x25519PublicKeyFromPrivate(input.clientPrivateKey);
  const info = bootEnvelopeInfo({
    bootId: input.bootId,
    environmentId: input.environmentId,
    environmentKeyVersion: input.environmentKeyVersion,
    clientPublicKeyFingerprint: await keyFingerprint(clientPublicKey),
    serverPublicKeyFingerprint: await keyFingerprint(serverPublicKey),
  });
  const wrapKey = await deriveEnvelopeWrapKey({
    privateKey: input.clientPrivateKey,
    peerPublicKey: serverPublicKey,
    salt: b64uDecode(input.envelope.salt),
    info,
  });
  return await aesGcmDecrypt({
    key: wrapKey,
    nonce: b64uDecode(input.envelope.nonce),
    ciphertext: b64uDecode(input.envelope.ciphertext),
    aad: info,
  });
}
