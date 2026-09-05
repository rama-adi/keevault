/**
 * The master -> project -> environment -> secret key hierarchy.
 *
 * Every key is generated independently from the platform CSPRNG. No key is derived
 * from another key. Each wrap binds its identity with an AAD string from aad.ts.
 */

import {
  environmentKeyAad,
  projectKeyAad,
  secretValueAad,
  type EnvironmentKeyAadInput,
  type ProjectKeyAadInput,
  type SecretValueAadInput,
} from "./aad.ts";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  generateNonce,
  AES_KEY_LENGTH,
  type SealedBytes,
} from "./aesgcm.ts";
import { randomBytes, utf8Decode, utf8Encode, type Bytes } from "./encoding.ts";

/** Generate a fresh 256-bit key. */
export function generateKey32(): Bytes {
  return randomBytes(AES_KEY_LENGTH);
}

export interface WrapProjectKeyInput extends ProjectKeyAadInput {
  readonly masterKey: Bytes;
  readonly projectKey: Bytes;
}

/** Wrap a project key under the master key. */
export async function wrapProjectKey(input: WrapProjectKeyInput): Promise<SealedBytes> {
  const nonce = generateNonce();
  const ciphertext = await aesGcmEncrypt({
    key: input.masterKey,
    nonce,
    plaintext: input.projectKey,
    aad: projectKeyAad(input),
  });
  return { nonce, ciphertext };
}

export interface UnwrapProjectKeyInput extends ProjectKeyAadInput {
  readonly masterKey: Bytes;
  readonly nonce: Bytes;
  readonly ciphertext: Bytes;
}

/** Unwrap a project key. Throws if the AAD identity or the tag does not match. */
export async function unwrapProjectKey(input: UnwrapProjectKeyInput): Promise<Bytes> {
  return await aesGcmDecrypt({
    key: input.masterKey,
    nonce: input.nonce,
    ciphertext: input.ciphertext,
    aad: projectKeyAad(input),
  });
}

export interface WrapEnvironmentKeyInput extends EnvironmentKeyAadInput {
  readonly projectKey: Bytes;
  readonly environmentKey: Bytes;
}

/** Wrap an environment key under its project key. */
export async function wrapEnvironmentKey(input: WrapEnvironmentKeyInput): Promise<SealedBytes> {
  const nonce = generateNonce();
  const ciphertext = await aesGcmEncrypt({
    key: input.projectKey,
    nonce,
    plaintext: input.environmentKey,
    aad: environmentKeyAad(input),
  });
  return { nonce, ciphertext };
}

export interface UnwrapEnvironmentKeyInput extends EnvironmentKeyAadInput {
  readonly projectKey: Bytes;
  readonly nonce: Bytes;
  readonly ciphertext: Bytes;
}

/** Unwrap an environment key. Throws if the AAD identity or the tag does not match. */
export async function unwrapEnvironmentKey(input: UnwrapEnvironmentKeyInput): Promise<Bytes> {
  return await aesGcmDecrypt({
    key: input.projectKey,
    nonce: input.nonce,
    ciphertext: input.ciphertext,
    aad: environmentKeyAad(input),
  });
}

export interface EncryptSecretInput extends SecretValueAadInput {
  readonly environmentKey: Bytes;
  readonly value: string;
}

/** Encrypt one secret value under its environment key. */
export async function encryptSecret(input: EncryptSecretInput): Promise<SealedBytes> {
  const nonce = generateNonce();
  const ciphertext = await aesGcmEncrypt({
    key: input.environmentKey,
    nonce,
    plaintext: utf8Encode(input.value),
    aad: secretValueAad(input),
  });
  return { nonce, ciphertext };
}

export interface DecryptSecretInput extends SecretValueAadInput {
  readonly environmentKey: Bytes;
  readonly nonce: Bytes;
  readonly ciphertext: Bytes;
}

/**
 * Decrypt one secret value.
 *
 * A wrong secret name, environment id or version changes the AAD and fails here.
 */
export async function decryptSecret(input: DecryptSecretInput): Promise<string> {
  const plaintext = await aesGcmDecrypt({
    key: input.environmentKey,
    nonce: input.nonce,
    ciphertext: input.ciphertext,
    aad: secretValueAad(input),
  });
  return utf8Decode(plaintext);
}
