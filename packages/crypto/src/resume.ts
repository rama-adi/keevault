/**
 * Resume proof of possession.
 *
 * After a reconnect the server sends a random challenge and the client signs a
 * canonical message with the Ed25519 key it announced in `boot.hello`.
 */

import { b64uDecode, b64uEncode, utf8Encode, type Bytes } from "./encoding.ts";
import { importEd25519PrivateKey, importEd25519PublicKey, SIGNATURE_LENGTH } from "./keys.ts";

export const RESUME_CHALLENGE_LENGTH = 32;

/**
 * The exact bytes the client signs.
 *
 * The challenge is inserted as the b64u text the server sent, not the decoded bytes.
 */
export function buildResumeMessage(bootId: string, challenge: string): string {
  return ["vault-resume:v1", bootId, challenge].join("\n");
}

export interface SignResumeInput {
  readonly seed: Bytes;
  readonly bootId: string;
  readonly challenge: string;
}

/** Sign the resume message. Returns the 64-byte signature as b64u. */
export async function signResume(input: SignResumeInput): Promise<string> {
  const privateKey = await importEd25519PrivateKey(input.seed);
  const signature = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    utf8Encode(buildResumeMessage(input.bootId, input.challenge)),
  );
  return b64uEncode(new Uint8Array(signature));
}

export interface VerifyResumeInput {
  readonly publicKey: Bytes;
  readonly bootId: string;
  readonly challenge: string;
  readonly signature: string;
}

/** Verify a resume signature. Returns false for a wrong boot id, challenge, key or length. */
export async function verifyResume(input: VerifyResumeInput): Promise<boolean> {
  const signature = b64uDecode(input.signature);
  if (signature.length !== SIGNATURE_LENGTH) return false;
  const publicKey = await importEd25519PublicKey(input.publicKey);
  return await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signature,
    utf8Encode(buildResumeMessage(input.bootId, input.challenge)),
  );
}

/** Generate a resume challenge: 32 random bytes as b64u. */
export function generateResumeChallenge(): string {
  const bytes = new Uint8Array(RESUME_CHALLENGE_LENGTH);
  globalThis.crypto.getRandomValues(bytes);
  return b64uEncode(bytes);
}
