import {
  b64uDecode,
  createBootEnvelope,
  deriveEnvelopeWrapKey,
  generateX25519PrivateKey,
  type Bytes,
} from "@keevault/crypto";
import type { KeyEnvelope } from "@keevault/protocol";
import { getEnvironment, type KeyMode, type VaultDatabase } from "@keevault/vault-store";

import { unwrapEnvironmentDek, type MasterKeyring } from "./keys.ts";

export interface BootKeyReleaseRequest {
  readonly bootId: string;
  readonly environmentId: string;
  readonly projectId: string;
  readonly keyMode: KeyMode;
  readonly environmentKeyVersion: number;
  readonly recipientPublicKey: string;
}

export type KeyReleaseErrorCode = "cold_key_required" | "key_mismatch" | "environment_missing";

export class KeyReleaseError extends Error {
  readonly code: KeyReleaseErrorCode;

  constructor(code: KeyReleaseErrorCode, message: string) {
    super(message);
    this.name = "KeyReleaseError";
    this.code = code;
  }
}

function requireCloud(request: BootKeyReleaseRequest): void {
  if (request.keyMode !== "CLOUD") {
    throw new KeyReleaseError(
      "cold_key_required",
      `Environment ${request.environmentId} requires cold-key release.`,
    );
  }
}

/** Unwraps the current cloud DEK and returns only its workload-encrypted envelope. */
export async function createCloudKeyRelease(
  db: VaultDatabase,
  keyring: MasterKeyring,
  request: BootKeyReleaseRequest,
): Promise<KeyEnvelope> {
  requireCloud(request);

  const environment = await getEnvironment(db, request.environmentId);
  if (environment === null) {
    throw new KeyReleaseError(
      "environment_missing",
      `Environment ${request.environmentId} does not exist.`,
    );
  }
  if (environment.keyMode !== "CLOUD") {
    throw new KeyReleaseError(
      "cold_key_required",
      `Environment ${request.environmentId} requires cold-key release.`,
    );
  }
  if (
    environment.projectId !== request.projectId ||
    environment.currentEnvKeyVersion !== request.environmentKeyVersion
  ) {
    throw new KeyReleaseError("key_mismatch", "The requested environment key does not match.");
  }

  // Decode before unwrapping so malformed recipient keys fail without touching key material.
  const recipientPublicKey = b64uDecode(request.recipientPublicKey);
  if (recipientPublicKey.length !== 32) {
    throw new KeyReleaseError("key_mismatch", "The recipient public key must be 32 bytes.");
  }
  await deriveEnvelopeWrapKey({
    privateKey: generateX25519PrivateKey(),
    peerPublicKey: recipientPublicKey,
    salt: new Uint8Array(32),
    info: "key-release-recipient-validation",
  });
  let dek: Bytes | undefined;
  try {
    const unwrapped = await unwrapEnvironmentDek(db, keyring, request.environmentId);
    dek = unwrapped.dek;
    if (
      unwrapped.projectId !== request.projectId ||
      unwrapped.version !== request.environmentKeyVersion
    ) {
      throw new KeyReleaseError("key_mismatch", "The requested environment key does not match.");
    }

    const current = await getEnvironment(db, request.environmentId);
    if (
      current === null ||
      current.keyMode !== "CLOUD" ||
      current.projectId !== request.projectId ||
      current.currentEnvKeyVersion !== request.environmentKeyVersion
    ) {
      throw new KeyReleaseError("key_mismatch", "The environment key changed during release.");
    }

    const created = await createBootEnvelope({
      bootId: request.bootId,
      environmentId: request.environmentId,
      environmentKeyVersion: request.environmentKeyVersion,
      environmentKey: dek,
      clientPublicKey: recipientPublicKey,
    });
    return created.envelope;
  } finally {
    dek?.fill(0);
  }
}
