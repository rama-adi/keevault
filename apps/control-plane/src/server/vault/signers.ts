/**
 * Trusted signers for signed-build-manifest evidence (spec section 27).
 *
 * A signer is an Ed25519 public key. The key is stored as base64url and looked
 * up by its fingerprint, the lowercase hex SHA-256 of the raw 32 public key
 * bytes. Public keys are not secret, so they may appear in audit metadata.
 */

import { b64uDecode, importEd25519PublicKey, keyFingerprint, KEY_LENGTH } from "@env-vault/crypto";
import {
  addTrustedSigner as addTrustedSignerRow,
  listTrustedSignersForEnvironment,
  revokeTrustedSigner as revokeTrustedSignerRow,
} from "@env-vault/vault-store";

import { writeAuditEvent, type AuditMetadataValue } from "./audit.ts";
import type { VaultContext } from "./context.ts";
import { generatePrefixedUlidId } from "./ids.ts";
import { requireEnvironment } from "./projects.ts";
import { toTrustedSignerSummary, type TrustedSignerSummary } from "./types.ts";
import { VaultInputError } from "./validation.ts";

/** The only signer type V1 verifies. */
export const SIGNER_TYPE_ED25519 = "ed25519";

export async function listTrustedSigners(
  context: VaultContext,
  environmentId: string,
): Promise<TrustedSignerSummary[]> {
  return (await listTrustedSignersForEnvironment(context.db, environmentId)).map(
    toTrustedSignerSummary,
  );
}

export interface AddTrustedSignerInput {
  environmentId: string;
  label: string;
  /** Raw 32-byte Ed25519 public key, base64url without padding. */
  publicKey: string;
  /** True to trust the signer across every environment in the project. */
  projectWide: boolean;
}

/** Register an Ed25519 signer. The key is checked before it is stored. */
export async function addTrustedSigner(
  context: VaultContext,
  input: AddTrustedSignerInput,
): Promise<TrustedSignerSummary> {
  const environment = await requireEnvironment(context, input.environmentId);
  const fingerprint = await validateEd25519PublicKey(input.publicKey);
  const now = context.now();

  const row = await addTrustedSignerRow(context.db, {
    id: generatePrefixedUlidId("sig"),
    projectId: input.projectWide ? environment.projectId : null,
    environmentId: input.projectWide ? null : input.environmentId,
    type: SIGNER_TYPE_ED25519,
    label: input.label,
    publicKey: input.publicKey,
    fingerprint,
    now,
  });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "trusted-signer.added",
      projectId: environment.projectId,
      environmentId: input.projectWide ? null : input.environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["signerId", row.id],
        ["label", input.label],
        ["fingerprint", fingerprint],
        ["scope", input.projectWide ? "project" : "environment"],
      ]),
    },
  );
  return toTrustedSignerSummary(row);
}

export interface RevokeTrustedSignerInput {
  environmentId: string;
  signerId: string;
}

export async function revokeTrustedSigner(
  context: VaultContext,
  input: RevokeTrustedSignerInput,
): Promise<void> {
  const environment = await requireEnvironment(context, input.environmentId);
  const signers = await listTrustedSigners(context, input.environmentId);
  const signer = signers.find((candidate) => candidate.id === input.signerId);
  if (signer === undefined) {
    throw new VaultInputError("signerId", `Signer ${input.signerId} does not exist here.`);
  }
  const now = context.now();
  await revokeTrustedSignerRow(context.db, { signerId: input.signerId, now });
  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "trusted-signer.revoked",
      projectId: environment.projectId,
      environmentId: signer.environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["signerId", signer.id],
        ["label", signer.label],
        ["fingerprint", signer.fingerprint],
      ]),
    },
  );
}

/** Decode, import and fingerprint a public key. Throws `VaultInputError` if it is not one. */
async function validateEd25519PublicKey(encoded: string): Promise<string> {
  let raw;
  try {
    raw = b64uDecode(encoded);
  } catch {
    throw new VaultInputError("publicKey", "The public key is not valid base64url.");
  }
  if (raw.length !== KEY_LENGTH) {
    throw new VaultInputError("publicKey", "An Ed25519 public key is 32 bytes.");
  }
  try {
    await importEd25519PublicKey(raw);
  } catch {
    throw new VaultInputError("publicKey", "Those bytes are not an Ed25519 public key.");
  }
  return await keyFingerprint(raw);
}
