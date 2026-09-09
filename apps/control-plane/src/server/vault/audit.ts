/**
 * Audit event writing (spec sections 35 and 36).
 *
 * Metadata is a flat map of scalars. There is no nested value and no free-form
 * payload, so a call site cannot smuggle a secret value, a token or key material
 * into the audit log. Record identifiers, fingerprints, versions and counts.
 */

import { appendAuditEvent, type VaultDatabase } from "@keevault/vault-store";

import { generatePrefixedUlidId } from "./ids.ts";

/** Every action name the vault writes (spec section 35). */
export const AUDIT_ACTIONS = [
  "project.created",
  "project.deleted",
  "environment.created",
  "environment.deleted",
  "secret.created",
  "secret.updated",
  "secret.deleted",
  "bootstrap-token.created",
  "bootstrap-token.revoked",
  "bootstrap-token.cidrs-changed",
  "provenance-policy.changed",
  "trusted-signer.added",
  "trusted-signer.revoked",
  "boot.requested",
  "boot.reconnected",
  "boot.approved",
  "boot.declined",
  "boot.expired",
  "boot.delivered",
  "boot.consumed",
  "boot.canceled",
  "project-key.rotated",
  "environment-key.rotated",
  "master-key-rewrapped",
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

/** The only value types audit metadata may hold. */
export type AuditMetadataValue = string | number | boolean | null;

/** Flat, scalar-only metadata. Never plaintext and never key bytes. */
export type AuditMetadata = ReadonlyMap<string, AuditMetadataValue>;

/** Serialise metadata for the `metadata_json` column. */
export function auditMetadataJson(metadata: AuditMetadata): string {
  return JSON.stringify(Object.fromEntries(metadata));
}

/** Who performed the action. */
export type AuditActorType = "user" | "system" | "boot";

export interface AuditActor {
  type: AuditActorType;
  /** Better Auth user id, boot id, or null for the system. */
  id: string | null;
}

export interface WriteAuditEventInput {
  action: AuditAction;
  projectId: string | null;
  environmentId: string | null;
  bootId: string | null;
  metadata: AuditMetadata;
}

export interface AuditWriteContext {
  db: VaultDatabase;
  actor: AuditActor;
  timestamp: string;
}

/** Append one audit event. */
export async function writeAuditEvent(
  context: AuditWriteContext,
  input: WriteAuditEventInput,
): Promise<void> {
  await appendAuditEvent(context.db, {
    id: generatePrefixedUlidId("aud"),
    timestamp: context.timestamp,
    actorType: context.actor.type,
    actorId: context.actor.id,
    action: input.action,
    projectId: input.projectId,
    environmentId: input.environmentId,
    bootId: input.bootId,
    metadataJson: auditMetadataJson(input.metadata),
  });
}
