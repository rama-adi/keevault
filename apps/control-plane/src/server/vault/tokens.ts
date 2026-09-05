/**
 * Bootstrap token lifecycle (spec sections 11, 12 and 38).
 *
 * The plaintext token exists once, in the return value of `createBootstrapToken`.
 * D1 stores only the token id and the SHA-256 of the token secret, and no
 * function here logs or audits either half of the token.
 */

import { generateBootstrapToken, parseCidr } from "@env-vault/crypto";
import {
  createBootstrapToken as createBootstrapTokenRow,
  listBootstrapTokensByEnvironment,
  revokeBootstrapToken as revokeBootstrapTokenRow,
  updateBootstrapTokenCidrs,
} from "@env-vault/vault-store";
import { z } from "zod";

import { writeAuditEvent, type AuditMetadataValue } from "./audit.ts";
import type { VaultContext } from "./context.ts";
import { requireEnvironment } from "./projects.ts";
import { toBootstrapTokenSummary, type BootstrapTokenSummary } from "./types.ts";
import { VaultInputError } from "./validation.ts";

/** Default concurrent pending boots per token (spec section 37). */
export const DEFAULT_MAX_PENDING_BOOTS = 3;

function assertCidrs(cidrs: readonly string[]): void {
  for (const cidr of cidrs) {
    if (parseCidr(cidr) === null) {
      throw new VaultInputError("allowedCidrs", `${cidr} is not a valid IPv4 or IPv6 CIDR.`);
    }
  }
}

export async function listBootstrapTokens(
  context: VaultContext,
  environmentId: string,
): Promise<BootstrapTokenSummary[]> {
  return (await listBootstrapTokensByEnvironment(context.db, environmentId)).map(
    toBootstrapTokenSummary,
  );
}

export interface CreateBootstrapTokenInput {
  environmentId: string;
  label: string;
  allowedCidrs: readonly string[];
  /** RFC 3339, or null for a token that does not expire on its own. */
  expiresAt: string | null;
  maxPendingBoots: number;
}

/** The one and only time the plaintext token is available. */
export interface CreatedBootstrapToken {
  /** Show once, never store, never log. */
  token: string;
  summary: BootstrapTokenSummary;
}

export async function createBootstrapToken(
  context: VaultContext,
  input: CreateBootstrapTokenInput,
): Promise<CreatedBootstrapToken> {
  const environment = await requireEnvironment(context, input.environmentId);
  assertCidrs(input.allowedCidrs);
  const minted = await generateBootstrapToken();
  const now = context.now();

  const row = await createBootstrapTokenRow(context.db, {
    id: `tok_${minted.tokenId}`,
    environmentId: input.environmentId,
    label: input.label,
    tokenHash: minted.secretHash,
    allowedCidrsJson: JSON.stringify([...input.allowedCidrs]),
    maxPendingBoots: input.maxPendingBoots,
    expiresAt: input.expiresAt,
    now,
  });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "bootstrap-token.created",
      projectId: environment.projectId,
      environmentId: input.environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["tokenId", row.id],
        ["label", input.label],
        ["cidrCount", input.allowedCidrs.length],
        ["maxPendingBoots", input.maxPendingBoots],
        ["expiresAt", input.expiresAt],
      ]),
    },
  );
  return { token: minted.token, summary: toBootstrapTokenSummary(row) };
}

/**
 * Revoke a token. Cancelling the boots it opened is the Durable Object's job;
 * this marks the row so no new socket authenticates (spec section 38).
 */
export async function revokeBootstrapToken(
  context: VaultContext,
  tokenRowId: string,
): Promise<void> {
  const token = await requireToken(context, tokenRowId);
  const environment = await requireEnvironment(context, token.environmentId);
  const now = context.now();
  await revokeBootstrapTokenRow(context.db, { tokenRowId, now });
  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "bootstrap-token.revoked",
      projectId: environment.projectId,
      environmentId: token.environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["tokenId", tokenRowId],
        ["label", token.label],
      ]),
    },
  );
}

export interface UpdateTokenCidrsInput {
  tokenRowId: string;
  allowedCidrs: readonly string[];
}

export async function updateTokenCidrs(
  context: VaultContext,
  input: UpdateTokenCidrsInput,
): Promise<BootstrapTokenSummary> {
  const token = await requireToken(context, input.tokenRowId);
  const environment = await requireEnvironment(context, token.environmentId);
  assertCidrs(input.allowedCidrs);
  const now = context.now();
  const row = await updateBootstrapTokenCidrs(context.db, {
    tokenRowId: input.tokenRowId,
    allowedCidrsJson: JSON.stringify([...input.allowedCidrs]),
  });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "bootstrap-token.cidrs-changed",
      projectId: environment.projectId,
      environmentId: token.environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["tokenId", input.tokenRowId],
        ["previousCidrCount", token.allowedCidrs.length],
        ["cidrCount", input.allowedCidrs.length],
      ]),
    },
  );
  return toBootstrapTokenSummary(row);
}

async function requireToken(
  context: VaultContext,
  tokenRowId: string,
): Promise<BootstrapTokenSummary> {
  const environmentId = await findTokenEnvironment(context, tokenRowId);
  const tokens = await listBootstrapTokens(context, environmentId);
  const token = tokens.find((candidate) => candidate.id === tokenRowId);
  if (token === undefined) {
    throw new VaultInputError("tokenId", `Token ${tokenRowId} does not exist.`);
  }
  return token;
}

const tokenEnvironmentSchema = z.object({ environmentId: z.string() });

async function findTokenEnvironment(context: VaultContext, tokenRowId: string): Promise<string> {
  const row = await context.db
    .prepare("SELECT environment_id AS environmentId FROM bootstrap_tokens WHERE id = ?")
    .bind(tokenRowId)
    .first<{ environmentId: string }>();
  if (row === null) {
    throw new VaultInputError("tokenId", `Token ${tokenRowId} does not exist.`);
  }
  return tokenEnvironmentSchema.parse(row).environmentId;
}
