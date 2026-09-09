/**
 * Server functions for the approval workflow (spec phase 8).
 *
 * The dashboard reads the D1 index, which is a projection, and then reconciles
 * every row against the Durable Object, which is authoritative (spec section
 * 20). A row that says PENDING while the object says EXPIRED is refreshed here
 * so the operator never sees a boot they cannot approve.
 */

import { ipAllowed } from "@keevault/crypto";
import type { BootStatus, ClientClaim } from "@keevault/protocol";
import {
  fromD1,
  getBootRequest,
  getBootstrapTokenByTokenId,
  getEnvironment,
  getProjectById,
  listEnvironmentsByProject,
  listPendingBootRequestsByEnvironment,
  listProjects,
  updateBootRequestStatus,
  type ProvenanceMode,
  type VaultDatabase,
} from "@keevault/vault-store";
import { createServerFn } from "@tanstack/react-start";
import { env } from "cloudflare:workers";
import { z } from "zod";

import { requireRecentPasskey, requireRole, requireSession } from "../auth/guards.ts";
import type { BootActionResult, BootView } from "../durable-objects/boot-session-core.ts";
import {
  evaluatePolicy,
  loadProvenanceContext,
  summaryDigest,
  type PolicyEvaluation,
  type VerificationResult,
} from "../provenance/index.ts";
import { guarded } from "./guarded.ts";

const bootIdSchema = z.string().regex(/^boot_[0-9A-HJKMNP-TV-Z]{26}$/, "That is not a boot id.");
const reasonSchema = z.string().trim().max(256);

/** One live boot as the pending list renders it. */
export interface BootSummary {
  bootId: string;
  status: BootStatus;
  projectId: string;
  projectName: string;
  environmentId: string;
  environmentName: string;
  tokenId: string;
  tokenLabel: string;
  sourceIp: string | null;
  signingFingerprint: string;
  encryptionFingerprint: string;
  claimedGitRepository: string | null;
  claimedGitCommit: string | null;
  claimedOciRepository: string | null;
  claimedOciDigest: string | null;
  createdAt: string;
  pendingExpiresAt: string | null;
  connected: boolean;
}

/** Pending boots for one environment, which is how the list is grouped. */
export interface PendingBootGroup {
  projectId: string;
  projectName: string;
  environmentId: string;
  environmentName: string;
  provenanceMode: ProvenanceMode;
  boots: BootSummary[];
  /** Live boots per bootstrap token. More than one is worth flagging (spec section 37). */
  liveBootsByToken: Array<{ tokenId: string; tokenLabel: string; count: number }>;
}

/** Everything the approval screen renders (spec section 34). */
export interface BootDetail {
  summary: BootSummary;
  claimedClient: ClientClaim | null;
  claimedProviderName: string | null;
  claimedProviderDeploymentId: string | null;
  cidrPolicySatisfied: boolean;
  cidrPolicyConfigured: boolean;
  provenanceMode: ProvenanceMode;
  results: VerificationResult[];
  evaluation: PolicyEvaluation;
  /** The digest the approver must send back with their decision. */
  evidenceDigest: string;
  payloadExpiresAt: string | null;
  terminalReason: string | null;
}

/** The outcome of an approve, decline or cancel. A conflict is data, not a throw. */
export interface BootActionOutcome {
  ok: boolean;
  status: BootStatus | null;
  reason: string | null;
  message: string | null;
}

function stubFor(environmentId: string) {
  return env.ENVIRONMENT_SESSION.get(env.ENVIRONMENT_SESSION.idFromName(environmentId));
}

/**
 * Find which environment a boot belongs to.
 *
 * The caller sends a boot id only. The environment comes from the index row, so
 * a caller cannot aim an approval at a Durable Object of their choosing.
 */
async function environmentOf(db: VaultDatabase, bootId: string): Promise<string | null> {
  const row = await getBootRequest(db, bootId);
  return row === null ? null : row.environmentId;
}

const NOT_FOUND: BootActionOutcome = {
  ok: false,
  status: null,
  reason: "not_found",
  message: "That boot is unknown.",
};

function outcome(result: BootActionResult): BootActionOutcome {
  if (result.ok) {
    return { ok: true, status: result.status, reason: null, message: null };
  }
  return { ok: false, status: null, reason: result.reason, message: result.message };
}

const STAMP_FOR: ReadonlyMap<BootStatus, string> = new Map([
  ["APPROVED", "approved"],
  ["DECLINED", "declined"],
  ["DELIVERED", "delivered"],
  ["CONSUMED", "consumed"],
  ["EXPIRED", "expired"],
  ["CANCELED", "canceled"],
]);

/** Bring one index row in line with the authoritative object. */
async function refreshIndexRow(
  db: VaultDatabase,
  bootId: string,
  status: BootStatus,
): Promise<void> {
  const now = new Date().toISOString();
  const stamp = STAMP_FOR.get(status) ?? "";
  await updateBootRequestStatus(db, {
    bootId,
    status,
    now,
    approvedAt: stamp === "approved" ? now : null,
    declinedAt: stamp === "declined" ? now : null,
    deliveredAt: stamp === "delivered" ? now : null,
    consumedAt: stamp === "consumed" ? now : null,
    expiredAt: stamp === "expired" ? now : null,
    canceledAt: stamp === "canceled" ? now : null,
  });
}

interface Labels {
  projectId: string;
  projectName: string;
  environmentName: string;
  tokenLabel: string;
}

async function loadLabels(
  db: VaultDatabase,
  environmentId: string,
  tokenId: string,
): Promise<Labels | null> {
  const environment = await getEnvironment(db, environmentId);
  if (environment === null) return null;
  const project = await getProjectById(db, environment.projectId);
  const token = await getBootstrapTokenByTokenId(db, tokenId.replace(/^tok_/, ""));
  return {
    projectId: environment.projectId,
    projectName: project?.name ?? environment.projectId,
    environmentName: environment.name,
    tokenLabel: token?.label ?? tokenId,
  };
}

function toSummary(view: BootView, labels: Labels): BootSummary {
  return {
    bootId: view.bootId,
    status: view.status,
    projectId: labels.projectId,
    projectName: labels.projectName,
    environmentId: view.environmentId,
    environmentName: labels.environmentName,
    tokenId: view.tokenId,
    tokenLabel: labels.tokenLabel,
    sourceIp: view.sourceIp,
    signingFingerprint: view.signingFingerprint,
    encryptionFingerprint: view.encryptionFingerprint,
    claimedGitRepository: view.claims.git?.repository ?? null,
    claimedGitCommit: view.claims.git?.commit ?? null,
    claimedOciRepository: view.claims.oci?.repository ?? null,
    claimedOciDigest: view.claims.oci?.digest ?? null,
    createdAt: view.createdAt,
    pendingExpiresAt: view.pendingExpiresAt,
    connected: view.connected,
  };
}

export const listPendingBootsFn = createServerFn({ method: "GET" }).handler(
  async (): Promise<PendingBootGroup[]> =>
    await guarded(async () => {
      await requireSession();
      const db = fromD1(env.VAULT_DB);
      const groups: PendingBootGroup[] = [];

      for (const project of await listProjects(db)) {
        for (const environment of await listEnvironmentsByProject(db, project.id)) {
          const indexed = await listPendingBootRequestsByEnvironment(db, environment.id);
          if (indexed.length === 0) continue;
          const live = await stubFor(environment.id).listLive();
          const byId = new Map(live.map((view) => [view.bootId, view]));
          const boots: BootSummary[] = [];

          for (const row of indexed) {
            const view = byId.get(row.id);
            if (view === undefined) {
              // The object no longer holds this boot, or it moved on without the
              // index catching up. Ask for it directly before rewriting the row.
              const authoritative = await stubFor(environment.id).get(row.id);
              if (authoritative !== null && authoritative.status !== row.status) {
                await refreshIndexRow(db, row.id, authoritative.status);
              }
              continue;
            }
            if (view.status !== row.status) {
              await refreshIndexRow(db, row.id, view.status);
            }
            if (view.status !== "PENDING") continue;
            const labels = await loadLabels(db, environment.id, view.tokenId);
            if (labels === null) continue;
            boots.push(toSummary(view, labels));
          }

          if (boots.length === 0) continue;
          const counts = new Map<string, { tokenId: string; tokenLabel: string; count: number }>();
          for (const view of live) {
            const existing = counts.get(view.tokenId);
            if (existing === undefined) {
              const label = boots.find((boot) => boot.tokenId === view.tokenId)?.tokenLabel;
              counts.set(view.tokenId, {
                tokenId: view.tokenId,
                tokenLabel: label ?? view.tokenId,
                count: 1,
              });
            } else {
              existing.count += 1;
            }
          }
          groups.push({
            projectId: project.id,
            projectName: project.name,
            environmentId: environment.id,
            environmentName: environment.name,
            provenanceMode: environment.provenanceMode,
            boots,
            liveBootsByToken: [...counts.values()],
          });
        }
      }
      return groups;
    }),
);

export const getBootFn = createServerFn({ method: "GET" })
  .validator(z.object({ bootId: bootIdSchema }))
  .handler(
    async ({ data }): Promise<BootDetail | null> =>
      await guarded(async () => {
        await requireSession();
        const db = fromD1(env.VAULT_DB);
        const environmentId = await environmentOf(db, data.bootId);
        if (environmentId === null) return null;
        const view = await stubFor(environmentId).get(data.bootId);
        if (view === null || view.environmentId !== environmentId) return null;

        const row = await getBootRequest(db, data.bootId);
        if (row !== null && row.status !== view.status) {
          await refreshIndexRow(db, data.bootId, view.status);
        }
        const labels = await loadLabels(db, view.environmentId, view.tokenId);
        if (labels === null) return null;

        const environment = await getEnvironment(db, view.environmentId);
        const mode: ProvenanceMode = environment?.provenanceMode ?? "ADVISORY";
        const context = await loadProvenanceContext(db, view.environmentId, mode);
        const results = [...view.provenance];
        const token = await getBootstrapTokenByTokenId(db, view.tokenId.replace(/^tok_/, ""));
        const allowedCidrs = readCidrs(token?.allowedCidrsJson ?? "[]");

        return {
          summary: toSummary(view, labels),
          claimedClient: view.claims.client ?? null,
          claimedProviderName: view.claims.provider?.name ?? null,
          claimedProviderDeploymentId: view.claims.provider?.deploymentId ?? null,
          cidrPolicyConfigured: allowedCidrs.length > 0,
          cidrPolicySatisfied: ipAllowed(view.sourceIp ?? "", allowedCidrs),
          provenanceMode: mode,
          results,
          evaluation: evaluatePolicy(mode, results, context.policies),
          evidenceDigest: await summaryDigest(results),
          payloadExpiresAt: view.payloadExpiresAt,
          terminalReason: view.terminalReason,
        };
      }),
  );

const cidrListJson = z
  .string()
  .transform((text, context) => {
    try {
      return JSON.parse(text);
    } catch {
      context.addIssue({ code: "custom", message: "allowed_cidrs_json is not valid JSON" });
      return z.NEVER;
    }
  })
  .pipe(z.array(z.string()));

function readCidrs(allowedCidrsJson: string): string[] {
  const parsed = cidrListJson.safeParse(allowedCidrsJson);
  return parsed.success ? parsed.data : [];
}

export const approveBootFn = createServerFn({ method: "POST" })
  .validator(
    z.object({
      bootId: bootIdSchema,
      /** The digest of the provenance summary the operator read on screen. */
      evidenceDigest: z.string().regex(/^[0-9a-f]{64}$/),
    }),
  )
  .handler(
    async ({ data }): Promise<BootActionOutcome> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        const environmentId = await environmentOf(fromD1(env.VAULT_DB), data.bootId);
        if (environmentId === null) return NOT_FOUND;
        return outcome(
          await stubFor(environmentId).approve({
            bootId: data.bootId,
            approverUserId: session.userId,
            // Better Auth 1.7.2 does not expose the credential that produced the
            // session, so the approval records the session itself as the
            // credential. The step-up guard has already proved a passkey
            // assertion happened within the last five minutes.
            approverCredentialId: "session",
            evidenceDigest: data.evidenceDigest,
          }),
        );
      }),
  );

export const declineBootFn = createServerFn({ method: "POST" })
  .validator(z.object({ bootId: bootIdSchema, reason: reasonSchema }))
  .handler(
    async ({ data }): Promise<BootActionOutcome> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        const environmentId = await environmentOf(fromD1(env.VAULT_DB), data.bootId);
        if (environmentId === null) return NOT_FOUND;
        return outcome(
          await stubFor(environmentId).decline({
            bootId: data.bootId,
            approverUserId: session.userId,
            reason: data.reason.length === 0 ? "declined by an administrator" : data.reason,
          }),
        );
      }),
  );

export const cancelBootFn = createServerFn({ method: "POST" })
  .validator(z.object({ bootId: bootIdSchema, reason: reasonSchema }))
  .handler(
    async ({ data }): Promise<BootActionOutcome> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        const environmentId = await environmentOf(fromD1(env.VAULT_DB), data.bootId);
        if (environmentId === null) return NOT_FOUND;
        return outcome(
          await stubFor(environmentId).cancelBoot({
            bootId: data.bootId,
            actorUserId: session.userId,
            reason: data.reason.length === 0 ? "canceled by an administrator" : data.reason,
          }),
        );
      }),
  );
