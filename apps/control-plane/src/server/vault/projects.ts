/**
 * Project and environment lifecycle.
 *
 * Creating a project generates a project key from the platform CSPRNG and wraps
 * it under the active master key version. Creating an environment generates an
 * environment DEK and wraps it under the project's current key. No key is ever
 * derived from another key (spec section 7).
 */

import { b64uEncode, generateKey32, wrapEnvironmentKey, wrapProjectKey } from "@env-vault/crypto";
import {
  createEnvironment as createEnvironmentRow,
  createProject as createProjectRow,
  deleteEnvironment as deleteEnvironmentRow,
  deleteProject as deleteProjectRow,
  getEnvironment,
  getProjectById,
  getProjectBySlug,
  insertEnvironmentKey,
  insertProjectKey,
  listEnvironmentsByProject,
  listProjects as listProjectRows,
  listSecretMetadata,
  setCurrentProjectKeyVersion,
  switchCurrentEnvironmentKey,
  updateEnvironmentPolicy,
  type EnvironmentRow,
  type ProjectRow,
} from "@env-vault/vault-store";

import { writeAuditEvent, type AuditMetadataValue } from "./audit.ts";
import type { VaultContext } from "./context.ts";
import { generatePrefixedUlidId } from "./ids.ts";
import { unwrapProjectKey, VaultKeyError } from "./keys.ts";
import {
  toEnvironmentSummary,
  toProjectSummary,
  type EnvironmentSummary,
  type ProjectSummary,
} from "./types.ts";
import { VaultInputError } from "./validation.ts";

/** Default boot TTLs for a new environment (engineering brief). */
export const DEFAULT_PENDING_TTL_SECONDS = 1800;
export const DEFAULT_APPROVED_TTL_SECONDS = 300;

export interface CreateProjectInput {
  slug: string;
  name: string;
}

/** Create a project and its first project key. */
export async function createProject(
  context: VaultContext,
  input: CreateProjectInput,
): Promise<ProjectSummary> {
  const existing = await getProjectBySlug(context.db, input.slug);
  if (existing !== null) {
    throw new VaultInputError("slug", `A project with the slug ${input.slug} already exists.`);
  }
  const now = context.now();
  const projectId = generatePrefixedUlidId("proj");
  const masterKeyVersion = context.keyring.activeVersion;
  const projectKey = generateKey32();
  const sealed = await wrapProjectKey({
    masterKey: context.keyring.key(masterKeyVersion),
    projectKey,
    projectId,
    projectKeyVersion: 1,
    masterKeyVersion,
  });

  await createProjectRow(context.db, { id: projectId, slug: input.slug, name: input.name, now });
  await insertProjectKey(context.db, {
    projectId,
    version: 1,
    masterKeyVersion,
    wrappedKey: b64uEncode(sealed.ciphertext),
    nonce: b64uEncode(sealed.nonce),
    now,
  });
  await setCurrentProjectKeyVersion(context.db, { projectId, version: 1, now });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "project.created",
      projectId,
      environmentId: null,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["slug", input.slug],
        ["projectKeyVersion", 1],
        ["masterKeyVersion", masterKeyVersion],
      ]),
    },
  );

  const row = await getProjectById(context.db, projectId);
  if (row === null) throw new VaultKeyError("project_missing", "Project row disappeared.");
  return toProjectSummary(row);
}

export async function listProjects(context: VaultContext): Promise<ProjectSummary[]> {
  return (await listProjectRows(context.db)).map(toProjectSummary);
}

export async function getProject(
  context: VaultContext,
  projectId: string,
): Promise<ProjectSummary | null> {
  const row = await getProjectById(context.db, projectId);
  return row === null ? null : toProjectSummary(row);
}

/** Delete a project. Cascading foreign keys remove its keys, environments and secrets. */
export async function deleteProject(context: VaultContext, projectId: string): Promise<void> {
  const project = await requireProject(context, projectId);
  const environments = await listEnvironmentsByProject(context.db, projectId);
  const now = context.now();

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "project.deleted",
      projectId: null,
      environmentId: null,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["projectId", projectId],
        ["slug", project.slug],
        ["environmentCount", environments.length],
      ]),
    },
  );
  await deleteProjectRow(context.db, projectId);
}

export interface CreateEnvironmentInput {
  projectId: string;
  slug: string;
  name: string;
}

/** Create an environment and its first environment key. */
export async function createEnvironment(
  context: VaultContext,
  input: CreateEnvironmentInput,
): Promise<EnvironmentSummary> {
  await requireProject(context, input.projectId);
  const siblings = await listEnvironmentsByProject(context.db, input.projectId);
  if (siblings.some((environment) => environment.slug === input.slug)) {
    throw new VaultInputError(
      "slug",
      `This project already has an environment called ${input.slug}.`,
    );
  }

  const now = context.now();
  const environmentId = generatePrefixedUlidId("env");
  const projectKey = await unwrapProjectKey(context.db, context.keyring, input.projectId);
  const environmentKey = generateKey32();
  const sealed = await wrapEnvironmentKey({
    projectKey: projectKey.key,
    environmentKey,
    projectId: input.projectId,
    environmentId,
    environmentKeyVersion: 1,
    projectKeyVersion: projectKey.version,
  });

  await createEnvironmentRow(context.db, {
    id: environmentId,
    projectId: input.projectId,
    slug: input.slug,
    name: input.name,
    provenanceMode: "ADVISORY",
    pendingTtlSeconds: DEFAULT_PENDING_TTL_SECONDS,
    approvedTtlSeconds: DEFAULT_APPROVED_TTL_SECONDS,
    now,
  });
  await insertEnvironmentKey(context.db, {
    environmentId,
    version: 1,
    projectKeyVersion: projectKey.version,
    wrappedKey: b64uEncode(sealed.ciphertext),
    nonce: b64uEncode(sealed.nonce),
    now,
  });
  await switchCurrentEnvironmentKey(context.db, {
    environmentId,
    previousVersion: 0,
    nextVersion: 1,
    now,
  });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "environment.created",
      projectId: input.projectId,
      environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["slug", input.slug],
        ["environmentKeyVersion", 1],
        ["projectKeyVersion", projectKey.version],
      ]),
    },
  );

  return toEnvironmentSummary(await requireEnvironment(context, environmentId));
}

export async function listEnvironments(
  context: VaultContext,
  projectId: string,
): Promise<EnvironmentSummary[]> {
  return (await listEnvironmentsByProject(context.db, projectId)).map(toEnvironmentSummary);
}

export async function getEnvironmentSummary(
  context: VaultContext,
  environmentId: string,
): Promise<EnvironmentSummary | null> {
  const row = await getEnvironment(context.db, environmentId);
  return row === null ? null : toEnvironmentSummary(row);
}

/** Delete an environment. Its keys, secrets, tokens and boot rows cascade away. */
export async function deleteEnvironment(
  context: VaultContext,
  environmentId: string,
): Promise<void> {
  const environment = await requireEnvironment(context, environmentId);
  const secrets = await listSecretMetadata(context.db, environmentId);
  const now = context.now();

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "environment.deleted",
      projectId: environment.projectId,
      environmentId: null,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["environmentId", environmentId],
        ["slug", environment.slug],
        ["secretCount", secrets.length],
      ]),
    },
  );
  await deleteEnvironmentRow(context.db, environmentId);
}

export interface SetEnvironmentPolicyInput {
  environmentId: string;
  provenanceMode: "OFF" | "ADVISORY" | "REQUIRED";
  pendingTtlSeconds: number;
  approvedTtlSeconds: number;
}

/** Change the provenance mode and boot TTLs of one environment (spec section 26). */
export async function setEnvironmentPolicy(
  context: VaultContext,
  input: SetEnvironmentPolicyInput,
): Promise<EnvironmentSummary> {
  const before = await requireEnvironment(context, input.environmentId);
  const now = context.now();
  const after = await updateEnvironmentPolicy(context.db, {
    environmentId: input.environmentId,
    provenanceMode: input.provenanceMode,
    pendingTtlSeconds: input.pendingTtlSeconds,
    approvedTtlSeconds: input.approvedTtlSeconds,
    now,
  });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "provenance-policy.changed",
      projectId: before.projectId,
      environmentId: input.environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["previousMode", before.provenanceMode],
        ["mode", input.provenanceMode],
        ["pendingTtlSeconds", input.pendingTtlSeconds],
        ["approvedTtlSeconds", input.approvedTtlSeconds],
      ]),
    },
  );
  return toEnvironmentSummary(after);
}

/** Read a project row or fail with a typed error. */
export async function requireProject(
  context: VaultContext,
  projectId: string,
): Promise<ProjectRow> {
  const row = await getProjectById(context.db, projectId);
  if (row === null) {
    throw new VaultInputError("projectId", `Project ${projectId} does not exist.`);
  }
  return row;
}

/** Read an environment row or fail with a typed error. */
export async function requireEnvironment(
  context: VaultContext,
  environmentId: string,
): Promise<EnvironmentRow> {
  const row = await getEnvironment(context.db, environmentId);
  if (row === null) {
    throw new VaultInputError("environmentId", `Environment ${environmentId} does not exist.`);
  }
  return row;
}
