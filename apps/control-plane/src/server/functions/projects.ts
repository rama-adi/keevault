/**
 * Project and environment server functions.
 *
 * Guards (spec sections 21 and 22): reads need a session, mutations need admin,
 * deleting an environment and rotating a key additionally need a passkey
 * verification from the last five minutes, and rotation needs owner.
 */

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireRecentPasskey, requireRole, requireSession } from "../auth/guards.ts";
import {
  createEnvironment,
  createProject,
  deleteEnvironment,
  deleteProject,
  getEnvironmentSummary,
  getProject,
  listEnvironments,
  listProjects,
  rotateEnvironmentKey,
  rotateProjectKey,
  setEnvironmentPolicy,
  type EnvironmentSummary,
  type ProjectSummary,
} from "../vault/service.ts";
import { vaultContextForSession } from "../vault/runtime.ts";
import {
  approvedTtlSecondsSchema,
  displayNameSchema,
  environmentIdSchema,
  pendingTtlSecondsSchema,
  projectIdSchema,
  provenanceModeSchema,
  slugSchema,
} from "../vault/validation.ts";
import { guarded } from "./guarded.ts";

export const listProjectsFn = createServerFn({ method: "GET" }).handler(
  async (): Promise<ProjectSummary[]> =>
    await guarded(async () => {
      const session = await requireSession();
      return await listProjects(vaultContextForSession(session));
    }),
);

const projectIdInput = z.object({ projectId: projectIdSchema });

export interface ProjectDetail {
  project: ProjectSummary;
  environments: EnvironmentSummary[];
}

export const getProjectDetailFn = createServerFn({ method: "GET" })
  .validator(projectIdInput)
  .handler(
    async ({ data }): Promise<ProjectDetail | null> =>
      await guarded(async () => {
        const session = await requireSession();
        const context = vaultContextForSession(session);
        const project = await getProject(context, data.projectId);
        if (project === null) return null;
        return { project, environments: await listEnvironments(context, data.projectId) };
      }),
  );

export const createProjectFn = createServerFn({ method: "POST" })
  .validator(z.object({ slug: slugSchema, name: displayNameSchema }))
  .handler(
    async ({ data }): Promise<ProjectSummary> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        return await createProject(vaultContextForSession(session), data);
      }),
  );

export const deleteProjectFn = createServerFn({ method: "POST" })
  .validator(projectIdInput)
  .handler(
    async ({ data }): Promise<{ deleted: true }> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        await deleteProject(vaultContextForSession(session), data.projectId);
        return { deleted: true };
      }),
  );

export const rotateProjectKeyFn = createServerFn({ method: "POST" })
  .validator(projectIdInput)
  .handler(
    async ({ data }) =>
      await guarded(async () => {
        const session = await requireRole("owner");
        await requireRecentPasskey();
        return await rotateProjectKey(vaultContextForSession(session), data.projectId);
      }),
  );

export const createEnvironmentFn = createServerFn({ method: "POST" })
  .validator(z.object({ projectId: projectIdSchema, slug: slugSchema, name: displayNameSchema }))
  .handler(
    async ({ data }): Promise<EnvironmentSummary> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        return await createEnvironment(vaultContextForSession(session), data);
      }),
  );

const environmentIdInput = z.object({ environmentId: environmentIdSchema });

export const getEnvironmentFn = createServerFn({ method: "GET" })
  .validator(environmentIdInput)
  .handler(
    async ({ data }): Promise<EnvironmentSummary | null> =>
      await guarded(async () => {
        const session = await requireSession();
        return await getEnvironmentSummary(vaultContextForSession(session), data.environmentId);
      }),
  );

export const deleteEnvironmentFn = createServerFn({ method: "POST" })
  .validator(environmentIdInput)
  .handler(
    async ({ data }): Promise<{ deleted: true }> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        await deleteEnvironment(vaultContextForSession(session), data.environmentId);
        return { deleted: true };
      }),
  );

export const setEnvironmentPolicyFn = createServerFn({ method: "POST" })
  .validator(
    z.object({
      environmentId: environmentIdSchema,
      provenanceMode: provenanceModeSchema,
      pendingTtlSeconds: pendingTtlSecondsSchema,
      approvedTtlSeconds: approvedTtlSecondsSchema,
    }),
  )
  .handler(
    async ({ data }): Promise<EnvironmentSummary> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        return await setEnvironmentPolicy(vaultContextForSession(session), data);
      }),
  );

export const rotateEnvironmentKeyFn = createServerFn({ method: "POST" })
  .validator(environmentIdInput)
  .handler(
    async ({ data }) =>
      await guarded(async () => {
        const session = await requireRole("owner");
        await requireRecentPasskey();
        return await rotateEnvironmentKey(vaultContextForSession(session), data.environmentId);
      }),
  );
