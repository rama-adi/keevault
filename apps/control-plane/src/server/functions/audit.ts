/**
 * Audit log reads. Any signed-in operator may read the log (spec section 21).
 */

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSession } from "../auth/guards.ts";
import { vaultContextForSession } from "../vault/runtime.ts";
import {
  listAuditEvents,
  listEnvironments,
  listProjects,
  type AuditPage,
  type EnvironmentSummary,
  type ProjectSummary,
} from "../vault/service.ts";
import { auditIdSchema, environmentIdSchema, projectIdSchema } from "../vault/validation.ts";
import { guarded } from "./guarded.ts";

export const AUDIT_PAGE_SIZE = 50;

export const listAuditEventsFn = createServerFn({ method: "GET" })
  .validator(
    z.object({
      projectId: projectIdSchema.nullable(),
      environmentId: environmentIdSchema.nullable(),
      before: auditIdSchema.nullable(),
    }),
  )
  .handler(
    async ({ data }): Promise<AuditPage> =>
      await guarded(async () => {
        const session = await requireSession();
        return await listAuditEvents(vaultContextForSession(session), {
          projectId: data.projectId,
          environmentId: data.environmentId,
          before: data.before,
          limit: AUDIT_PAGE_SIZE,
        });
      }),
  );

/** One project and its environments, for the audit page filter. */
export interface AuditFilterProject {
  project: ProjectSummary;
  environments: EnvironmentSummary[];
}

export const listAuditFiltersFn = createServerFn({ method: "GET" }).handler(
  async (): Promise<AuditFilterProject[]> =>
    await guarded(async () => {
      const session = await requireSession();
      const context = vaultContextForSession(session);
      const projects = await listProjects(context);
      const filters: AuditFilterProject[] = [];
      for (const project of projects) {
        filters.push({ project, environments: await listEnvironments(context, project.id) });
      }
      return filters;
    }),
);
