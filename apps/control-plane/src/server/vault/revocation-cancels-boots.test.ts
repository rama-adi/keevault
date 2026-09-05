/**
 * Revoking a token or removing an environment must cancel the live boots that
 * depend on it (spec sections 38 and 40).
 *
 * The service reaches the Durable Object through `context.boots`, so these
 * tests run the real service over `node:sqlite` with a recording control and
 * assert on the calls it made.
 */

import { describe, expect, test } from "vite-plus/test";

import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  deleteEnvironment,
  deleteProject,
  listBootstrapTokens,
  revokeBootstrapToken,
  ENVIRONMENT_DELETED_REASON,
  PROJECT_DELETED_REASON,
  TOKEN_REVOKED_REASON,
} from "./service.ts";
import { createTestContext } from "./test-context.ts";

async function seed() {
  const { context, boots } = await createTestContext();
  const project = await createProject(context, { slug: "acme", name: "Acme" });
  const production = await createEnvironment(context, {
    projectId: project.id,
    slug: "production",
    name: "Production",
  });
  return { context, boots, project, production };
}

describe("bootstrap token revocation", () => {
  test("cancels the boots of that token in that environment", async () => {
    const { context, boots, production } = await seed();
    const token = await createBootstrapToken(context, {
      environmentId: production.id,
      label: "zeabur-prod-1",
      allowedCidrs: [],
      expiresAt: null,
      maxPendingBoots: 3,
    });

    await revokeBootstrapToken(context, token.summary.id);

    expect(boots.calls).toEqual([
      {
        kind: "token",
        environmentId: production.id,
        tokenRowId: token.summary.id,
        reason: TOKEN_REVOKED_REASON,
      },
    ]);
  });

  test("leaves the token revoked when the environment object cannot be reached", async () => {
    const { context, boots, production } = await seed();
    const token = await createBootstrapToken(context, {
      environmentId: production.id,
      label: "zeabur-prod-1",
      allowedCidrs: [],
      expiresAt: null,
      maxPendingBoots: 3,
    });
    boots.fail = true;

    await revokeBootstrapToken(context, token.summary.id);

    const listed = await listBootstrapTokens(context, production.id);
    expect(listed[0]?.revokedAt).not.toBeNull();
    expect(boots.calls).toEqual([]);
  });
});

describe("environment deletion", () => {
  test("cancels every live boot before the keys go away", async () => {
    const { context, boots, production } = await seed();

    await deleteEnvironment(context, production.id);

    expect(boots.calls).toEqual([
      {
        kind: "environment",
        environmentId: production.id,
        tokenRowId: null,
        reason: ENVIRONMENT_DELETED_REASON,
      },
    ]);
    const keys = await context.db
      .prepare("SELECT COUNT(*) AS total FROM environment_keys WHERE environment_id = ?")
      .bind(production.id)
      .first<{ total: number }>();
    expect(keys?.total).toBe(0);
  });

  test("still deletes when the environment object cannot be reached", async () => {
    const { context, boots, production } = await seed();
    boots.fail = true;

    await deleteEnvironment(context, production.id);

    const row = await context.db
      .prepare("SELECT COUNT(*) AS total FROM environments WHERE id = ?")
      .bind(production.id)
      .first<{ total: number }>();
    expect(row?.total).toBe(0);
    expect(boots.calls).toEqual([]);
  });
});

describe("project deletion", () => {
  test("cancels the boots of every environment it owns", async () => {
    const { context, boots, project, production } = await seed();
    const staging = await createEnvironment(context, {
      projectId: project.id,
      slug: "staging",
      name: "Staging",
    });

    await deleteProject(context, project.id);

    expect(boots.calls.map((call) => call.environmentId).sort()).toEqual(
      [production.id, staging.id].sort(),
    );
    for (const call of boots.calls) {
      expect(call.kind).toBe("environment");
      expect(call.reason).toBe(PROJECT_DELETED_REASON);
    }
  });
});
