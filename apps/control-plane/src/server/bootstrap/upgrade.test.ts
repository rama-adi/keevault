import { generateBootstrapToken, generatePrefixedUlid } from "@keevault/crypto";
import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  type VaultDatabase,
} from "@keevault/vault-store";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import {
  INTERNAL_ENVIRONMENT_HEADER,
  INTERNAL_MAX_PENDING_HEADER,
  INTERNAL_PROJECT_HEADER,
  INTERNAL_SOURCE_IP_HEADER,
  INTERNAL_TOKEN_HEADER,
} from "./headers.ts";
import { createTestVault } from "./test-vault.ts";
import { isBootstrapRequest, routeBootstrapUpgrade } from "./upgrade.ts";

const NOW = "2026-09-05T10:00:00.000Z";

interface Fixture {
  db: VaultDatabase;
  token: string;
  tokenRowId: string;
  environmentId: string;
  projectId: string;
}

/** Records what the Worker forwarded, standing in for the Durable Object stub. */
class RecordingRouter {
  environmentId: string | null = null;
  forwarded: Request | null = null;

  fetchEnvironment(environmentId: string, request: Request): Promise<Response> {
    this.environmentId = environmentId;
    this.forwarded = request;
    // The real object answers 101. Node's Response refuses that status outside
    // workerd, so the double answers 200 and the test asserts on what was
    // forwarded rather than on the status it made up.
    return Promise.resolve(new Response(null, { status: 200 }));
  }
}

async function seed(): Promise<Fixture> {
  const vault = await createTestVault();
  const projectId = generatePrefixedUlid("proj");
  const environmentId = generatePrefixedUlid("env");
  await createProject(vault.db, { id: projectId, slug: "acme", name: "Acme", now: NOW });
  await createEnvironment(vault.db, {
    id: environmentId,
    projectId,
    slug: "production",
    name: "Production",
    provenanceMode: "ADVISORY",
    pendingTtlSeconds: 1800,
    approvedTtlSeconds: 300,
    now: NOW,
  });
  const minted = await generateBootstrapToken();
  const tokenRowId = `tok_${minted.tokenId}`;
  await createBootstrapToken(vault.db, {
    id: tokenRowId,
    environmentId,
    label: "zeabur-prod-01",
    tokenHash: minted.secretHash,
    allowedCidrsJson: "[]",
    maxPendingBoots: 2,
    expiresAt: null,
    now: NOW,
  });
  return { db: vault.db, token: minted.token, tokenRowId, environmentId, projectId };
}

function upgradeRequest(token: string, extra: ReadonlyMap<string, string> = new Map()): Request {
  const headers = new Headers({
    Upgrade: "websocket",
    Authorization: `Bearer ${token}`,
    "CF-Connecting-IP": "203.0.113.42",
  });
  extra.forEach((value, name) => {
    headers.set(name, value);
  });
  return new Request("https://vault.test/bootstrap/v1", { method: "GET", headers });
}

describe("isBootstrapRequest", () => {
  it("matches only the exact endpoint path", () => {
    expect(isBootstrapRequest(new URL("https://vault.test/bootstrap/v1"))).toBe(true);
    expect(isBootstrapRequest(new URL("https://vault.test/bootstrap/v1/extra"))).toBe(false);
    expect(isBootstrapRequest(new URL("https://vault.test/projects"))).toBe(false);
  });
});

describe("routeBootstrapUpgrade", () => {
  let fixture: Fixture;
  let router: RecordingRouter;

  beforeEach(async () => {
    fixture = await seed();
    router = new RecordingRouter();
  });

  it("answers 426 when the request is not a WebSocket upgrade", async () => {
    const request = new Request("https://vault.test/bootstrap/v1", {
      method: "GET",
      headers: { Authorization: `Bearer ${fixture.token}` },
    });

    const response = await routeBootstrapUpgrade(request, fixture.db, router);

    expect(response.status).toBe(426);
    expect(response.headers.get("Upgrade")).toBe("websocket");
    expect(router.forwarded).toBeNull();
  });

  it("answers 405 for a method other than GET", async () => {
    const request = new Request("https://vault.test/bootstrap/v1", {
      method: "POST",
      headers: { Upgrade: "websocket" },
    });

    const response = await routeBootstrapUpgrade(request, fixture.db, router);

    expect(response.status).toBe(405);
  });

  it("answers 401 for a missing token and never reaches the object", async () => {
    const request = new Request("https://vault.test/bootstrap/v1", {
      method: "GET",
      headers: { Upgrade: "websocket" },
    });

    const response = await routeBootstrapUpgrade(request, fixture.db, router);

    expect(response.status).toBe(401);
    expect(router.forwarded).toBeNull();
  });

  it("forwards the authenticated identity to the environment's object", async () => {
    const response = await routeBootstrapUpgrade(upgradeRequest(fixture.token), fixture.db, router);

    expect(response.status).toBe(200);
    expect(router.environmentId).toBe(fixture.environmentId);
    const forwarded = router.forwarded;
    expect(forwarded).not.toBeNull();
    if (forwarded === null) return;
    expect(forwarded.headers.get(INTERNAL_TOKEN_HEADER)).toBe(fixture.tokenRowId);
    expect(forwarded.headers.get(INTERNAL_ENVIRONMENT_HEADER)).toBe(fixture.environmentId);
    expect(forwarded.headers.get(INTERNAL_PROJECT_HEADER)).toBe(fixture.projectId);
    expect(forwarded.headers.get(INTERNAL_SOURCE_IP_HEADER)).toBe("203.0.113.42");
    expect(forwarded.headers.get(INTERNAL_MAX_PENDING_HEADER)).toBe("2");
  });

  it("never forwards the bootstrap token itself", async () => {
    await routeBootstrapUpgrade(upgradeRequest(fixture.token), fixture.db, router);

    expect(router.forwarded?.headers.get("Authorization")).toBeNull();
  });

  it("strips internal headers the client tried to set", async () => {
    const forged = new Map([
      [INTERNAL_TOKEN_HEADER, "tok_FORGED"],
      [INTERNAL_ENVIRONMENT_HEADER, "env_FORGED"],
      [INTERNAL_PROJECT_HEADER, "proj_FORGED"],
      [INTERNAL_SOURCE_IP_HEADER, "10.0.0.1"],
      [INTERNAL_MAX_PENDING_HEADER, "9999"],
    ]);

    await routeBootstrapUpgrade(upgradeRequest(fixture.token, forged), fixture.db, router);

    const forwarded = router.forwarded;
    expect(forwarded).not.toBeNull();
    if (forwarded === null) return;
    expect(forwarded.headers.get(INTERNAL_TOKEN_HEADER)).toBe(fixture.tokenRowId);
    expect(forwarded.headers.get(INTERNAL_ENVIRONMENT_HEADER)).toBe(fixture.environmentId);
    expect(forwarded.headers.get(INTERNAL_PROJECT_HEADER)).toBe(fixture.projectId);
    expect(forwarded.headers.get(INTERNAL_SOURCE_IP_HEADER)).toBe("203.0.113.42");
    expect(forwarded.headers.get(INTERNAL_MAX_PENDING_HEADER)).toBe("2");
  });
});
