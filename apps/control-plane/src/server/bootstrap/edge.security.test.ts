import { generateBootstrapToken, generatePrefixedUlid } from "@env-vault/crypto";
import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  type VaultDatabase,
} from "@env-vault/vault-store";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import {
  INTERNAL_ENVIRONMENT_HEADER,
  INTERNAL_HEADERS,
  INTERNAL_MAX_PENDING_HEADER,
  INTERNAL_PROJECT_HEADER,
  INTERNAL_SOURCE_IP_HEADER,
  INTERNAL_TOKEN_HEADER,
} from "./headers.ts";
import { createTestVault } from "./test-vault.ts";
import { routeBootstrapUpgrade } from "./upgrade.ts";
import { authenticateBootstrapRequest } from "../vault/bootstrap-auth.ts";

/**
 * Edge tests for the one machine endpoint (spec sections 12, 13 and phase 11).
 *
 * Two properties are checked here that nothing else can check downstream,
 * because by the time a frame reaches the Durable Object both have already been
 * decided: a credential in the query string is refused outright, and the
 * internal identity headers are attacker-proof.
 */

const NOW = "2026-09-05T10:00:00.000Z";

interface Fixture {
  db: VaultDatabase;
  token: string;
  tokenRowId: string;
  environmentId: string;
  projectId: string;
  otherEnvironmentId: string;
}

/** Records what the Worker forwarded, standing in for the Durable Object stub. */
class RecordingRouter {
  environmentId: string | null = null;
  forwarded: Request | null = null;
  calls = 0;

  fetchEnvironment(environmentId: string, request: Request): Promise<Response> {
    this.calls += 1;
    this.environmentId = environmentId;
    this.forwarded = request;
    return Promise.resolve(new Response(null, { status: 200 }));
  }
}

async function seed(allowedCidrs: readonly string[] = []): Promise<Fixture> {
  const vault = await createTestVault();
  const projectId = generatePrefixedUlid("proj");
  const environmentId = generatePrefixedUlid("env");
  const otherEnvironmentId = generatePrefixedUlid("env");
  await createProject(vault.db, { id: projectId, slug: "acme", name: "Acme", now: NOW });
  for (const [id, slug] of [
    [environmentId, "production"],
    [otherEnvironmentId, "staging"],
  ] as const) {
    await createEnvironment(vault.db, {
      id,
      projectId,
      slug,
      name: slug,
      provenanceMode: "ADVISORY",
      pendingTtlSeconds: 1800,
      approvedTtlSeconds: 300,
      now: NOW,
    });
  }
  const minted = await generateBootstrapToken();
  const tokenRowId = `tok_${minted.tokenId}`;
  await createBootstrapToken(vault.db, {
    id: tokenRowId,
    environmentId,
    label: "zeabur-prod-01",
    tokenHash: minted.secretHash,
    allowedCidrsJson: JSON.stringify(allowedCidrs),
    maxPendingBoots: 2,
    expiresAt: null,
    now: NOW,
  });
  return {
    db: vault.db,
    token: minted.token,
    tokenRowId,
    environmentId,
    projectId,
    otherEnvironmentId,
  };
}

function upgradeRequest(
  url: string,
  headers: ReadonlyMap<string, string>,
  token: string | null,
): Request {
  const built = new Headers({ Upgrade: "websocket", "CF-Connecting-IP": "203.0.113.42" });
  if (token !== null) built.set("Authorization", `Bearer ${token}`);
  headers.forEach((value, name) => {
    built.set(name, value);
  });
  return new Request(url, { method: "GET", headers: built });
}

async function lastSeen(fixture: Fixture): Promise<string | null> {
  const row = await fixture.db
    .prepare("SELECT last_seen_at AS lastSeenAt FROM bootstrap_tokens WHERE id = ?")
    .bind(fixture.tokenRowId)
    .first<{ lastSeenAt: string | null }>();
  return row?.lastSeenAt ?? null;
}

describe("credentials in the query string", () => {
  let fixture: Fixture;

  beforeEach(async () => {
    fixture = await seed();
  });

  it("refuses a valid token presented as ?token= and never looks it up", async () => {
    const result = await authenticateBootstrapRequest(
      upgradeRequest(
        `https://vault.test/bootstrap/v1?token=${encodeURIComponent(fixture.token)}`,
        new Map(),
        null,
      ),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("query_token");
    expect(result.httpStatus).toBe(401);
    // Nothing was hashed or looked up, which is the point: a token that leaked
    // into a URL must not become a working credential for one more request.
    expect(await lastSeen(fixture)).toBe(null);
  });

  it("refuses the query string even when a good header is also present", async () => {
    const result = await authenticateBootstrapRequest(
      upgradeRequest("https://vault.test/bootstrap/v1?token=decoy", new Map(), fixture.token),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("query_token");
  });

  it("never echoes the presented token back in the refusal", async () => {
    const secret = fixture.token.split(".")[1] ?? "";
    const result = await authenticateBootstrapRequest(
      upgradeRequest(
        `https://vault.test/bootstrap/v1?token=${encodeURIComponent(fixture.token)}`,
        new Map(),
        null,
      ),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message.includes(secret)).toBe(false);
    expect(result.message.includes(fixture.token)).toBe(false);
  });

  it("stops the query-string request at the edge, before any object is woken", async () => {
    const router = new RecordingRouter();
    const response = await routeBootstrapUpgrade(
      upgradeRequest(
        `https://vault.test/bootstrap/v1?token=${encodeURIComponent(fixture.token)}`,
        new Map(),
        null,
      ),
      fixture.db,
      router,
    );

    expect(response.status).toBe(401);
    expect(router.calls).toBe(0);
  });
});

describe("internal identity headers on an external request", () => {
  let fixture: Fixture;
  let router: RecordingRouter;

  beforeEach(async () => {
    fixture = await seed();
    router = new RecordingRouter();
  });

  it("replaces every internal header the client set with the proved identity", async () => {
    const spoofed = new Map<string, string>([
      [INTERNAL_TOKEN_HEADER, "tok_ATTACKERATTACKERATTACKERA"],
      [INTERNAL_ENVIRONMENT_HEADER, fixture.otherEnvironmentId],
      [INTERNAL_PROJECT_HEADER, "proj_ATTACKERATTACKERATTACKER"],
      [INTERNAL_SOURCE_IP_HEADER, "198.51.100.1"],
      [INTERNAL_MAX_PENDING_HEADER, "64"],
    ]);

    await routeBootstrapUpgrade(
      upgradeRequest("https://vault.test/bootstrap/v1", spoofed, fixture.token),
      fixture.db,
      router,
    );

    const forwarded = router.forwarded;
    expect(forwarded).not.toBe(null);
    if (forwarded === null) return;
    expect(forwarded.headers.get(INTERNAL_TOKEN_HEADER)).toBe(fixture.tokenRowId);
    expect(forwarded.headers.get(INTERNAL_ENVIRONMENT_HEADER)).toBe(fixture.environmentId);
    expect(forwarded.headers.get(INTERNAL_PROJECT_HEADER)).toBe(fixture.projectId);
    expect(forwarded.headers.get(INTERNAL_SOURCE_IP_HEADER)).toBe("203.0.113.42");
    expect(forwarded.headers.get(INTERNAL_MAX_PENDING_HEADER)).toBe("2");
  });

  it("routes to the token's environment, not the one the client named", async () => {
    await routeBootstrapUpgrade(
      upgradeRequest(
        "https://vault.test/bootstrap/v1",
        new Map([[INTERNAL_ENVIRONMENT_HEADER, fixture.otherEnvironmentId]]),
        fixture.token,
      ),
      fixture.db,
      router,
    );

    expect(router.environmentId).toBe(fixture.environmentId);
    expect(router.environmentId).not.toBe(fixture.otherEnvironmentId);
  });

  it("is not fooled by header names in a different case", async () => {
    const shouted = new Map<string, string>(
      INTERNAL_HEADERS.map((name) => [name.toUpperCase(), "attacker"]),
    );

    await routeBootstrapUpgrade(
      upgradeRequest("https://vault.test/bootstrap/v1", shouted, fixture.token),
      fixture.db,
      router,
    );

    const forwarded = router.forwarded;
    expect(forwarded).not.toBe(null);
    if (forwarded === null) return;
    for (const name of INTERNAL_HEADERS) {
      expect(forwarded.headers.get(name)).not.toBe("attacker");
    }
  });

  it("does not forward the bootstrap token to the object", async () => {
    await routeBootstrapUpgrade(
      upgradeRequest("https://vault.test/bootstrap/v1", new Map(), fixture.token),
      fixture.db,
      router,
    );

    const forwarded = router.forwarded;
    expect(forwarded).not.toBe(null);
    if (forwarded === null) return;
    expect(forwarded.headers.get("Authorization")).toBe(null);
  });

  it("never reaches the object when the token itself is wrong", async () => {
    const [prefix] = fixture.token.split(".");
    const wrong = `${prefix ?? ""}.${"A".repeat(43)}`;

    const response = await routeBootstrapUpgrade(
      upgradeRequest(
        "https://vault.test/bootstrap/v1",
        new Map([[INTERNAL_ENVIRONMENT_HEADER, fixture.environmentId]]),
        wrong,
      ),
      fixture.db,
      router,
    );

    expect(response.status).toBe(401);
    expect(router.calls).toBe(0);
  });
});

describe("source address policy", () => {
  it("reads CF-Connecting-IP only, so a forwarding header cannot move the client", async () => {
    const fixture = await seed(["203.0.113.0/24"]);

    const denied = await authenticateBootstrapRequest(
      upgradeRequest(
        "https://vault.test/bootstrap/v1",
        new Map([
          ["CF-Connecting-IP", "198.51.100.7"],
          ["X-Forwarded-For", "203.0.113.42"],
          ["X-Real-IP", "203.0.113.42"],
          ["True-Client-IP", "203.0.113.42"],
        ]),
        fixture.token,
      ),
      fixture.db,
    );

    expect(denied.ok).toBe(false);
    if (denied.ok) return;
    expect(denied.reason).toBe("cidr");
    expect(denied.httpStatus).toBe(403);
  });

  it("fails closed when CF-Connecting-IP is absent and a policy exists", async () => {
    const fixture = await seed(["203.0.113.0/24"]);
    const headers = new Headers({
      Upgrade: "websocket",
      Authorization: `Bearer ${fixture.token}`,
    });

    const result = await authenticateBootstrapRequest(
      new Request("https://vault.test/bootstrap/v1", { method: "GET", headers }),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("cidr");
  });

  it("treats an unreadable CIDR policy as a deny, not as no policy", async () => {
    const fixture = await seed([]);
    await fixture.db
      .prepare("UPDATE bootstrap_tokens SET allowed_cidrs_json = ? WHERE id = ?")
      .bind("{not json", fixture.tokenRowId)
      .run();

    const result = await authenticateBootstrapRequest(
      upgradeRequest("https://vault.test/bootstrap/v1", new Map(), fixture.token),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("cidr");
  });
});
