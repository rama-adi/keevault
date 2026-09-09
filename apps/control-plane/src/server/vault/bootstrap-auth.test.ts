import { generateBootstrapToken, generatePrefixedUlid } from "@keevault/crypto";
import {
  createEnvironment,
  createBootstrapToken,
  createProject,
  revokeBootstrapToken,
} from "@keevault/vault-store";
import type { VaultDatabase } from "@keevault/vault-store";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { createTestVault } from "../bootstrap/test-vault.ts";
import { authenticateBootstrapRequest } from "./bootstrap-auth.ts";

const NOW = "2026-09-05T10:00:00.000Z";

interface Fixture {
  db: VaultDatabase;
  token: string;
  tokenRowId: string;
  environmentId: string;
  projectId: string;
}

async function seed(allowedCidrs: readonly string[], expiresAt: string | null): Promise<Fixture> {
  const vault = await createTestVault();
  const projectId = generatePrefixedUlid("proj");
  const environmentId = generatePrefixedUlid("env");
  await createProject(vault.db, {
    id: projectId,
    slug: "acme",
    name: "Acme",
    now: NOW,
  });
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
    allowedCidrsJson: JSON.stringify(allowedCidrs),
    maxPendingBoots: 3,
    expiresAt,
    now: NOW,
  });
  return { db: vault.db, token: minted.token, tokenRowId, environmentId, projectId };
}

function upgrade(token: string | null, sourceIp: string, url = "https://vault.test/bootstrap/v1") {
  const headers = new Headers({ "CF-Connecting-IP": sourceIp });
  if (token !== null) headers.set("Authorization", `Bearer ${token}`);
  return new Request(url, { method: "GET", headers });
}

describe("authenticateBootstrapRequest", () => {
  let fixture: Fixture;

  beforeEach(async () => {
    fixture = await seed([], null);
  });

  it("resolves exactly one environment for a valid token", async () => {
    const result = await authenticateBootstrapRequest(
      upgrade(fixture.token, "203.0.113.42"),
      fixture.db,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.environmentId).toBe(fixture.environmentId);
    expect(result.projectId).toBe(fixture.projectId);
    expect(result.tokenId).toBe(fixture.tokenRowId);
    expect(result.sourceIp).toBe("203.0.113.42");
    expect(result.maxPendingBoots).toBe(3);
  });

  it("records last_seen_at on a successful authentication", async () => {
    await authenticateBootstrapRequest(upgrade(fixture.token, "203.0.113.42"), fixture.db);

    const row = await fixture.db
      .prepare("SELECT last_seen_at AS lastSeenAt FROM bootstrap_tokens WHERE id = ?")
      .bind(fixture.tokenRowId)
      .first<{ lastSeenAt: string | null }>();

    expect(row?.lastSeenAt).not.toBeNull();
  });

  it("rejects a wrong secret with 4401 without saying which half was wrong", async () => {
    const [prefix] = fixture.token.split(".");
    const wrong = `${prefix ?? ""}.${"A".repeat(43)}`;

    const result = await authenticateBootstrapRequest(upgrade(wrong, "203.0.113.42"), fixture.db);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("bad_secret");
    expect(result.closeCode).toBe(4401);
    expect(result.httpStatus).toBe(401);
    expect(result.message).toBe("Unknown bootstrap token.");
  });

  it("rejects a revoked token with 4403", async () => {
    await revokeBootstrapToken(fixture.db, { tokenRowId: fixture.tokenRowId, now: NOW });

    const result = await authenticateBootstrapRequest(
      upgrade(fixture.token, "203.0.113.42"),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("revoked");
    expect(result.closeCode).toBe(4403);
    expect(result.httpStatus).toBe(403);
  });

  it("rejects an expired token with 4403", async () => {
    const expired = await seed([], "2020-01-01T00:00:00.000Z");

    const result = await authenticateBootstrapRequest(
      upgrade(expired.token, "203.0.113.42"),
      expired.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("expired");
    expect(result.closeCode).toBe(4403);
  });

  it("rejects an address outside the allowed CIDR list", async () => {
    const restricted = await seed(["203.0.113.0/24", "2001:db8::/32"], null);

    const denied = await authenticateBootstrapRequest(
      upgrade(restricted.token, "198.51.100.7"),
      restricted.db,
    );
    expect(denied.ok).toBe(false);
    if (denied.ok) return;
    expect(denied.reason).toBe("cidr");
    expect(denied.closeCode).toBe(4403);

    const allowed = await authenticateBootstrapRequest(
      upgrade(restricted.token, "203.0.113.9"),
      restricted.db,
    );
    expect(allowed.ok).toBe(true);

    const allowedV6 = await authenticateBootstrapRequest(
      upgrade(restricted.token, "2001:db8::1"),
      restricted.db,
    );
    expect(allowedV6.ok).toBe(true);
  });

  it("rejects unreadable CIDR policies even for loopback", async () => {
    await fixture.db
      .prepare("UPDATE bootstrap_tokens SET allowed_cidrs_json = ? WHERE id = ?")
      .bind("{", fixture.tokenRowId)
      .run();
    const result = await authenticateBootstrapRequest(upgrade(fixture.token, "::1"), fixture.db);
    expect(result).toMatchObject({ ok: false, reason: "cidr" });
  });

  it("ignores X-Forwarded-For when applying the CIDR policy", async () => {
    const restricted = await seed(["203.0.113.0/24"], null);
    const request = upgrade(restricted.token, "198.51.100.7");
    request.headers.set("X-Forwarded-For", "203.0.113.9");

    const result = await authenticateBootstrapRequest(request, restricted.db);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("cidr");
  });

  it("rejects a token in the query string before parsing it", async () => {
    const result = await authenticateBootstrapRequest(
      upgrade(null, "203.0.113.42", `https://vault.test/bootstrap/v1?token=${fixture.token}`),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("query_token");
    expect(result.closeCode).toBe(4401);
  });

  it("rejects a missing or malformed Authorization header", async () => {
    const missing = await authenticateBootstrapRequest(upgrade(null, "203.0.113.42"), fixture.db);
    expect(missing.ok).toBe(false);
    if (missing.ok) return;
    expect(missing.reason).toBe("missing_token");

    const malformed = await authenticateBootstrapRequest(
      upgrade("not-a-token", "203.0.113.42"),
      fixture.db,
    );
    expect(malformed.ok).toBe(false);
    if (malformed.ok) return;
    expect(malformed.reason).toBe("malformed_token");
  });

  it("rejects a token whose id is unknown", async () => {
    const other = await generateBootstrapToken();

    const result = await authenticateBootstrapRequest(
      upgrade(other.token, "203.0.113.42"),
      fixture.db,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("unknown_token");
    expect(result.closeCode).toBe(4401);
  });

  it("never puts token material in the rejection message", async () => {
    const [prefix] = fixture.token.split(".");
    const wrong = `${prefix ?? ""}.${"A".repeat(43)}`;

    const result = await authenticateBootstrapRequest(upgrade(wrong, "203.0.113.42"), fixture.db);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.message).not.toContain("vlt_boot_");
  });
});
