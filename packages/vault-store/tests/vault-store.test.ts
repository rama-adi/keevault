import { beforeEach, describe, expect, test } from "vite-plus/test";

import {
  addTrustedSigner,
  appendAuditEvent,
  cancelBootRequestsForToken,
  countPendingBootRequestsByToken,
  createBootstrapToken,
  createEnvironment,
  createProject,
  deleteEnvironment,
  deleteSecret,
  findTrustedSignersByFingerprint,
  getBootApproval,
  getBootRequest,
  getBootstrapTokenByTokenId,
  getCurrentEnvironmentKey,
  getCurrentProjectKey,
  getProjectBySlug,
  insertBootApproval,
  insertBootRequest,
  insertEnvironmentKey,
  insertProjectKey,
  listAuditEventsByEnvironment,
  listAuditEventsByProject,
  listBootstrapTokensByEnvironment,
  listEnvironmentKeys,
  listEnvironmentsByProject,
  listPendingBootRequestsByEnvironment,
  listProjects,
  listRecentBootRequestsByEnvironment,
  listSecretMetadata,
  listSecretsForDelivery,
  listTrustedSignersForEnvironment,
  revokeBootstrapToken,
  revokeTrustedSigner,
  setCurrentProjectKeyVersion,
  switchCurrentEnvironmentKey,
  touchBootstrapTokenLastSeen,
  updateBootRequestStatus,
  updateBootstrapTokenCidrs,
  updateEnvironmentPolicy,
  upsertProvenancePolicy,
  upsertSecretReplace,
} from "../src/index.ts";
import type { VaultDatabase } from "../src/index.ts";
import { createTestVault, LATER, NOW } from "./helpers.ts";

let db: VaultDatabase;

const PROJECT_ID = "proj_01K4ABCDEFGHJKMNPQRSTVWXYZ";
const ENVIRONMENT_ID = "env_01K4ABCDEFGHJKMNPQRSTVWXYZ";
const TOKEN_ULID = "01K4ABCDEFGHJKMNPQRSTVWXYZ";
const TOKEN_ROW_ID = `tok_${TOKEN_ULID}`;

async function seedProject(): Promise<void> {
  await createProject(db, {
    id: PROJECT_ID,
    slug: "acme",
    name: "Acme",
    now: NOW,
  });
}

async function seedEnvironment(): Promise<void> {
  await seedProject();
  await createEnvironment(db, {
    id: ENVIRONMENT_ID,
    projectId: PROJECT_ID,
    slug: "production",
    name: "Production",
    provenanceMode: "ADVISORY",
    pendingTtlSeconds: 1800,
    approvedTtlSeconds: 300,
    now: NOW,
  });
}

async function seedToken(): Promise<void> {
  await createBootstrapToken(db, {
    id: TOKEN_ROW_ID,
    environmentId: ENVIRONMENT_ID,
    label: "zeabur-prod-1",
    tokenHash: "a".repeat(64),
    allowedCidrsJson: JSON.stringify(["203.0.113.44/32"]),
    maxPendingBoots: 3,
    expiresAt: null,
    now: NOW,
  });
}

beforeEach(async () => {
  const vault = await createTestVault();
  db = vault.db;
});

describe("projects", () => {
  test("create, read back and list", async () => {
    const created = await createProject(db, {
      id: PROJECT_ID,
      slug: "acme",
      name: "Acme",
      now: NOW,
    });
    expect(created.slug).toBe("acme");
    expect(created.currentProjectKeyVersion).toBe(0);

    const bySlug = await getProjectBySlug(db, "acme");
    expect(bySlug?.id).toBe(PROJECT_ID);
    expect(await listProjects(db)).toHaveLength(1);
  });

  test("slug is unique", async () => {
    await seedProject();
    await expect(
      createProject(db, { id: "proj_OTHER", slug: "acme", name: "Other", now: NOW }),
    ).rejects.toThrow();
  });
});

describe("environments", () => {
  test("create applies the spec defaults and reads back by project", async () => {
    await seedEnvironment();
    const environments = await listEnvironmentsByProject(db, PROJECT_ID);
    expect(environments).toHaveLength(1);
    const environment = environments[0];
    expect(environment?.pendingTtlSeconds).toBe(1800);
    expect(environment?.approvedTtlSeconds).toBe(300);
    expect(environment?.provenanceMode).toBe("ADVISORY");
  });

  test("slug is unique per project only", async () => {
    await seedEnvironment();
    await expect(
      createEnvironment(db, {
        id: "env_OTHER",
        projectId: PROJECT_ID,
        slug: "production",
        name: "Production again",
        provenanceMode: "OFF",
        pendingTtlSeconds: 60,
        approvedTtlSeconds: 30,
        now: NOW,
      }),
    ).rejects.toThrow();
  });

  test("policy update changes mode and both ttls", async () => {
    await seedEnvironment();
    const updated = await updateEnvironmentPolicy(db, {
      environmentId: ENVIRONMENT_ID,
      provenanceMode: "REQUIRED",
      pendingTtlSeconds: 900,
      approvedTtlSeconds: 120,
      now: LATER,
    });
    expect(updated.provenanceMode).toBe("REQUIRED");
    expect(updated.pendingTtlSeconds).toBe(900);
    expect(updated.approvedTtlSeconds).toBe(120);
  });

  test("provenance mode is constrained", async () => {
    await seedProject();
    await expect(
      db
        .prepare(
          `INSERT INTO environments
             (id, project_id, slug, name, current_env_key_version, provenance_mode,
              pending_ttl_seconds, approved_ttl_seconds, created_at, updated_at)
           VALUES (?, ?, 'staging', 'Staging', 0, 'MAYBE', 1800, 300, ?, ?)`,
        )
        .bind("env_BAD", PROJECT_ID, NOW, NOW)
        .run(),
    ).rejects.toThrow();
  });
});

describe("keys", () => {
  test("current project key follows the project pointer", async () => {
    await seedProject();
    await insertProjectKey(db, {
      projectId: PROJECT_ID,
      version: 1,
      masterKeyVersion: 1,
      wrappedKey: "d3JhcHBlZC1wcm9qZWN0LWtleQ",
      nonce: "bm9uY2UtcHJvamVjdA",
      now: NOW,
    });
    await setCurrentProjectKeyVersion(db, { projectId: PROJECT_ID, version: 1, now: NOW });

    const current = await getCurrentProjectKey(db, PROJECT_ID);
    expect(current?.version).toBe(1);
    expect(current?.status).toBe("active");
  });

  test("environment key version switch is atomic", async () => {
    await seedEnvironment();
    await insertEnvironmentKey(db, {
      environmentId: ENVIRONMENT_ID,
      version: 1,
      projectKeyVersion: 1,
      wrappedKey: "d3JhcHBlZC12MQ",
      nonce: "bm9uY2UtdjE",
      now: NOW,
    });
    await switchCurrentEnvironmentKey(db, {
      environmentId: ENVIRONMENT_ID,
      previousVersion: 0,
      nextVersion: 1,
      now: NOW,
    });
    await insertEnvironmentKey(db, {
      environmentId: ENVIRONMENT_ID,
      version: 2,
      projectKeyVersion: 1,
      wrappedKey: "d3JhcHBlZC12Mg",
      nonce: "bm9uY2UtdjI",
      now: LATER,
    });
    await switchCurrentEnvironmentKey(db, {
      environmentId: ENVIRONMENT_ID,
      previousVersion: 1,
      nextVersion: 2,
      now: LATER,
    });

    const current = await getCurrentEnvironmentKey(db, ENVIRONMENT_ID);
    expect(current?.version).toBe(2);
    expect(current?.status).toBe("active");

    const keys = await listEnvironmentKeys(db, ENVIRONMENT_ID);
    expect(keys).toHaveLength(2);
    expect(keys[0]?.status).toBe("retired");
    expect(keys[0]?.retiredAt).toBe(LATER);
  });

  test("key status is constrained", async () => {
    await seedEnvironment();
    await expect(
      db
        .prepare(
          `INSERT INTO environment_keys
             (environment_id, version, project_key_version, wrapped_key, nonce, status, created_at)
           VALUES (?, 9, 1, 'x', 'y', 'expired', ?)`,
        )
        .bind(ENVIRONMENT_ID, NOW)
        .run(),
    ).rejects.toThrow();
  });
});

describe("secrets", () => {
  test("write, replace with a version bump, and delete", async () => {
    await seedEnvironment();
    const created = await upsertSecretReplace(db, {
      expectedVersion: 0,
      id: "sec_01K4ABCDEFGHJKMNPQRSTVWXYZ",
      environmentId: ENVIRONMENT_ID,
      name: "DATABASE_URL",
      ciphertext: "Y2lwaGVydGV4dC12MQ",
      nonce: "bm9uY2UtdjE",
      envKeyVersion: 1,
      now: NOW,
    });
    expect(created.secretVersion).toBe(1);

    const replaced = await upsertSecretReplace(db, {
      expectedVersion: 1,
      id: created.id,
      environmentId: ENVIRONMENT_ID,
      name: "DATABASE_URL",
      ciphertext: "Y2lwaGVydGV4dC12Mg",
      nonce: "bm9uY2UtdjI",
      envKeyVersion: 2,
      now: LATER,
    });
    expect(replaced.secretVersion).toBe(2);
    expect(replaced.id).toBe(created.id);
    expect(replaced.envKeyVersion).toBe(2);

    const delivery = await listSecretsForDelivery(db, ENVIRONMENT_ID);
    expect(delivery).toHaveLength(1);
    expect(delivery[0]?.ciphertext).toBe("Y2lwaGVydGV4dC12Mg");

    await deleteSecret(db, { environmentId: ENVIRONMENT_ID, name: "DATABASE_URL" });
    expect(await listSecretMetadata(db, ENVIRONMENT_ID)).toHaveLength(0);
  });

  test("metadata listing carries no ciphertext", async () => {
    await seedEnvironment();
    await upsertSecretReplace(db, {
      expectedVersion: 0,
      id: "sec_META",
      environmentId: ENVIRONMENT_ID,
      name: "API_KEY",
      ciphertext: "Y2lwaGVydGV4dA",
      nonce: "bm9uY2U",
      envKeyVersion: 1,
      now: NOW,
    });
    const metadata = await listSecretMetadata(db, ENVIRONMENT_ID);
    expect(metadata).toHaveLength(1);
    expect(JSON.stringify(metadata)).not.toContain("Y2lwaGVydGV4dA");
  });

  test("the same name cannot exist twice in one environment", async () => {
    await seedEnvironment();
    await upsertSecretReplace(db, {
      expectedVersion: 0,
      id: "sec_ONE",
      environmentId: ENVIRONMENT_ID,
      name: "API_KEY",
      ciphertext: "YQ",
      nonce: "Yg",
      envKeyVersion: 1,
      now: NOW,
    });
    await expect(
      db
        .prepare(
          `INSERT INTO secrets
             (id, environment_id, name, ciphertext, nonce, env_key_version, secret_version,
              created_at, updated_at)
           VALUES ('sec_TWO', ?, 'API_KEY', 'Yw', 'Yg', 1, 1, ?, ?)`,
        )
        .bind(ENVIRONMENT_ID, NOW, NOW)
        .run(),
    ).rejects.toThrow();
  });
});

describe("bootstrap tokens", () => {
  test("create, look up by token id, revoke", async () => {
    await seedEnvironment();
    await seedToken();

    const found = await getBootstrapTokenByTokenId(db, TOKEN_ULID);
    expect(found?.tokenHash).toBe("a".repeat(64));
    expect(found?.maxPendingBoots).toBe(3);

    await revokeBootstrapToken(db, { tokenRowId: TOKEN_ROW_ID, now: LATER });
    const revoked = await getBootstrapTokenByTokenId(db, TOKEN_ULID);
    expect(revoked?.revokedAt).toBe(LATER);
  });

  test("listings never return the stored hash", async () => {
    await seedEnvironment();
    await seedToken();
    const listed = await listBootstrapTokensByEnvironment(db, ENVIRONMENT_ID);
    expect(listed).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain("a".repeat(64));
  });

  test("last seen and cidrs update", async () => {
    await seedEnvironment();
    await seedToken();
    await touchBootstrapTokenLastSeen(db, { tokenRowId: TOKEN_ROW_ID, now: LATER });
    const updated = await updateBootstrapTokenCidrs(db, {
      tokenRowId: TOKEN_ROW_ID,
      allowedCidrsJson: JSON.stringify(["198.51.100.0/24"]),
    });
    expect(updated.allowedCidrsJson).toBe(JSON.stringify(["198.51.100.0/24"]));
    const found = await getBootstrapTokenByTokenId(db, TOKEN_ULID);
    expect(found?.lastSeenAt).toBe(LATER);
  });
});

describe("boot requests", () => {
  async function seedBoot(bootId: string): Promise<void> {
    await insertBootRequest(db, {
      id: bootId,
      environmentId: ENVIRONMENT_ID,
      bootstrapTokenId: TOKEN_ROW_ID,
      status: "PENDING",
      sourceIp: "203.0.113.44",
      signingPublicKey: "c2lnbmluZy1rZXk",
      encryptionPublicKey: "ZW5jcnlwdGlvbi1rZXk",
      claimedGitRepository: "github.com/acme/foo",
      claimedGitCommit: "a".repeat(40),
      claimedOciRepository: null,
      claimedOciDigest: null,
      provenanceSummaryJson: null,
      now: NOW,
    });
  }

  test("status update keeps earlier timestamps and records new ones", async () => {
    await seedEnvironment();
    await seedToken();
    await seedBoot("boot_01K4ABCDEFGHJKMNPQRSTVWXYZ");

    const approved = await updateBootRequestStatus(db, {
      bootId: "boot_01K4ABCDEFGHJKMNPQRSTVWXYZ",
      status: "APPROVED",
      approvedAt: NOW,
      approvedBy: "user_1",
      now: NOW,
    });
    expect(approved.status).toBe("APPROVED");
    expect(approved.approvedAt).toBe(NOW);

    const consumed = await updateBootRequestStatus(db, {
      bootId: "boot_01K4ABCDEFGHJKMNPQRSTVWXYZ",
      status: "CONSUMED",
      consumedAt: LATER,
      now: LATER,
    });
    expect(consumed.status).toBe("CONSUMED");
    expect(consumed.approvedAt).toBe(NOW);
    expect(consumed.consumedAt).toBe(LATER);
  });

  test("pending listing, recent listing and per-token count", async () => {
    await seedEnvironment();
    await seedToken();
    await seedBoot("boot_A");
    await seedBoot("boot_B");

    expect(await countPendingBootRequestsByToken(db, TOKEN_ROW_ID)).toBe(2);
    expect(await listPendingBootRequestsByEnvironment(db, ENVIRONMENT_ID)).toHaveLength(2);
    expect(
      await listRecentBootRequestsByEnvironment(db, { environmentId: ENVIRONMENT_ID, limit: 1 }),
    ).toHaveLength(1);

    await cancelBootRequestsForToken(db, { bootstrapTokenId: TOKEN_ROW_ID, now: LATER });
    expect(await countPendingBootRequestsByToken(db, TOKEN_ROW_ID)).toBe(0);
    const canceled = await getBootRequest(db, "boot_A");
    expect(canceled?.status).toBe("CANCELED");
    expect(canceled?.canceledAt).toBe(LATER);
  });

  test("status values are constrained", async () => {
    await seedEnvironment();
    await seedToken();
    await expect(
      db
        .prepare(
          `INSERT INTO boot_requests
             (id, environment_id, bootstrap_token_id, status, signing_public_key,
              encryption_public_key, created_at, updated_at)
           VALUES ('boot_BAD', ?, ?, 'WAITING', 'a', 'b', ?, ?)`,
        )
        .bind(ENVIRONMENT_ID, TOKEN_ROW_ID, NOW, NOW)
        .run(),
    ).rejects.toThrow();
  });

  test("approval record is stored and read back", async () => {
    await seedEnvironment();
    await seedToken();
    await seedBoot("boot_A");
    await insertBootApproval(db, {
      bootId: "boot_A",
      approverUserId: "user_1",
      approverCredentialId: "cred_1",
      approvedAt: NOW,
      clientSigningFingerprint: "b".repeat(64),
      clientEncryptionFingerprint: "c".repeat(64),
      evidenceDigest: "d".repeat(64),
      keyMode: "CLOUD",
      environmentKeyVersion: 1,
      releaseContextDigest: "e".repeat(64),
    });
    const approval = await getBootApproval(db, "boot_A");
    expect(approval?.approverCredentialId).toBe("cred_1");
    expect(approval?.evidenceDigest).toBe("d".repeat(64));
  });
});

describe("provenance policies and trusted signers", () => {
  test("policy upsert replaces configuration for the same verifier", async () => {
    await seedEnvironment();
    const created = await upsertProvenancePolicy(db, {
      id: "pol_ONE",
      environmentId: ENVIRONMENT_ID,
      verifierType: "signed-build-manifest-v1",
      configurationJson: JSON.stringify({ builder: "acme-ci" }),
      required: false,
      enabled: true,
      now: NOW,
    });
    expect(created.required).toBe(false);
    expect(created.enabled).toBe(true);

    const updated = await upsertProvenancePolicy(db, {
      id: "pol_TWO",
      environmentId: ENVIRONMENT_ID,
      verifierType: "signed-build-manifest-v1",
      configurationJson: JSON.stringify({ builder: "acme-ci-2" }),
      required: true,
      enabled: true,
      now: LATER,
    });
    expect(updated.id).toBe("pol_ONE");
    expect(updated.required).toBe(true);
  });

  test("environment signer lookup includes project-wide signers", async () => {
    await seedEnvironment();
    await addTrustedSigner(db, {
      id: "sig_PROJECT",
      projectId: PROJECT_ID,
      environmentId: null,
      type: "ed25519",
      label: "acme-ci",
      publicKey: "cHVibGljLWtleQ",
      fingerprint: "e".repeat(64),
      now: NOW,
    });
    await addTrustedSigner(db, {
      id: "sig_ENV",
      projectId: null,
      environmentId: ENVIRONMENT_ID,
      type: "ed25519",
      label: "prod-only",
      publicKey: "cHVibGljLWtleS0y",
      fingerprint: "f".repeat(64),
      now: NOW,
    });

    expect(await listTrustedSignersForEnvironment(db, ENVIRONMENT_ID)).toHaveLength(2);
    expect(
      await findTrustedSignersByFingerprint(db, {
        environmentId: ENVIRONMENT_ID,
        fingerprint: "e".repeat(64),
      }),
    ).toHaveLength(1);

    await revokeTrustedSigner(db, { signerId: "sig_PROJECT", now: LATER });
    expect(
      await findTrustedSignersByFingerprint(db, {
        environmentId: ENVIRONMENT_ID,
        fingerprint: "e".repeat(64),
      }),
    ).toHaveLength(0);
  });
});

describe("audit events", () => {
  test("append and page backwards with a cursor", async () => {
    await seedEnvironment();
    for (const suffix of ["A", "B", "C"]) {
      await appendAuditEvent(db, {
        id: `aud_${suffix}`,
        timestamp: NOW,
        actorType: "user",
        actorId: "user_1",
        action: "secret.created",
        projectId: PROJECT_ID,
        environmentId: ENVIRONMENT_ID,
        bootId: null,
        metadataJson: JSON.stringify({ name: "API_KEY" }),
      });
    }

    const byProject = await listAuditEventsByProject(db, {
      id: PROJECT_ID,
      limit: 2,
      before: null,
    });
    expect(byProject.map((event) => event.id)).toEqual(["aud_C", "aud_B"]);

    const nextPage = await listAuditEventsByProject(db, {
      id: PROJECT_ID,
      limit: 2,
      before: "aud_B",
    });
    expect(nextPage.map((event) => event.id)).toEqual(["aud_A"]);

    const byEnvironment = await listAuditEventsByEnvironment(db, {
      id: ENVIRONMENT_ID,
      limit: 10,
      before: null,
    });
    expect(byEnvironment).toHaveLength(3);
  });
});

describe("cascades", () => {
  test("deleting an environment removes its keys, secrets, tokens and boots", async () => {
    await seedEnvironment();
    await seedToken();
    await insertEnvironmentKey(db, {
      environmentId: ENVIRONMENT_ID,
      version: 1,
      projectKeyVersion: 1,
      wrappedKey: "d3JhcHBlZA",
      nonce: "bm9uY2U",
      now: NOW,
    });
    await upsertSecretReplace(db, {
      expectedVersion: 0,
      id: "sec_ONE",
      environmentId: ENVIRONMENT_ID,
      name: "API_KEY",
      ciphertext: "YQ",
      nonce: "Yg",
      envKeyVersion: 1,
      now: NOW,
    });
    await insertBootRequest(db, {
      id: "boot_A",
      environmentId: ENVIRONMENT_ID,
      bootstrapTokenId: TOKEN_ROW_ID,
      status: "PENDING",
      sourceIp: null,
      signingPublicKey: "a",
      encryptionPublicKey: "b",
      claimedGitRepository: null,
      claimedGitCommit: null,
      claimedOciRepository: null,
      claimedOciDigest: null,
      provenanceSummaryJson: null,
      now: NOW,
    });
    await insertBootApproval(db, {
      bootId: "boot_A",
      approverUserId: "user_1",
      approverCredentialId: "cred_1",
      approvedAt: NOW,
      clientSigningFingerprint: "b".repeat(64),
      clientEncryptionFingerprint: "c".repeat(64),
      evidenceDigest: "d".repeat(64),
      keyMode: "CLOUD",
      environmentKeyVersion: 1,
      releaseContextDigest: "e".repeat(64),
    });

    await deleteEnvironment(db, ENVIRONMENT_ID);

    expect(await listSecretMetadata(db, ENVIRONMENT_ID)).toHaveLength(0);
    expect(await listEnvironmentKeys(db, ENVIRONMENT_ID)).toHaveLength(0);
    expect(await listBootstrapTokensByEnvironment(db, ENVIRONMENT_ID)).toHaveLength(0);
    expect(await getBootRequest(db, "boot_A")).toBeNull();
    expect(await getBootApproval(db, "boot_A")).toBeNull();
    expect(await listEnvironmentsByProject(db, PROJECT_ID)).toHaveLength(0);
  });
});
