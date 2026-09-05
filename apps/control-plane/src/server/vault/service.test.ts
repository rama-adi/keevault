import { b64uDecode, decryptSecret } from "@env-vault/crypto";
import { getSecretForDelivery, listEnvironmentKeys } from "@env-vault/vault-store";
import { describe, expect, test } from "vite-plus/test";
import { z } from "zod";

import { createTestContext } from "./test-context.ts";
import type { VaultContext } from "./context.ts";
import { unwrapEnvironmentDek } from "./keys.ts";
import {
  createEnvironment,
  createProject,
  deleteEnvironment,
  deleteProject,
  deleteSecret,
  importDotenv,
  listAuditEvents,
  listBootstrapTokens,
  listEnvironments,
  listProjects,
  listSecretsMetadata,
  putSecret,
  rotateEnvironmentKey,
  rotateProjectKey,
  setEnvironmentPolicy,
  addTrustedSigner,
  createBootstrapToken,
  revokeBootstrapToken,
  revokeTrustedSigner,
  listTrustedSigners,
  updateTokenCidrs,
} from "./service.ts";
import { VaultInputError } from "./validation.ts";

const DATABASE_URL = "postgres://vault:hunter2@db.internal:5432/app";
const API_KEY = "sk-live-0123456789abcdef";

async function seed(context: VaultContext) {
  const project = await createProject(context, { slug: "acme", name: "Acme" });
  const production = await createEnvironment(context, {
    projectId: project.id,
    slug: "production",
    name: "Production",
  });
  const staging = await createEnvironment(context, {
    projectId: project.id,
    slug: "staging",
    name: "Staging",
  });
  return { project, production, staging };
}

async function readSecretValue(
  context: VaultContext,
  environmentId: string,
  name: string,
): Promise<string> {
  const row = await getSecretForDelivery(context.db, { environmentId, name });
  if (row === null) throw new Error(`missing secret ${name}`);
  const dek = await unwrapEnvironmentDek(context.db, context.keyring, environmentId);
  return await decryptSecret({
    environmentKey: dek.dek,
    nonce: b64uDecode(row.nonce),
    ciphertext: b64uDecode(row.ciphertext),
    projectId: dek.projectId,
    environmentId,
    secretId: row.id,
    secretName: row.name,
    secretVersion: row.secretVersion,
    environmentKeyVersion: row.envKeyVersion,
  });
}

describe("projects and environments", () => {
  test("creating a project wraps a project key under the active master version", async () => {
    const { context } = await createTestContext();
    const project = await createProject(context, { slug: "acme", name: "Acme" });
    expect(project.projectKeyVersion).toBe(1);
    expect((await listProjects(context)).map((row) => row.slug)).toEqual(["acme"]);
  });

  test("a duplicate slug is refused", async () => {
    const { context } = await createTestContext();
    await createProject(context, { slug: "acme", name: "Acme" });
    await expect(createProject(context, { slug: "acme", name: "Other" })).rejects.toBeInstanceOf(
      VaultInputError,
    );
  });

  test("creating an environment wraps a DEK under the project key", async () => {
    const { context } = await createTestContext();
    const { project, production } = await seed(context);
    expect(production.environmentKeyVersion).toBe(1);
    expect((await listEnvironments(context, project.id)).map((row) => row.slug)).toEqual([
      "production",
      "staging",
    ]);
    const dek = await unwrapEnvironmentDek(context.db, context.keyring, production.id);
    expect(dek.dek.length).toBe(32);
    expect(dek.projectId).toBe(project.id);
  });

  test("environment policy changes are stored", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    const updated = await setEnvironmentPolicy(context, {
      environmentId: production.id,
      provenanceMode: "REQUIRED",
      pendingTtlSeconds: 600,
      approvedTtlSeconds: 120,
    });
    expect(updated.provenanceMode).toBe("REQUIRED");
    expect(updated.pendingTtlSeconds).toBe(600);
  });

  test("deleting an environment removes its secrets, and deleting a project removes both", async () => {
    const { context } = await createTestContext();
    const { project, production, staging } = await seed(context);
    await putSecret(context, { environmentId: production.id, name: "API_KEY", value: API_KEY });
    await deleteEnvironment(context, production.id);
    expect((await listEnvironments(context, project.id)).map((row) => row.id)).toEqual([
      staging.id,
    ]);
    await deleteProject(context, project.id);
    expect(await listProjects(context)).toEqual([]);
  });
});

describe("secrets", () => {
  test("create, replace and delete", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);

    const created = await putSecret(context, {
      environmentId: production.id,
      name: "DATABASE_URL",
      value: DATABASE_URL,
    });
    expect(created.created).toBe(true);
    expect(created.secret.secretVersion).toBe(1);
    expect(await readSecretValue(context, production.id, "DATABASE_URL")).toBe(DATABASE_URL);

    const replaced = await putSecret(context, {
      environmentId: production.id,
      name: "DATABASE_URL",
      value: "postgres://vault:next@db.internal:5432/app",
    });
    expect(replaced.created).toBe(false);
    expect(replaced.secret.secretVersion).toBe(2);
    expect(replaced.secret.id).toBe(created.secret.id);
    expect(await readSecretValue(context, production.id, "DATABASE_URL")).toBe(
      "postgres://vault:next@db.internal:5432/app",
    );

    await deleteSecret(context, { environmentId: production.id, name: "DATABASE_URL" });
    expect(await listSecretsMetadata(context, production.id)).toEqual([]);
  });

  test("a secret name that is not a POSIX environment name is refused", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    await expect(
      putSecret(context, { environmentId: production.id, name: "not-a-name", value: "x" }),
    ).rejects.toBeInstanceOf(VaultInputError);
  });

  test("metadata listings never carry a value", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    await putSecret(context, { environmentId: production.id, name: "API_KEY", value: API_KEY });
    const listed = await listSecretsMetadata(context, production.id);
    expect(JSON.stringify(listed)).not.toContain(API_KEY);
    expect(listed[0]?.name).toBe("API_KEY");
  });

  test("a secret encrypted for one environment does not decrypt with another environment's AAD", async () => {
    const { context } = await createTestContext();
    const { production, staging } = await seed(context);
    await putSecret(context, { environmentId: production.id, name: "API_KEY", value: API_KEY });
    const row = await getSecretForDelivery(context.db, {
      environmentId: production.id,
      name: "API_KEY",
    });
    if (row === null) throw new Error("missing row");

    const productionDek = await unwrapEnvironmentDek(context.db, context.keyring, production.id);
    const stagingDek = await unwrapEnvironmentDek(context.db, context.keyring, staging.id);

    await expect(
      decryptSecret({
        environmentKey: stagingDek.dek,
        nonce: b64uDecode(row.nonce),
        ciphertext: b64uDecode(row.ciphertext),
        projectId: stagingDek.projectId,
        environmentId: staging.id,
        secretId: row.id,
        secretName: row.name,
        secretVersion: row.secretVersion,
        environmentKeyVersion: row.envKeyVersion,
      }),
    ).rejects.toThrow();

    await expect(
      decryptSecret({
        environmentKey: productionDek.dek,
        nonce: b64uDecode(row.nonce),
        ciphertext: b64uDecode(row.ciphertext),
        projectId: productionDek.projectId,
        environmentId: staging.id,
        secretId: row.id,
        secretName: row.name,
        secretVersion: row.secretVersion,
        environmentKeyVersion: row.envKeyVersion,
      }),
    ).rejects.toThrow();
  });
});

describe("dotenv import", () => {
  test("imports quoted, exported and commented lines and reports counts only", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    await putSecret(context, { environmentId: production.id, name: "API_KEY", value: "old" });

    const result = await importDotenv(context, {
      environmentId: production.id,
      content: [
        "# deployment settings",
        "",
        `DATABASE_URL=${DATABASE_URL}`,
        `export API_KEY="${API_KEY}"`,
        "GREETING='hello world'",
        'MULTILINE="line one\\nline two"',
        "PORT=8080 # the http port",
      ].join("\n"),
    });

    expect(result).toEqual({ created: 4, replaced: 1, parsed: 5 });
    expect(JSON.stringify(result)).not.toContain(API_KEY);
    expect(await readSecretValue(context, production.id, "DATABASE_URL")).toBe(DATABASE_URL);
    expect(await readSecretValue(context, production.id, "API_KEY")).toBe(API_KEY);
    expect(await readSecretValue(context, production.id, "GREETING")).toBe("hello world");
    expect(await readSecretValue(context, production.id, "MULTILINE")).toBe("line one\nline two");
    expect(await readSecretValue(context, production.id, "PORT")).toBe("8080");
  });

  test("an invalid name rejects the whole file", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    await expect(
      importDotenv(context, {
        environmentId: production.id,
        content: "GOOD=1\nbad-name=2\n",
      }),
    ).rejects.toBeInstanceOf(VaultInputError);
    expect(await listSecretsMetadata(context, production.id)).toEqual([]);
  });
});

describe("bootstrap tokens", () => {
  test("create shows the plaintext once, then revoke and edit CIDRs", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);

    const created = await createBootstrapToken(context, {
      environmentId: production.id,
      label: "zeabur-prod-1",
      allowedCidrs: ["203.0.113.44/32"],
      expiresAt: null,
      maxPendingBoots: 3,
    });
    expect(created.token).toMatch(/^vlt_boot_[0-9A-HJKMNP-TV-Z]{26}\.[A-Za-z0-9_-]{43}$/);
    expect(created.summary.allowedCidrs).toEqual(["203.0.113.44/32"]);
    expect(JSON.stringify(created.summary)).not.toContain(created.token);

    const stored = await context.db
      .prepare("SELECT token_hash AS tokenHash FROM bootstrap_tokens WHERE id = ?")
      .bind(created.summary.id)
      .first<{ tokenHash: string }>();
    expect(stored?.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(created.token).not.toContain(stored?.tokenHash ?? "");

    const edited = await updateTokenCidrs(context, {
      tokenRowId: created.summary.id,
      allowedCidrs: ["198.51.100.0/24", "2001:db8::/32"],
    });
    expect(edited.allowedCidrs).toHaveLength(2);

    await expect(
      updateTokenCidrs(context, {
        tokenRowId: created.summary.id,
        allowedCidrs: ["not-a-cidr"],
      }),
    ).rejects.toBeInstanceOf(VaultInputError);

    await revokeBootstrapToken(context, created.summary.id);
    const listed = await listBootstrapTokens(context, production.id);
    expect(listed[0]?.revokedAt).not.toBeNull();
  });
});

describe("trusted signers", () => {
  test("an Ed25519 key is accepted and fingerprinted, junk is refused", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const publicKey = btoa(String.fromCharCode(...raw))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");

    const signer = await addTrustedSigner(context, {
      environmentId: production.id,
      label: "acme-ci",
      publicKey,
      projectWide: false,
    });
    expect(signer.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(await listTrustedSigners(context, production.id)).toHaveLength(1);

    await expect(
      addTrustedSigner(context, {
        environmentId: production.id,
        label: "bad",
        publicKey: "AAAA",
        projectWide: false,
      }),
    ).rejects.toBeInstanceOf(VaultInputError);

    await revokeTrustedSigner(context, {
      environmentId: production.id,
      signerId: signer.id,
    });
    expect((await listTrustedSigners(context, production.id))[0]?.enabled).toBe(false);
  });
});

describe("rotation", () => {
  test("environment rotation re-encrypts every secret and retires the old key", async () => {
    const { context } = await createTestContext();
    const { production } = await seed(context);
    await putSecret(context, {
      environmentId: production.id,
      name: "DATABASE_URL",
      value: DATABASE_URL,
    });
    await putSecret(context, { environmentId: production.id, name: "API_KEY", value: API_KEY });
    const before = await getSecretForDelivery(context.db, {
      environmentId: production.id,
      name: "API_KEY",
    });

    const result = await rotateEnvironmentKey(context, production.id);
    expect(result).toMatchObject({ previousVersion: 1, version: 2, secretsReencrypted: 2 });

    const after = await getSecretForDelivery(context.db, {
      environmentId: production.id,
      name: "API_KEY",
    });
    expect(after?.ciphertext).not.toBe(before?.ciphertext);
    expect(after?.envKeyVersion).toBe(2);
    expect(after?.secretVersion).toBe(before?.secretVersion);

    expect(await readSecretValue(context, production.id, "DATABASE_URL")).toBe(DATABASE_URL);
    expect(await readSecretValue(context, production.id, "API_KEY")).toBe(API_KEY);

    const keys = await listEnvironmentKeys(context.db, production.id);
    expect(keys.find((row) => row.version === 1)?.status).toBe("retired");
    expect(keys.find((row) => row.version === 1)?.retiredAt).not.toBeNull();
    expect(keys.find((row) => row.version === 2)?.status).toBe("active");
  });

  test("project rotation rewraps environment keys without touching secrets", async () => {
    const { context } = await createTestContext();
    const { project, production, staging } = await seed(context);
    await putSecret(context, {
      environmentId: production.id,
      name: "DATABASE_URL",
      value: DATABASE_URL,
    });
    await rotateEnvironmentKey(context, production.id);
    const beforeCiphertext = (
      await getSecretForDelivery(context.db, {
        environmentId: production.id,
        name: "DATABASE_URL",
      })
    )?.ciphertext;

    const result = await rotateProjectKey(context, project.id);
    expect(result).toMatchObject({ previousVersion: 1, version: 2 });
    expect(result.environmentKeysRewrapped).toBe(3);

    const afterCiphertext = (
      await getSecretForDelivery(context.db, {
        environmentId: production.id,
        name: "DATABASE_URL",
      })
    )?.ciphertext;
    expect(afterCiphertext).toBe(beforeCiphertext);
    expect(await readSecretValue(context, production.id, "DATABASE_URL")).toBe(DATABASE_URL);

    const stagingDek = await unwrapEnvironmentDek(context.db, context.keyring, staging.id);
    expect(stagingDek.dek.length).toBe(32);

    const projectKeys = await context.db
      .prepare("SELECT status AS status FROM project_keys WHERE project_id = ? AND version = 1")
      .bind(project.id)
      .first<{ status: string }>();
    expect(projectKeys?.status).toBe("retired");
  });
});

const rowSchema = z.array(z.record(z.string(), z.union([z.string(), z.number(), z.null()])));

const VAULT_TABLES = [
  "projects",
  "project_keys",
  "environments",
  "environment_keys",
  "secrets",
  "bootstrap_tokens",
  "provenance_policies",
  "trusted_signers",
  "audit_events",
] as const;

async function dumpVault(context: VaultContext): Promise<string> {
  const parts: string[] = [];
  for (const table of VAULT_TABLES) {
    const result = await context.db.prepare(`SELECT * FROM ${table}`).all();
    parts.push(JSON.stringify(rowSchema.parse(result.results)));
  }
  return parts.join("\n");
}

/** Everything one full scenario touches, so one dump covers every write path. */
async function runFullScenario(context: VaultContext): Promise<{ token: string }> {
  const { project, production, staging } = await seed(context);
  await putSecret(context, {
    environmentId: production.id,
    name: "DATABASE_URL",
    value: DATABASE_URL,
  });
  await putSecret(context, { environmentId: production.id, name: "API_KEY", value: API_KEY });
  await putSecret(context, { environmentId: production.id, name: "API_KEY", value: API_KEY });
  await importDotenv(context, {
    environmentId: staging.id,
    content: `DATABASE_URL=${DATABASE_URL}\nexport API_KEY="${API_KEY}"\n`,
  });
  await deleteSecret(context, { environmentId: staging.id, name: "DATABASE_URL" });
  const token = await createBootstrapToken(context, {
    environmentId: production.id,
    label: "zeabur-prod-1",
    allowedCidrs: ["203.0.113.44/32"],
    expiresAt: null,
    maxPendingBoots: 3,
  });
  await updateTokenCidrs(context, {
    tokenRowId: token.summary.id,
    allowedCidrs: ["198.51.100.0/24"],
  });
  await revokeBootstrapToken(context, token.summary.id);
  await setEnvironmentPolicy(context, {
    environmentId: production.id,
    provenanceMode: "REQUIRED",
    pendingTtlSeconds: 900,
    approvedTtlSeconds: 120,
  });
  await rotateEnvironmentKey(context, production.id);
  await rotateProjectKey(context, project.id);
  await deleteEnvironment(context, staging.id);
  return { token: token.token };
}

describe("redaction", () => {
  test("no audit metadata written during a full scenario contains plaintext", async () => {
    const { context } = await createTestContext();
    const { token } = await runFullScenario(context);
    const page = await listAuditEvents(context, {
      projectId: null,
      environmentId: null,
      before: null,
      limit: 500,
    });
    expect(page.events.length).toBeGreaterThan(10);
    const metadata = page.events.map((event) => event.metadataJson).join("\n");
    for (const marker of [DATABASE_URL, API_KEY, "hunter2", token, token.split(".")[1] ?? ""]) {
      expect(metadata).not.toContain(marker);
    }
    expect(metadata).toContain("secretsReencrypted");
  });

  test("no row in any table holds a plaintext value or a key in the clear", async () => {
    const { context } = await createTestContext();
    const { token } = await runFullScenario(context);
    const dump = await dumpVault(context);
    for (const marker of [DATABASE_URL, API_KEY, "hunter2", token, token.split(".")[1] ?? ""]) {
      expect(dump).not.toContain(marker);
    }
    const masterKey = context.keyring.key(context.keyring.activeVersion);
    expect(dump).not.toContain(btoa(String.fromCharCode(...masterKey)).replaceAll("=", ""));
  });
});
