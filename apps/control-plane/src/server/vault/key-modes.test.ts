import {
  b64uEncode,
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  generateX25519PrivateKey,
  x25519PublicKeyFromPrivate,
  randomBytes,
} from "@keevault/crypto";
import {
  listEnvironmentKeys,
  getEnvironment,
  insertColdEnvironmentKey,
  listColdEnvironmentKeys,
} from "@keevault/vault-store";
import { describe, expect, test } from "vite-plus/test";
import { createTestContext } from "./test-context.ts";
import {
  createProject,
  createEnvironment,
  putSecret,
  importDotenv,
  rotateEnvironmentKey,
  rotateProjectKey,
} from "./service.ts";
import { unwrapEnvironmentDek } from "./keys.ts";

async function cold() {
  const { context } = await createTestContext();
  const project = await createProject(context, { slug: "cold", name: "Cold" });
  const encryption = b64uEncode(await x25519PublicKeyFromPrivate(generateX25519PrivateKey()));
  const signing = b64uEncode(await ed25519PublicKeyFromSeed(generateEd25519Seed()));
  const environment = await createEnvironment(context, {
    projectId: project.id,
    slug: "prod",
    name: "Prod",
    keyMode: "COLD",
    ownerEncryptionPublicKey: encryption,
    ownerSigningPublicKey: signing,
  });
  return { context, project, environment, encryption, signing };
}

describe("cold key mode", () => {
  test("persists owner keys without a server environment key", async () => {
    const { context, environment, encryption, signing } = await cold();
    expect(environment.keyMode).toBe("COLD");
    expect(await getEnvironment(context.db, environment.id)).toMatchObject({
      ownerEncryptionPublicKey: encryption,
      ownerSigningPublicKey: signing,
      currentEnvKeyVersion: 0,
    });
    expect(await listEnvironmentKeys(context.db, environment.id)).toEqual([]);
    await expect(
      unwrapEnvironmentDek(context.db, context.keyring, environment.id),
    ).rejects.toThrow();
  });
  test("rejects plaintext operations and rotation", async () => {
    const { context, environment } = await cold();
    await expect(
      putSecret(context, { environmentId: environment.id, name: "A", value: "B" }),
    ).rejects.toThrow();
    await expect(
      importDotenv(context, { environmentId: environment.id, content: "" }),
    ).rejects.toThrow("Cold environments require encrypted imports");
    await expect(rotateEnvironmentKey(context, environment.id)).rejects.toThrow();
    await expect(
      importDotenv(context, { environmentId: environment.id, content: "A=private" }),
    ).rejects.toThrow("Cold environments require encrypted imports");
  });
  test("database mode discriminators reject cross-mode rows", async () => {
    const { context, environment } = await cold();
    await expect(
      context.db
        .prepare(
          "INSERT INTO environment_keys (environment_id, key_mode, version, project_key_version, wrapped_key, nonce, created_at) VALUES (?, 'CLOUD', 1, 1, 'x', 'x', 'now')",
        )
        .bind(environment.id)
        .run(),
    ).rejects.toThrow();
  });

  test("stores cold envelopes only for the pinned owner and skips them during project rotation", async () => {
    const { context, project, environment, encryption } = await cold();
    const cloud = await createEnvironment(context, {
      projectId: project.id,
      slug: "cloud",
      name: "Cloud",
    });
    const input = {
      environmentId: environment.id,
      version: 1,
      recipientPublicKey: encryption,
      ephemeralPublicKey: b64uEncode(await x25519PublicKeyFromPrivate(generateX25519PrivateKey())),
      salt: b64uEncode(randomBytes(32)),
      nonce: b64uEncode(randomBytes(12)),
      wrappedKey: b64uEncode(randomBytes(48)),
      now: context.now(),
    };
    await insertColdEnvironmentKey(context.db, input);
    const before = await listColdEnvironmentKeys(context.db, environment.id);
    expect(before).toHaveLength(1);
    await expect(
      insertColdEnvironmentKey(context.db, { ...input, environmentId: cloud.id }),
    ).rejects.toThrow();
    await expect(
      insertColdEnvironmentKey(context.db, {
        ...input,
        version: 2,
        recipientPublicKey: input.ephemeralPublicKey,
      }),
    ).rejects.toThrow();
    await expect(
      context.db
        .prepare(
          "UPDATE environments SET key_mode = 'CLOUD', owner_encryption_public_key = NULL, owner_signing_public_key = NULL WHERE id = ?",
        )
        .bind(environment.id)
        .run(),
    ).rejects.toThrow();
    expect(await rotateProjectKey(context, project.id)).toMatchObject({
      environmentKeysRewrapped: 1,
    });
    expect(await listColdEnvironmentKeys(context.db, environment.id)).toEqual(before);
  });
});
