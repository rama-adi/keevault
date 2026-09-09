import {
  b64uEncode,
  generateEd25519Seed,
  generateX25519PrivateKey,
  openBootEnvelope,
  x25519PublicKeyFromPrivate,
  ed25519PublicKeyFromSeed,
} from "@keevault/crypto";
import { unwrapEnvironmentDek } from "./keys.ts";
import { describe, expect, test } from "vite-plus/test";

import { createEnvironment, createProject } from "./service.ts";
import { createTestContext } from "./test-context.ts";
import { createCloudKeyRelease, KeyReleaseError } from "./key-release.ts";

async function cloudFixture() {
  const { context } = await createTestContext();
  const project = await createProject(context, { slug: "acme", name: "Acme" });
  const environment = await createEnvironment(context, {
    projectId: project.id,
    slug: "production",
    name: "Production",
  });
  return { context, project, environment };
}

async function coldKeys() {
  const encryptionPrivateKey = generateX25519PrivateKey();
  const signingSeed = generateEd25519Seed();
  return {
    ownerEncryptionPublicKey: b64uEncode(await x25519PublicKeyFromPrivate(encryptionPrivateKey)),
    ownerSigningPublicKey: b64uEncode(await ed25519PublicKeyFromSeed(signingSeed)),
  };
}

describe("cloud key release", () => {
  test("encrypts the current DEK for the workload recipient", async () => {
    const { context, project, environment } = await cloudFixture();
    const privateKey = generateX25519PrivateKey();
    const envelope = await createCloudKeyRelease(context.db, context.keyring, {
      bootId: "boot_test",
      environmentId: environment.id,
      projectId: project.id,
      keyMode: "CLOUD",
      environmentKeyVersion: environment.environmentKeyVersion,
      recipientPublicKey: b64uEncode(await x25519PublicKeyFromPrivate(privateKey)),
    });
    const dek = await openBootEnvelope({
      bootId: "boot_test",
      environmentId: environment.id,
      environmentKeyVersion: environment.environmentKeyVersion,
      clientPrivateKey: privateKey,
      envelope,
    });
    const expected = await unwrapEnvironmentDek(context.db, context.keyring, environment.id);
    expect(dek).toEqual(expected.dek);
  });

  test("cannot be opened by a different workload key", async () => {
    const { context, project, environment } = await cloudFixture();
    const privateKey = generateX25519PrivateKey();
    const envelope = await createCloudKeyRelease(context.db, context.keyring, {
      bootId: "boot_test",
      environmentId: environment.id,
      projectId: project.id,
      keyMode: "CLOUD",
      environmentKeyVersion: environment.environmentKeyVersion,
      recipientPublicKey: b64uEncode(await x25519PublicKeyFromPrivate(privateKey)),
    });
    await expect(
      openBootEnvelope({
        bootId: "boot_test",
        environmentId: environment.id,
        environmentKeyVersion: environment.environmentKeyVersion,
        clientPrivateKey: generateX25519PrivateKey(),
        envelope,
      }),
    ).rejects.toThrow();
  });

  test("rejects requested and stored cold modes", async () => {
    const fixture = await cloudFixture();
    await expect(
      createCloudKeyRelease(fixture.context.db, fixture.context.keyring, {
        bootId: "boot_test",
        environmentId: fixture.environment.id,
        projectId: fixture.project.id,
        keyMode: "COLD",
        environmentKeyVersion: fixture.environment.environmentKeyVersion,
        recipientPublicKey: b64uEncode(
          await x25519PublicKeyFromPrivate(generateX25519PrivateKey()),
        ),
      }),
    ).rejects.toMatchObject({ code: "cold_key_required" });

    const cold = await createEnvironment(fixture.context, {
      projectId: fixture.project.id,
      slug: "cold",
      name: "Cold",
      keyMode: "COLD",
      ...(await coldKeys()),
    });
    await expect(
      createCloudKeyRelease(fixture.context.db, fixture.context.keyring, {
        bootId: "boot_test",
        environmentId: cold.id,
        projectId: fixture.project.id,
        keyMode: "CLOUD",
        environmentKeyVersion: cold.environmentKeyVersion,
        recipientPublicKey: b64uEncode(
          await x25519PublicKeyFromPrivate(generateX25519PrivateKey()),
        ),
      }),
    ).rejects.toMatchObject({ code: "cold_key_required" });
  });

  test("rejects project and version mismatches", async () => {
    const { context, project, environment } = await cloudFixture();
    const recipientPublicKey = b64uEncode(
      await x25519PublicKeyFromPrivate(generateX25519PrivateKey()),
    );
    const base = {
      bootId: "boot_test",
      environmentId: environment.id,
      projectId: project.id,
      keyMode: "CLOUD" as const,
      environmentKeyVersion: environment.environmentKeyVersion,
      recipientPublicKey,
    };
    await expect(
      createCloudKeyRelease(context.db, context.keyring, { ...base, projectId: "proj_other" }),
    ).rejects.toBeInstanceOf(KeyReleaseError);
    await expect(
      createCloudKeyRelease(context.db, context.keyring, { ...base, environmentKeyVersion: 99 }),
    ).rejects.toMatchObject({ code: "key_mismatch" });
  });

  test("rejects a malformed recipient before touching the keyring", async () => {
    const { context, project, environment } = await cloudFixture();
    const keyring = {
      activeVersion: 1,
      versions: [1],
      key() {
        throw new Error("keyring accessed");
      },
    };
    await expect(
      createCloudKeyRelease(context.db, keyring, {
        bootId: "boot_test",
        environmentId: environment.id,
        projectId: project.id,
        keyMode: "CLOUD",
        environmentKeyVersion: environment.environmentKeyVersion,
        recipientPublicKey: "bad",
      }),
    ).rejects.toThrow();
  });
});
