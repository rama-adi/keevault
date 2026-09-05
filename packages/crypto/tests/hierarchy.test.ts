import { describe, expect, it } from "vite-plus/test";

import {
  decryptSecret,
  encryptSecret,
  generateKey32,
  unwrapEnvironmentKey,
  unwrapProjectKey,
  wrapEnvironmentKey,
  wrapProjectKey,
} from "../src/index.ts";

const PROJECT_ID = "proj_01K4M4X2ZQ0V3E9A7N6B5C4D3E";
const ENVIRONMENT_ID = "env_01K4M4X30W1Y4F8B6P7C2D5E3F";
const SECRET_ID = "sec_01K4M4X32Y3A6H0D8R9E4F7G5H";

describe("key hierarchy", () => {
  it("round trips a project key", async () => {
    const masterKey = generateKey32();
    const projectKey = generateKey32();
    const identity = { projectId: PROJECT_ID, projectKeyVersion: 2, masterKeyVersion: 1 };
    const sealed = await wrapProjectKey({ masterKey, projectKey, ...identity });
    const opened = await unwrapProjectKey({ masterKey, ...sealed, ...identity });
    expect(Array.from(opened)).toEqual(Array.from(projectKey));
  });

  it("refuses a project key wrapped under another master key version", async () => {
    const masterKey = generateKey32();
    const projectKey = generateKey32();
    const identity = { projectId: PROJECT_ID, projectKeyVersion: 2, masterKeyVersion: 1 };
    const sealed = await wrapProjectKey({ masterKey, projectKey, ...identity });
    await expect(
      unwrapProjectKey({ masterKey, ...sealed, ...identity, masterKeyVersion: 2 }),
    ).rejects.toThrow();
  });

  it("round trips an environment key and refuses a foreign project", async () => {
    const projectKey = generateKey32();
    const environmentKey = generateKey32();
    const identity = {
      projectId: PROJECT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      projectKeyVersion: 2,
    };
    const sealed = await wrapEnvironmentKey({ projectKey, environmentKey, ...identity });
    const opened = await unwrapEnvironmentKey({ projectKey, ...sealed, ...identity });
    expect(Array.from(opened)).toEqual(Array.from(environmentKey));
    await expect(
      unwrapEnvironmentKey({
        projectKey,
        ...sealed,
        ...identity,
        projectId: "proj_01K4M4X2ZQ0V3E9A7N6B5C4D3F",
      }),
    ).rejects.toThrow();
  });
});

describe("secret values", () => {
  const identity = {
    projectId: PROJECT_ID,
    environmentId: ENVIRONMENT_ID,
    secretId: SECRET_ID,
    secretName: "DATABASE_URL",
    secretVersion: 3,
    environmentKeyVersion: 4,
  };

  it("round trips a value", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    expect(await decryptSecret({ environmentKey, ...sealed, ...identity })).toBe("s3cret");
  });

  it("fails on tampered ciphertext", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    const tampered = Uint8Array.from(sealed.ciphertext);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    await expect(
      decryptSecret({ environmentKey, nonce: sealed.nonce, ciphertext: tampered, ...identity }),
    ).rejects.toThrow();
  });

  it("fails on a tampered nonce", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    const nonce = Uint8Array.from(sealed.nonce);
    nonce[11] = (nonce[11] ?? 0) ^ 0x80;
    await expect(
      decryptSecret({ environmentKey, nonce, ciphertext: sealed.ciphertext, ...identity }),
    ).rejects.toThrow();
  });

  it("fails on a wrong secret name", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    await expect(
      decryptSecret({ environmentKey, ...sealed, ...identity, secretName: "API_KEY" }),
    ).rejects.toThrow();
  });

  it("fails on a wrong environment id", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    await expect(
      decryptSecret({
        environmentKey,
        ...sealed,
        ...identity,
        environmentId: "env_01K4M4X30W1Y4F8B6P7C2D5E3G",
      }),
    ).rejects.toThrow();
  });

  it("fails on a wrong secret version", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    await expect(
      decryptSecret({ environmentKey, ...sealed, ...identity, secretVersion: 4 }),
    ).rejects.toThrow();
  });

  it("fails on a wrong environment key version", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    await expect(
      decryptSecret({ environmentKey, ...sealed, ...identity, environmentKeyVersion: 5 }),
    ).rejects.toThrow();
  });

  it("fails under a different environment key", async () => {
    const environmentKey = generateKey32();
    const sealed = await encryptSecret({ environmentKey, value: "s3cret", ...identity });
    await expect(
      decryptSecret({ environmentKey: generateKey32(), ...sealed, ...identity }),
    ).rejects.toThrow();
  });
});
