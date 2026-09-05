import { describe, expect, it } from "vite-plus/test";

import {
  b64uDecode,
  createBootEnvelope,
  decryptSecret,
  encryptSecret,
  generateKey32,
  generateX25519PrivateKey,
  openBootEnvelope,
  secretValueAad,
  x25519PublicKeyFromPrivate,
} from "../src/index.ts";

/**
 * Adversarial binding tests for spec section 44.
 *
 * Each case moves one authenticated field out from under a ciphertext and
 * checks that AES-GCM refuses it. The whole "D1 compromise is insufficient"
 * property (spec section 3) rests on these AAD strings, so they get their own
 * file rather than living beside the round-trip tests.
 */

const PROJECT_ID = "proj_01K4M4X2ZQ0V3E9A7N6B5C4D3E";
const ENVIRONMENT_A = "env_01K4M4X30W1Y4F8B6P7C2D5E3F";
const ENVIRONMENT_B = "env_01K4M4X30W1Y4F8B6P7C2D5E9Z";
const SECRET_ID = "sec_01K4M4X3A0000000000000001";
const BOOT_A = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4G";
const BOOT_B = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4H";

interface SealedSecret {
  readonly environmentKey: ReturnType<typeof generateKey32>;
  readonly nonce: Uint8Array<ArrayBuffer>;
  readonly ciphertext: Uint8Array<ArrayBuffer>;
}

async function sealIn(environmentId: string, value: string): Promise<SealedSecret> {
  const environmentKey = generateKey32();
  const sealed = await encryptSecret({
    environmentKey,
    projectId: PROJECT_ID,
    environmentId,
    secretId: SECRET_ID,
    secretName: "DATABASE_URL",
    secretVersion: 3,
    environmentKeyVersion: 4,
    value,
  });
  return { environmentKey, nonce: sealed.nonce, ciphertext: sealed.ciphertext };
}

describe("one environment's ciphertext under another environment's identity", () => {
  it("refuses a record moved from environment A into environment B", async () => {
    const staging = await sealIn(ENVIRONMENT_A, "postgres://staging/app");

    // The attacker has a full D1 export, so they hold both rows and can swap
    // the ciphertext blob between the two environments' secret tables.
    await expect(
      decryptSecret({
        environmentKey: staging.environmentKey,
        projectId: PROJECT_ID,
        environmentId: ENVIRONMENT_B,
        secretId: SECRET_ID,
        secretName: "DATABASE_URL",
        secretVersion: 3,
        environmentKeyVersion: 4,
        nonce: staging.nonce,
        ciphertext: staging.ciphertext,
      }),
    ).rejects.toThrow();
  });

  it("refuses production ciphertext opened with the staging environment key", async () => {
    const production = await sealIn(ENVIRONMENT_A, "postgres://production/app");
    const staging = await sealIn(ENVIRONMENT_B, "postgres://staging/app");

    await expect(
      decryptSecret({
        environmentKey: staging.environmentKey,
        projectId: PROJECT_ID,
        environmentId: ENVIRONMENT_A,
        secretId: SECRET_ID,
        secretName: "DATABASE_URL",
        secretVersion: 3,
        environmentKeyVersion: 4,
        nonce: production.nonce,
        ciphertext: production.ciphertext,
      }),
    ).rejects.toThrow();
  });

  it("binds the environment id into the AAD string itself", () => {
    const shared = {
      projectId: PROJECT_ID,
      secretId: SECRET_ID,
      secretName: "DATABASE_URL",
      secretVersion: 3,
      environmentKeyVersion: 4,
    };
    const inA = secretValueAad({ ...shared, environmentId: ENVIRONMENT_A });
    const inB = secretValueAad({ ...shared, environmentId: ENVIRONMENT_B });
    expect(inA).not.toBe(inB);
    expect(inA.includes(`environment=${ENVIRONMENT_A}`)).toBe(true);
  });
});

describe("renaming a secret in flight", () => {
  it("refuses a record whose name was changed after it was sealed", async () => {
    const sealed = await sealIn(ENVIRONMENT_A, "sk-live-4f8b6p7c2d5e3f");

    // Renaming API_KEY to PATH, or to any name the workload already trusts, is
    // the interesting attack: the value never changes, only the label does.
    await expect(
      decryptSecret({
        environmentKey: sealed.environmentKey,
        projectId: PROJECT_ID,
        environmentId: ENVIRONMENT_A,
        secretId: SECRET_ID,
        secretName: "LD_PRELOAD",
        secretVersion: 3,
        environmentKeyVersion: 4,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
      }),
    ).rejects.toThrow();
  });

  it("refuses a record replayed at an older version number", async () => {
    const sealed = await sealIn(ENVIRONMENT_A, "sk-live-4f8b6p7c2d5e3f");

    await expect(
      decryptSecret({
        environmentKey: sealed.environmentKey,
        projectId: PROJECT_ID,
        environmentId: ENVIRONMENT_A,
        secretId: SECRET_ID,
        secretName: "DATABASE_URL",
        secretVersion: 2,
        environmentKeyVersion: 4,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
      }),
    ).rejects.toThrow();
  });
});

describe("copying an approval response", () => {
  it("refuses an envelope replayed against a second boot id", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const environmentKey = generateKey32();
    const created = await createBootEnvelope({
      bootId: BOOT_A,
      environmentId: ENVIRONMENT_A,
      environmentKeyVersion: 4,
      environmentKey,
      clientPublicKey,
    });

    await expect(
      openBootEnvelope({
        bootId: BOOT_B,
        environmentId: ENVIRONMENT_A,
        environmentKeyVersion: 4,
        clientPrivateKey,
        envelope: created.envelope,
      }),
    ).rejects.toThrow();
  });

  it("refuses an envelope replayed against a second environment", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const created = await createBootEnvelope({
      bootId: BOOT_A,
      environmentId: ENVIRONMENT_A,
      environmentKeyVersion: 4,
      environmentKey: generateKey32(),
      clientPublicKey,
    });

    await expect(
      openBootEnvelope({
        bootId: BOOT_A,
        environmentId: ENVIRONMENT_B,
        environmentKeyVersion: 4,
        clientPrivateKey,
        envelope: created.envelope,
      }),
    ).rejects.toThrow();
  });

  it("refuses an envelope captured off the wire by a boot with its own keys", async () => {
    // The attacker holds a stolen bootstrap token, so they can open their own
    // socket and watch nothing useful. What they cannot do is take the frame a
    // legitimate boot was approved for and unwrap it with their own key.
    const victimPrivateKey = generateX25519PrivateKey();
    const victimPublicKey = await x25519PublicKeyFromPrivate(victimPrivateKey);
    const attackerPrivateKey = generateX25519PrivateKey();
    const created = await createBootEnvelope({
      bootId: BOOT_A,
      environmentId: ENVIRONMENT_A,
      environmentKeyVersion: 4,
      environmentKey: generateKey32(),
      clientPublicKey: victimPublicKey,
    });

    await expect(
      openBootEnvelope({
        bootId: BOOT_A,
        environmentId: ENVIRONMENT_A,
        environmentKeyVersion: 4,
        clientPrivateKey: attackerPrivateKey,
        envelope: created.envelope,
      }),
    ).rejects.toThrow();
  });

  it("gives every approval a fresh server key, salt and nonce", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const environmentKey = generateKey32();
    const first = await createBootEnvelope({
      bootId: BOOT_A,
      environmentId: ENVIRONMENT_A,
      environmentKeyVersion: 4,
      environmentKey,
      clientPublicKey,
    });
    const second = await createBootEnvelope({
      bootId: BOOT_A,
      environmentId: ENVIRONMENT_A,
      environmentKeyVersion: 4,
      environmentKey,
      clientPublicKey,
    });

    expect(first.envelope.serverPublicKey).not.toBe(second.envelope.serverPublicKey);
    expect(first.envelope.salt).not.toBe(second.envelope.salt);
    expect(first.envelope.nonce).not.toBe(second.envelope.nonce);
    expect(first.envelope.ciphertext).not.toBe(second.envelope.ciphertext);
    expect(b64uDecode(first.envelope.nonce).length).toBe(12);
  });
});
