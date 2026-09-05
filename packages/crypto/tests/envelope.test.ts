import { describe, expect, it } from "vite-plus/test";

import {
  b64uDecode,
  b64uEncode,
  createBootEnvelope,
  deriveEnvelopeWrapKey,
  generateKey32,
  generateX25519PrivateKey,
  openBootEnvelope,
  x25519PublicKeyFromPrivate,
} from "../src/index.ts";

const BOOT_ID = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4G";
const ENVIRONMENT_ID = "env_01K4M4X30W1Y4F8B6P7C2D5E3F";

describe("boot envelope", () => {
  it("delivers the environment key to the holder of the client private key", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const environmentKey = generateKey32();
    const created = await createBootEnvelope({
      bootId: BOOT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      environmentKey,
      clientPublicKey,
    });
    expect(created.info.startsWith("vault:boot-envelope:v1\n")).toBe(true);
    expect(b64uDecode(created.envelope.salt).length).toBe(32);
    expect(b64uDecode(created.envelope.nonce).length).toBe(12);
    expect(b64uDecode(created.envelope.ciphertext).length).toBe(48);

    const opened = await openBootEnvelope({
      bootId: BOOT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      clientPrivateKey,
      envelope: created.envelope,
    });
    expect(Array.from(opened)).toEqual(Array.from(environmentKey));
  });

  it("cannot be opened with a different X25519 private key", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const created = await createBootEnvelope({
      bootId: BOOT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      environmentKey: generateKey32(),
      clientPublicKey,
    });
    await expect(
      openBootEnvelope({
        bootId: BOOT_ID,
        environmentId: ENVIRONMENT_ID,
        environmentKeyVersion: 4,
        clientPrivateKey: generateX25519PrivateKey(),
        envelope: created.envelope,
      }),
    ).rejects.toThrow();
  });

  it("cannot be opened against a different boot id or key version", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const created = await createBootEnvelope({
      bootId: BOOT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      environmentKey: generateKey32(),
      clientPublicKey,
    });
    await expect(
      openBootEnvelope({
        bootId: "boot_01K4M4X31X2Z5G9C7Q8D3E6F4H",
        environmentId: ENVIRONMENT_ID,
        environmentKeyVersion: 4,
        clientPrivateKey,
        envelope: created.envelope,
      }),
    ).rejects.toThrow();
    await expect(
      openBootEnvelope({
        bootId: BOOT_ID,
        environmentId: ENVIRONMENT_ID,
        environmentKeyVersion: 5,
        clientPrivateKey,
        envelope: created.envelope,
      }),
    ).rejects.toThrow();
  });

  it("rejects a server public key that yields an all-zero shared secret", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const lowOrderPoint = new Uint8Array(32);
    await expect(
      deriveEnvelopeWrapKey({
        privateKey: clientPrivateKey,
        peerPublicKey: lowOrderPoint,
        salt: new Uint8Array(32),
        info: "vault:boot-envelope:v1",
      }),
    ).rejects.toThrow();
  });

  it("produces a different envelope for every approval", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const environmentKey = generateKey32();
    const first = await createBootEnvelope({
      bootId: BOOT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      environmentKey,
      clientPublicKey,
    });
    const second = await createBootEnvelope({
      bootId: BOOT_ID,
      environmentId: ENVIRONMENT_ID,
      environmentKeyVersion: 4,
      environmentKey,
      clientPublicKey,
    });
    expect(first.envelope.serverPublicKey).not.toBe(second.envelope.serverPublicKey);
    expect(first.envelope.ciphertext).not.toBe(second.envelope.ciphertext);
  });

  it("derives the same wrap key on both sides", async () => {
    const clientPrivateKey = generateX25519PrivateKey();
    const serverPrivateKey = generateX25519PrivateKey();
    const clientPublicKey = await x25519PublicKeyFromPrivate(clientPrivateKey);
    const serverPublicKey = await x25519PublicKeyFromPrivate(serverPrivateKey);
    const salt = new Uint8Array(32).fill(7);
    const info = "vault:boot-envelope:v1\nboot=boot_x";
    const fromServer = await deriveEnvelopeWrapKey({
      privateKey: serverPrivateKey,
      peerPublicKey: clientPublicKey,
      salt,
      info,
    });
    const fromClient = await deriveEnvelopeWrapKey({
      privateKey: clientPrivateKey,
      peerPublicKey: serverPublicKey,
      salt,
      info,
    });
    expect(b64uEncode(fromServer)).toBe(b64uEncode(fromClient));
  });
});
