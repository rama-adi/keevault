/**
 * Re-read the committed vector files and reproduce every output.
 *
 * The Go implementation loads the same files. If this test fails, the files and the
 * implementation have drifted apart and one of them is wrong.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vite-plus/test";
import { z } from "zod";

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64uDecode,
  b64uEncode,
  buildResumeMessage,
  canonicalizeManifest,
  createBootEnvelope,
  deriveEnvelopeWrapKey,
  ed25519PublicKeyFromSeed,
  environmentKeyAad,
  hashTokenSecret,
  hexEncode,
  keyFingerprint,
  openBootEnvelope,
  parseBootstrapToken,
  projectKeyAad,
  secretValueAad,
  signManifest,
  signResume,
  signedBuildManifestNode,
  utf8Decode,
  utf8Encode,
  verifyManifest,
  verifyResume,
  x25519PublicKeyFromPrivate,
} from "../src/index.ts";

function readVectors<Vector extends z.ZodType>(fileName: string, vector: Vector) {
  const path = new URL(`../../../crypto/test-vectors/${fileName}`, import.meta.url);
  const parsed = z
    .object({ description: z.string().min(1), vectors: z.array(vector).min(1) })
    .parse(JSON.parse(readFileSync(path, "utf8")));
  return parsed.vectors;
}

describe("aes-gcm-secret.json", () => {
  const vectors = readVectors(
    "aes-gcm-secret.json",
    z.object({
      name: z.string(),
      projectId: z.string(),
      environmentId: z.string(),
      secretId: z.string(),
      secretName: z.string(),
      secretVersion: z.number().int(),
      environmentKeyVersion: z.number().int(),
      key: z.string(),
      nonce: z.string(),
      aad: z.string(),
      plaintextUtf8: z.string(),
      plaintext: z.string(),
      ciphertext: z.string(),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      expect(
        secretValueAad({
          projectId: vector.projectId,
          environmentId: vector.environmentId,
          secretId: vector.secretId,
          secretName: vector.secretName,
          secretVersion: vector.secretVersion,
          environmentKeyVersion: vector.environmentKeyVersion,
        }),
      ).toBe(vector.aad);
      expect(b64uEncode(utf8Encode(vector.plaintextUtf8))).toBe(vector.plaintext);
      const ciphertext = await aesGcmEncrypt({
        key: b64uDecode(vector.key),
        nonce: b64uDecode(vector.nonce),
        plaintext: b64uDecode(vector.plaintext),
        aad: vector.aad,
      });
      expect(b64uEncode(ciphertext)).toBe(vector.ciphertext);
      const opened = await aesGcmDecrypt({
        key: b64uDecode(vector.key),
        nonce: b64uDecode(vector.nonce),
        ciphertext: b64uDecode(vector.ciphertext),
        aad: vector.aad,
      });
      expect(utf8Decode(opened)).toBe(vector.plaintextUtf8);
    },
  );
});

describe("key-wrap.json", () => {
  const vectors = readVectors(
    "key-wrap.json",
    z.object({
      name: z.string(),
      kind: z.enum(["project-key", "environment-key"]),
      projectId: z.string(),
      environmentId: z.string().optional(),
      projectKeyVersion: z.number().int(),
      masterKeyVersion: z.number().int().optional(),
      environmentKeyVersion: z.number().int().optional(),
      wrappingKey: z.string(),
      wrappedKey: z.string(),
      nonce: z.string(),
      aad: z.string(),
      ciphertext: z.string(),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      const aad =
        vector.kind === "project-key"
          ? projectKeyAad({
              projectId: vector.projectId,
              projectKeyVersion: vector.projectKeyVersion,
              masterKeyVersion: vector.masterKeyVersion ?? 0,
            })
          : environmentKeyAad({
              projectId: vector.projectId,
              environmentId: vector.environmentId ?? "",
              environmentKeyVersion: vector.environmentKeyVersion ?? 0,
              projectKeyVersion: vector.projectKeyVersion,
            });
      expect(aad).toBe(vector.aad);
      const ciphertext = await aesGcmEncrypt({
        key: b64uDecode(vector.wrappingKey),
        nonce: b64uDecode(vector.nonce),
        plaintext: b64uDecode(vector.wrappedKey),
        aad: vector.aad,
      });
      expect(b64uEncode(ciphertext)).toBe(vector.ciphertext);
    },
  );
});

describe("boot-envelope.json", () => {
  const vectors = readVectors(
    "boot-envelope.json",
    z.object({
      name: z.string(),
      bootId: z.string(),
      environmentId: z.string(),
      environmentKeyVersion: z.number().int(),
      clientPrivateKey: z.string(),
      clientPublicKey: z.string(),
      clientPublicKeyFingerprint: z.string(),
      serverPrivateKey: z.string(),
      serverPublicKey: z.string(),
      serverPublicKeyFingerprint: z.string(),
      salt: z.string(),
      nonce: z.string(),
      info: z.string(),
      wrapKey: z.string(),
      environmentKey: z.string(),
      ciphertext: z.string(),
      keyEnvelope: z.object({
        serverPublicKey: z.string(),
        salt: z.string(),
        nonce: z.string(),
        ciphertext: z.string(),
      }),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      const clientPublicKey = await x25519PublicKeyFromPrivate(b64uDecode(vector.clientPrivateKey));
      const serverPublicKey = await x25519PublicKeyFromPrivate(b64uDecode(vector.serverPrivateKey));
      expect(b64uEncode(clientPublicKey)).toBe(vector.clientPublicKey);
      expect(b64uEncode(serverPublicKey)).toBe(vector.serverPublicKey);
      expect(await keyFingerprint(clientPublicKey)).toBe(vector.clientPublicKeyFingerprint);
      expect(await keyFingerprint(serverPublicKey)).toBe(vector.serverPublicKeyFingerprint);

      const created = await createBootEnvelope({
        bootId: vector.bootId,
        environmentId: vector.environmentId,
        environmentKeyVersion: vector.environmentKeyVersion,
        environmentKey: b64uDecode(vector.environmentKey),
        clientPublicKey,
        material: {
          serverPrivateKey: b64uDecode(vector.serverPrivateKey),
          salt: b64uDecode(vector.salt),
          nonce: b64uDecode(vector.nonce),
        },
      });
      expect(created.info).toBe(vector.info);
      expect(created.envelope).toEqual(vector.keyEnvelope);

      const wrapKey = await deriveEnvelopeWrapKey({
        privateKey: b64uDecode(vector.clientPrivateKey),
        peerPublicKey: serverPublicKey,
        salt: b64uDecode(vector.salt),
        info: vector.info,
      });
      expect(b64uEncode(wrapKey)).toBe(vector.wrapKey);

      const opened = await openBootEnvelope({
        bootId: vector.bootId,
        environmentId: vector.environmentId,
        environmentKeyVersion: vector.environmentKeyVersion,
        clientPrivateKey: b64uDecode(vector.clientPrivateKey),
        envelope: vector.keyEnvelope,
      });
      expect(b64uEncode(opened)).toBe(vector.environmentKey);
    },
  );
});

describe("resume-signature.json", () => {
  const vectors = readVectors(
    "resume-signature.json",
    z.object({
      name: z.string(),
      seed: z.string(),
      publicKey: z.string(),
      publicKeyFingerprint: z.string(),
      bootId: z.string(),
      challenge: z.string(),
      message: z.string(),
      messageBytes: z.string(),
      signature: z.string(),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      const publicKey = await ed25519PublicKeyFromSeed(b64uDecode(vector.seed));
      expect(b64uEncode(publicKey)).toBe(vector.publicKey);
      expect(await keyFingerprint(publicKey)).toBe(vector.publicKeyFingerprint);
      expect(buildResumeMessage(vector.bootId, vector.challenge)).toBe(vector.message);
      expect(b64uEncode(utf8Encode(vector.message))).toBe(vector.messageBytes);
      expect(
        await signResume({
          seed: b64uDecode(vector.seed),
          bootId: vector.bootId,
          challenge: vector.challenge,
        }),
      ).toBe(vector.signature);
      expect(
        await verifyResume({
          publicKey,
          bootId: vector.bootId,
          challenge: vector.challenge,
          signature: vector.signature,
        }),
      ).toBe(true);
    },
  );
});

describe("bootstrap-token.json", () => {
  const vectors = readVectors(
    "bootstrap-token.json",
    z.object({
      name: z.string(),
      token: z.string(),
      valid: z.boolean(),
      tokenId: z.string().optional(),
      secret: z.string().optional(),
      secretHash: z.string().optional(),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      const parsed = parseBootstrapToken(vector.token);
      if (!vector.valid) {
        expect(parsed).toBeNull();
        return;
      }
      expect(parsed).not.toBeNull();
      expect(parsed?.tokenId).toBe(vector.tokenId);
      expect(parsed?.secret).toBe(vector.secret);
      expect(await hashTokenSecret(vector.secret ?? "")).toBe(vector.secretHash);
    },
  );
});

describe("manifest-canonical.json", () => {
  const vectors = readVectors(
    "manifest-canonical.json",
    z.object({
      name: z.string(),
      manifest: z.object({
        version: z.literal(1),
        source: z.object({ repository: z.string(), commit: z.string() }),
        artifact: z.object({
          type: z.string(),
          repository: z.string(),
          digest: z.string(),
        }),
        builder: z.string(),
        issuedAt: z.string(),
      }),
      canonical: z.string(),
      signedMessage: z.string(),
      signingSeed: z.string(),
      signingPublicKey: z.string(),
      signerFingerprint: z.string(),
      signature: z.string(),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      expect(canonicalizeManifest(vector.manifest)).toBe(vector.canonical);
      expect(vector.signedMessage).toBe(`vault:signed-build-manifest:v1\n${vector.canonical}`);
      const node = signedBuildManifestNode(vector.manifest);
      const publicKey = await ed25519PublicKeyFromSeed(b64uDecode(vector.signingSeed));
      expect(b64uEncode(publicKey)).toBe(vector.signingPublicKey);
      expect(await keyFingerprint(publicKey)).toBe(vector.signerFingerprint);
      expect(await signManifest({ seed: b64uDecode(vector.signingSeed), manifest: node })).toBe(
        vector.signature,
      );
      expect(await verifyManifest({ publicKey, manifest: node, signature: vector.signature })).toBe(
        true,
      );
    },
  );
});

describe("fingerprint.json", () => {
  const vectors = readVectors(
    "fingerprint.json",
    z.object({
      name: z.string(),
      key: z.string(),
      keyHex: z.string(),
      fingerprint: z.string(),
    }),
  );

  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    "reproduces %s",
    async (_name, vector) => {
      const key = b64uDecode(vector.key);
      expect(hexEncode(key)).toBe(vector.keyHex);
      expect(await keyFingerprint(key)).toBe(vector.fingerprint);
    },
  );
});
