/**
 * Regenerate crypto/test-vectors/*.json.
 *
 * Every input here is fixed, so running this script twice produces identical files.
 * The Go implementation loads the same files and must reproduce every output.
 *
 * Run with: pnpm --filter @keevault/crypto run vectors
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  aesGcmEncrypt,
  b64uEncode,
  createBootEnvelope,
  deriveEnvelopeWrapKey,
  ed25519PublicKeyFromSeed,
  environmentKeyAad,
  hashTokenSecret,
  hexDecode,
  hexEncode,
  keyFingerprint,
  canonicalizeManifest,
  projectKeyAad,
  secretValueAad,
  signManifest,
  signResume,
  signedBuildManifestNode,
  utf8Encode,
  x25519PublicKeyFromPrivate,
  buildResumeMessage,
  type Bytes,
  type SignedBuildManifest,
} from "../src/index.ts";

const OUT_DIR = fileURLToPath(new URL("../../../crypto/test-vectors/", import.meta.url));

const MASTER_KEY = hexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const PROJECT_KEY = hexDecode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
const ENVIRONMENT_KEY = hexDecode(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
);
const PROJECT_KEY_NONCE = hexDecode("a0a1a2a3a4a5a6a7a8a9aaab");
const ENVIRONMENT_KEY_NONCE = hexDecode("b0b1b2b3b4b5b6b7b8b9babb");
const SECRET_NONCE_ONE = hexDecode("c0c1c2c3c4c5c6c7c8c9cacb");
const SECRET_NONCE_TWO = hexDecode("d0d1d2d3d4d5d6d7d8d9dadb");
const SECRET_NONCE_THREE = hexDecode("e0e1e2e3e4e5e6e7e8e9eaeb");

const CLIENT_X25519_PRIVATE = hexDecode(
  "6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435",
);
const SERVER_X25519_PRIVATE = hexDecode(
  "4142434445464748494a4b4c4d4e4f505152535455565758595a616263646566",
);
const ENVELOPE_SALT = hexDecode("0f0e0d0c0b0a09080706050403020100101112131415161718191a1b1c1d1e1f");
const ENVELOPE_NONCE = hexDecode("112233445566778899aabbcc");

const RESUME_SEED = hexDecode("1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30");
const MANIFEST_SEED = hexDecode("3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50");

const PROJECT_ID = "proj_01K4M4X2ZQ0V3E9A7N6B5C4D3E";
const ENVIRONMENT_ID = "env_01K4M4X30W1Y4F8B6P7C2D5E3F";
const BOOT_ID = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4G";
const SECRET_ID_ONE = "sec_01K4M4X32Y3A6H0D8R9E4F7G5H";
const SECRET_ID_TWO = "sec_01K4M4X33Z4B7J1E9S0F5G8H6J";
const SECRET_ID_THREE = "sec_01K4M4X350A9D3G1V2H7J0K8M";
const TOKEN_ID = "01K4M4X34A5C8K2F0T1G6H9J7K";
const TOKEN_SECRET = b64uEncode(
  hexDecode("9192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0"),
);

function writeVectors<Vector>(
  fileName: string,
  description: string,
  vectors: readonly Vector[],
): void {
  const path = `${OUT_DIR}${fileName}`;
  writeFileSync(path, `${JSON.stringify({ description, vectors }, null, 2)}\n`, "utf8");
  process.stdout.write(`wrote ${fileName} (${vectors.length} vectors)\n`);
}

interface SecretCase {
  readonly name: string;
  readonly secretId: string;
  readonly secretName: string;
  readonly secretVersion: number;
  readonly nonce: Bytes;
  readonly value: string;
}

async function writeSecretVectors(): Promise<void> {
  const cases: readonly SecretCase[] = [
    {
      name: "ascii value",
      secretId: SECRET_ID_ONE,
      secretName: "DATABASE_URL",
      secretVersion: 1,
      nonce: SECRET_NONCE_ONE,
      value: "postgres://vault:hunter2@db.internal:5432/app",
    },
    {
      name: "empty value",
      secretId: SECRET_ID_TWO,
      secretName: "OPTIONAL_FLAG",
      secretVersion: 7,
      nonce: SECRET_NONCE_TWO,
      value: "",
    },
    {
      name: "multi-byte utf-8 value",
      secretId: SECRET_ID_THREE,
      secretName: "GREETING",
      secretVersion: 42,
      nonce: SECRET_NONCE_THREE,
      value: "halo dunia \u{1f510} éèê",
    },
  ];

  const vectors = [];
  for (const secretCase of cases) {
    const aad = secretValueAad({
      projectId: PROJECT_ID,
      environmentId: ENVIRONMENT_ID,
      secretId: secretCase.secretId,
      secretName: secretCase.secretName,
      secretVersion: secretCase.secretVersion,
      environmentKeyVersion: 4,
    });
    const plaintext = utf8Encode(secretCase.value);
    const ciphertext = await aesGcmEncrypt({
      key: ENVIRONMENT_KEY,
      nonce: secretCase.nonce,
      plaintext,
      aad,
    });
    vectors.push({
      name: secretCase.name,
      projectId: PROJECT_ID,
      environmentId: ENVIRONMENT_ID,
      secretId: secretCase.secretId,
      secretName: secretCase.secretName,
      secretVersion: secretCase.secretVersion,
      environmentKeyVersion: 4,
      key: b64uEncode(ENVIRONMENT_KEY),
      nonce: b64uEncode(secretCase.nonce),
      aad,
      plaintextUtf8: secretCase.value,
      plaintext: b64uEncode(plaintext),
      ciphertext: b64uEncode(ciphertext),
    });
  }
  writeVectors(
    "aes-gcm-secret.json",
    "AES-256-GCM secret value encryption. ciphertext is ct||tag, b64u without padding. aad is the UTF-8 canonical string.",
    vectors,
  );
}

async function writeKeyWrapVectors(): Promise<void> {
  const projectAad = projectKeyAad({
    projectId: PROJECT_ID,
    projectKeyVersion: 2,
    masterKeyVersion: 1,
  });
  const projectCiphertext = await aesGcmEncrypt({
    key: MASTER_KEY,
    nonce: PROJECT_KEY_NONCE,
    plaintext: PROJECT_KEY,
    aad: projectAad,
  });
  const environmentAad = environmentKeyAad({
    projectId: PROJECT_ID,
    environmentId: ENVIRONMENT_ID,
    environmentKeyVersion: 4,
    projectKeyVersion: 2,
  });
  const environmentCiphertext = await aesGcmEncrypt({
    key: PROJECT_KEY,
    nonce: ENVIRONMENT_KEY_NONCE,
    plaintext: ENVIRONMENT_KEY,
    aad: environmentAad,
  });

  writeVectors(
    "key-wrap.json",
    "Project key wrapped under the master key and environment key wrapped under the project key. wrappingKey encrypts wrappedKey with AES-256-GCM.",
    [
      {
        name: "project key under master key",
        kind: "project-key",
        projectId: PROJECT_ID,
        projectKeyVersion: 2,
        masterKeyVersion: 1,
        wrappingKey: b64uEncode(MASTER_KEY),
        wrappedKey: b64uEncode(PROJECT_KEY),
        nonce: b64uEncode(PROJECT_KEY_NONCE),
        aad: projectAad,
        ciphertext: b64uEncode(projectCiphertext),
      },
      {
        name: "environment key under project key",
        kind: "environment-key",
        projectId: PROJECT_ID,
        environmentId: ENVIRONMENT_ID,
        environmentKeyVersion: 4,
        projectKeyVersion: 2,
        wrappingKey: b64uEncode(PROJECT_KEY),
        wrappedKey: b64uEncode(ENVIRONMENT_KEY),
        nonce: b64uEncode(ENVIRONMENT_KEY_NONCE),
        aad: environmentAad,
        ciphertext: b64uEncode(environmentCiphertext),
      },
    ],
  );
}

async function writeEnvelopeVectors(): Promise<void> {
  const clientPublicKey = await x25519PublicKeyFromPrivate(CLIENT_X25519_PRIVATE);
  const serverPublicKey = await x25519PublicKeyFromPrivate(SERVER_X25519_PRIVATE);
  const created = await createBootEnvelope({
    bootId: BOOT_ID,
    environmentId: ENVIRONMENT_ID,
    environmentKeyVersion: 4,
    environmentKey: ENVIRONMENT_KEY,
    clientPublicKey,
    material: {
      serverPrivateKey: SERVER_X25519_PRIVATE,
      salt: ENVELOPE_SALT,
      nonce: ENVELOPE_NONCE,
    },
  });
  const wrapKey = await deriveEnvelopeWrapKey({
    privateKey: SERVER_X25519_PRIVATE,
    peerPublicKey: clientPublicKey,
    salt: ENVELOPE_SALT,
    info: created.info,
  });

  writeVectors(
    "boot-envelope.json",
    "Boot key envelope. wrapKey = HKDF-SHA256(ikm=X25519(serverPrivate, clientPublic), salt, info, 32). ciphertext = AES-256-GCM(wrapKey, nonce, environmentKey, aad=info).",
    [
      {
        name: "environment DEK delivered to one boot",
        bootId: BOOT_ID,
        environmentId: ENVIRONMENT_ID,
        environmentKeyVersion: 4,
        clientPrivateKey: b64uEncode(CLIENT_X25519_PRIVATE),
        clientPublicKey: b64uEncode(clientPublicKey),
        clientPublicKeyFingerprint: await keyFingerprint(clientPublicKey),
        serverPrivateKey: b64uEncode(SERVER_X25519_PRIVATE),
        serverPublicKey: b64uEncode(serverPublicKey),
        serverPublicKeyFingerprint: await keyFingerprint(serverPublicKey),
        salt: b64uEncode(ENVELOPE_SALT),
        nonce: b64uEncode(ENVELOPE_NONCE),
        info: created.info,
        wrapKey: b64uEncode(wrapKey),
        environmentKey: b64uEncode(ENVIRONMENT_KEY),
        ciphertext: created.envelope.ciphertext,
        keyEnvelope: created.envelope,
      },
    ],
  );
}

async function writeResumeVectors(): Promise<void> {
  const publicKey = await ed25519PublicKeyFromSeed(RESUME_SEED);
  const challenge = b64uEncode(
    hexDecode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
  );
  const message = buildResumeMessage(BOOT_ID, challenge);
  const signature = await signResume({ seed: RESUME_SEED, bootId: BOOT_ID, challenge });

  writeVectors(
    "resume-signature.json",
    "Ed25519 resume proof. message is the UTF-8 canonical string; signature is 64 bytes b64u.",
    [
      {
        name: "resume proof for one boot",
        seed: b64uEncode(RESUME_SEED),
        publicKey: b64uEncode(publicKey),
        publicKeyFingerprint: await keyFingerprint(publicKey),
        bootId: BOOT_ID,
        challenge,
        message,
        messageBytes: b64uEncode(utf8Encode(message)),
        signature,
      },
    ],
  );
}

async function writeTokenVectors(): Promise<void> {
  const token = `vlt_boot_${TOKEN_ID}.${TOKEN_SECRET}`;
  const secretHash = await hashTokenSecret(TOKEN_SECRET);
  writeVectors(
    "bootstrap-token.json",
    "Bootstrap token parsing and hashing. secretHash is lowercase hex SHA-256 over the UTF-8 bytes of the 43-character secret. Vectors with valid=false must be rejected by the parser.",
    [
      {
        name: "well formed token",
        token,
        valid: true,
        tokenId: TOKEN_ID,
        secret: TOKEN_SECRET,
        secretHash,
      },
      { name: "wrong prefix", token: `vlt_bootstrap_${TOKEN_ID}.${TOKEN_SECRET}`, valid: false },
      { name: "missing separator", token: `vlt_boot_${TOKEN_ID}${TOKEN_SECRET}`, valid: false },
      {
        name: "token id too short",
        token: `vlt_boot_${TOKEN_ID.slice(1)}.${TOKEN_SECRET}`,
        valid: false,
      },
      {
        name: "token id uses an excluded crockford letter",
        token: `vlt_boot_I${TOKEN_ID.slice(1)}.${TOKEN_SECRET}`,
        valid: false,
      },
      {
        name: "secret too short",
        token: `vlt_boot_${TOKEN_ID}.${TOKEN_SECRET.slice(1)}`,
        valid: false,
      },
      {
        name: "secret uses standard base64 characters",
        token: `vlt_boot_${TOKEN_ID}.${`${TOKEN_SECRET.slice(0, 42)}+`}`,
        valid: false,
      },
    ],
  );
}

async function writeManifestVectors(): Promise<void> {
  const manifest: SignedBuildManifest = {
    version: 1,
    source: { repository: "github.com/acme/foo", commit: "a".repeat(40) },
    artifact: {
      type: "oci",
      repository: "ghcr.io/acme/foo",
      digest: `sha256:${"b".repeat(64)}`,
    },
    builder: "acme-ci",
    issuedAt: "2026-09-05T10:00:00.000Z",
  };
  const node = signedBuildManifestNode(manifest);
  const canonical = canonicalizeManifest(manifest);
  const publicKey = await ed25519PublicKeyFromSeed(MANIFEST_SEED);
  const signature = await signManifest({ seed: MANIFEST_SEED, manifest: node });

  writeVectors(
    "manifest-canonical.json",
    "Signed build manifest v1. canonical is the key-sorted JSON with no whitespace; signedMessage is 'vault:signed-build-manifest:v1\\n' followed by canonical.",
    [
      {
        name: "oci artifact manifest",
        manifest,
        canonical,
        signedMessage: `vault:signed-build-manifest:v1\n${canonical}`,
        signingSeed: b64uEncode(MANIFEST_SEED),
        signingPublicKey: b64uEncode(publicKey),
        signerFingerprint: await keyFingerprint(publicKey),
        signature,
      },
    ],
  );
}

async function writeFingerprintVectors(): Promise<void> {
  const clientPublicKey = await x25519PublicKeyFromPrivate(CLIENT_X25519_PRIVATE);
  const resumePublicKey = await ed25519PublicKeyFromSeed(RESUME_SEED);
  const zeroKey = hexDecode("00".repeat(32));

  writeVectors(
    "fingerprint.json",
    "Key fingerprint: lowercase hex SHA-256 over the raw 32-byte public key.",
    [
      {
        name: "client X25519 public key",
        key: b64uEncode(clientPublicKey),
        keyHex: hexEncode(clientPublicKey),
        fingerprint: await keyFingerprint(clientPublicKey),
      },
      {
        name: "boot Ed25519 public key",
        key: b64uEncode(resumePublicKey),
        keyHex: hexEncode(resumePublicKey),
        fingerprint: await keyFingerprint(resumePublicKey),
      },
      {
        name: "all-zero key",
        key: b64uEncode(zeroKey),
        keyHex: hexEncode(zeroKey),
        fingerprint: await keyFingerprint(zeroKey),
      },
    ],
  );
}

mkdirSync(OUT_DIR, { recursive: true });
await writeSecretVectors();
await writeKeyWrapVectors();
await writeEnvelopeVectors();
await writeResumeVectors();
await writeTokenVectors();
await writeManifestVectors();
await writeFingerprintVectors();
