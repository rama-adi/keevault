import { DatabaseSync } from "node:sqlite";

import {
  b64uEncode,
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  generatePrefixedUlid,
  generateResumeChallenge,
  generateX25519PrivateKey,
  randomBytes,
  sha256HexOfText,
  signResume,
  x25519PublicKeyFromPrivate,
  type Bytes,
} from "@keevault/crypto";
import { parseServerFrame, type ClientClaim, type ServerMessage } from "@keevault/protocol";
import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  getBootRequest,
  listAuditEventsByBoot,
  revokeBootstrapToken,
  upsertProvenancePolicy,
  upsertSecretReplace,
  type ProvenanceMode,
  type VaultDatabase,
} from "@keevault/vault-store";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { createTestVault } from "../bootstrap/test-vault.ts";
import { summaryDigest, V1_VERIFIERS } from "../provenance/index.ts";
import type { UnwrappedEnvironmentDek } from "../vault/keys.ts";
import { BootSessionCore, type BootIdentity, type BootView } from "./boot-session-core.ts";
import { FakeConnection, FakeSocketRegistry, fromNodeSqliteStorage } from "./test-support.ts";

const START = Date.parse("2026-09-05T10:00:00.000Z");
const PENDING_TTL_SECONDS = 1800;
const PAYLOAD_TTL_SECONDS = 300;

interface BootKeys {
  seed: Bytes;
  signingPublicKey: string;
  encryptionPublicKey: string;
}

async function bootKeys(): Promise<BootKeys> {
  const seed = generateEd25519Seed();
  const encryptionPrivateKey = generateX25519PrivateKey();
  return {
    seed,
    signingPublicKey: b64uEncode(await ed25519PublicKeyFromSeed(seed)),
    encryptionPublicKey: b64uEncode(await x25519PublicKeyFromPrivate(encryptionPrivateKey)),
  };
}

interface Harness {
  db: VaultDatabase;
  storage: DatabaseSync;
  sockets: FakeSocketRegistry;
  environmentId: string;
  projectId: string;
  tokenId: string;
  identity: BootIdentity;
  clock: { now: number };
  alarms: (number | null)[];
  core: () => BootSessionCore;
  /** A brand new core over the same storage, as a hibernated object would build. */
  restart: () => BootSessionCore;
  dek: Bytes;
}

async function createHarness(
  provenanceMode: ProvenanceMode = "ADVISORY",
  maxPendingBoots = 3,
): Promise<Harness> {
  const vault = await createTestVault();
  const projectId = generatePrefixedUlid("proj");
  const environmentId = generatePrefixedUlid("env");
  const tokenId = `tok_${generatePrefixedUlid("boot").slice(5)}`;
  const now = "2026-09-05T09:00:00.000Z";

  await createProject(vault.db, { id: projectId, slug: "acme", name: "Acme", now });
  await createEnvironment(vault.db, {
    id: environmentId,
    projectId,
    slug: "production",
    name: "Production",
    provenanceMode,
    pendingTtlSeconds: PENDING_TTL_SECONDS,
    approvedTtlSeconds: PAYLOAD_TTL_SECONDS,
    now,
  });
  await createBootstrapToken(vault.db, {
    id: tokenId,
    environmentId,
    label: "zeabur-prod-01",
    tokenHash: "0".repeat(64),
    allowedCidrsJson: "[]",
    maxPendingBoots,
    expiresAt: null,
    now,
  });
  await upsertSecretReplace(vault.db, {
    expectedVersion: 0,
    id: generatePrefixedUlid("sec"),
    environmentId,
    name: "DATABASE_URL",
    ciphertext: b64uEncode(randomBytes(48)),
    nonce: b64uEncode(randomBytes(12)),
    envKeyVersion: 1,
    now,
  });

  const storage = new DatabaseSync(":memory:");
  const sockets = new FakeSocketRegistry();
  const clock = { now: START };
  const alarms: (number | null)[] = [];
  const dek = randomBytes(32);

  const build = (): BootSessionCore =>
    new BootSessionCore({
      storage: fromNodeSqliteStorage(storage),
      db: vault.db,
      environmentId,
      now: () => clock.now,
      newBootId: () => generatePrefixedUlid("boot"),
      newAuditId: () => generatePrefixedUlid("aud"),
      randomChallenge: () => generateResumeChallenge(),
      unwrapDek: (): Promise<UnwrappedEnvironmentDek> =>
        Promise.resolve({ projectId, dek, version: 1 }),
      sockets: { forBoot: (bootId: string) => sockets.forBoot(bootId) },
      scheduleAlarm: (at: number | null) => {
        alarms.push(at);
      },
      verifiers: V1_VERIFIERS,
    });

  const instance = build();
  return {
    db: vault.db,
    storage,
    sockets,
    environmentId,
    projectId,
    tokenId,
    identity: { tokenId, sourceIp: "203.0.113.42", maxPendingBoots },
    clock,
    alarms,
    core: () => instance,
    restart: build,
    dek,
  };
}

function helloFrame(keys: BootKeys, client?: ClientClaim): string {
  return JSON.stringify({
    type: "boot.hello",
    protocol: 1,
    bootNonce: b64uEncode(randomBytes(16)),
    signingPublicKey: keys.signingPublicKey,
    encryptionPublicKey: keys.encryptionPublicKey,
    claims: {
      client,
      git: { repository: "github.com/acme/foo", commit: "a".repeat(40) },
      provider: { name: "zeabur", deploymentId: "dep-1234" },
    },
    evidence: [],
  });
}

function frames(connection: FakeConnection): ServerMessage[] {
  return connection.sent.map((text) => {
    const parsed = parseServerFrame(text);
    if (!parsed.ok) throw new Error(`server sent an invalid frame: ${parsed.error}`);
    return parsed.message;
  });
}

function lastOf(connection: FakeConnection): ServerMessage {
  const all = frames(connection);
  const last = all[all.length - 1];
  if (last === undefined) throw new Error("the server sent nothing");
  return last;
}

/** Open a socket, say hello, and return the boot id the server assigned. */
async function startBoot(
  harness: Harness,
  keys: BootKeys,
): Promise<{ connection: FakeConnection; bootId: string }> {
  const connection = harness.sockets.open();
  await harness.core().handleFrame(connection, harness.identity, helloFrame(keys));
  const pending = lastOf(connection);
  if (pending.type !== "boot.pending")
    throw new Error(`expected boot.pending, got ${pending.type}`);
  return { connection, bootId: pending.bootId };
}

/** Reconnect: resume, sign the challenge, and return the new socket. */
async function resume(
  harness: Harness,
  keys: BootKeys,
  bootId: string,
  core: BootSessionCore = harness.core(),
): Promise<FakeConnection> {
  const connection = harness.sockets.open();
  await core.handleFrame(
    connection,
    harness.identity,
    JSON.stringify({ type: "boot.resume", protocol: 1, bootId }),
  );
  const challenge = lastOf(connection);
  if (challenge.type !== "boot.challenge") return connection;
  const signature = await signResume({
    seed: keys.seed,
    bootId,
    challenge: challenge.challenge,
  });
  await core.handleFrame(
    connection,
    harness.identity,
    JSON.stringify({ type: "boot.challenge-response", bootId, signature }),
  );
  return connection;
}

async function approve(
  harness: Harness,
  bootId: string,
  core: BootSessionCore = harness.core(),
  view: BootView | null = null,
) {
  const boot = view ?? core.get(bootId);
  if (boot === null) throw new Error("boot is missing");
  return await core.approve({
    bootId,
    approverUserId: "user_1",
    approverCredentialId: "cred_1",
    evidenceDigest: await summaryDigest(boot.provenance),
  });
}

describe("boot.hello", () => {
  it("persists a client report across hibernation without treating it as verified evidence", async () => {
    const harness = await createHarness();
    const keys = await bootKeys();
    const connection = harness.sockets.open();
    const client = { version: "v1.2.3", os: "linux", arch: "arm64", sha256: "a".repeat(64) };
    await harness.core().handleFrame(connection, harness.identity, helloFrame(keys, client));
    const pending = lastOf(connection);
    if (pending.type !== "boot.pending") throw new Error("expected pending boot");
    const view = harness.restart().get(pending.bootId);
    expect(view?.claims.client).toEqual(client);
    expect(view?.provenance.some((result) => result.status === "VERIFIED")).toBe(false);
  });

  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("creates a PENDING boot, answers boot.pending and indexes it in D1", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);

    const pending = lastOf(connection);
    expect(pending.type).toBe("boot.pending");
    if (pending.type !== "boot.pending") return;
    expect(pending.expiresAt).toBe(new Date(START + PENDING_TTL_SECONDS * 1000).toISOString());

    const view = harness.core().get(bootId);
    expect(view?.status).toBe("PENDING");
    expect(view?.sourceIp).toBe("203.0.113.42");
    expect(view?.tokenId).toBe(harness.tokenId);

    const row = await getBootRequest(harness.db, bootId);
    expect(row?.status).toBe("PENDING");
    expect(row?.claimedGitRepository).toBe("github.com/acme/foo");

    const events = await listAuditEventsByBoot(harness.db, { id: bootId, limit: 10, before: null });
    expect(events.map((event) => event.action)).toContain("boot.requested");
  });

  it("arms an alarm at the pending deadline", async () => {
    await startBoot(harness, await bootKeys());

    expect(harness.alarms.at(-1)).toBe(START + PENDING_TTL_SECONDS * 1000);
  });

  it("refuses a fourth pending boot for the same token with 4409", async () => {
    for (let index = 0; index < 3; index += 1) {
      await startBoot(harness, await bootKeys());
    }

    const connection = harness.sockets.open();
    await harness.core().handleFrame(connection, harness.identity, helloFrame(await bootKeys()));

    const error = lastOf(connection);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4409);
    expect(connection.closedCode).toBe(4409);
  });

  it("rejects a frame that is not protocol v1 with 4400", async () => {
    const connection = harness.sockets.open();

    await harness.core().handleFrame(connection, harness.identity, '{"type":"nope"}');

    const error = lastOf(connection);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4400);
  });

  it("rejects a second hello on a connection that already owns a boot", async () => {
    const keys = await bootKeys();
    const { connection } = await startBoot(harness, keys);

    await harness.core().handleFrame(connection, harness.identity, helloFrame(await bootKeys()));

    const error = lastOf(connection);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4400);
  });

  it("gives a stolen token its own boot and leaves the legitimate one untouched", async () => {
    const honest = await startBoot(harness, await bootKeys());
    const attacker = await startBoot(harness, await bootKeys());

    expect(attacker.bootId).not.toBe(honest.bootId);
    const live = harness.core().listLive();
    expect(live).toHaveLength(2);
    const fingerprints = new Set(live.map((boot) => boot.signingFingerprint));
    expect(fingerprints.size).toBe(2);
    expect(harness.core().get(honest.bootId)?.status).toBe("PENDING");
  });
});

describe("resume", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("challenges, verifies the signature and answers boot.resumed", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    const reconnected = await resume(harness, keys, bootId);

    const resumed = lastOf(reconnected);
    expect(resumed.type).toBe("boot.resumed");
    if (resumed.type !== "boot.resumed") return;
    expect(resumed.status).toBe("PENDING");
    expect(reconnected.attachedBootId()).toBe(bootId);

    const events = await listAuditEventsByBoot(harness.db, { id: bootId, limit: 10, before: null });
    expect(events.map((event) => event.action)).toContain("boot.reconnected");
  });

  it("fails the challenge when an attacker copies only the boot id", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    const attackerKeys = await bootKeys();

    const attacker = await resume(harness, attackerKeys, bootId);

    const error = lastOf(attacker);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4400);
    expect(attacker.attachedBootId()).toBeNull();
  });

  it("answers 4404 for a boot id this environment never issued", async () => {
    const connection = harness.sockets.open();

    await harness.core().handleFrame(
      connection,
      harness.identity,
      JSON.stringify({
        type: "boot.resume",
        protocol: 1,
        bootId: generatePrefixedUlid("boot"),
      }),
    );

    const error = lastOf(connection);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4404);
  });

  it("spends a challenge on one verification attempt", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    const connection = harness.sockets.open();
    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.resume", protocol: 1, bootId }),
      );
    const challenge = lastOf(connection);
    if (challenge.type !== "boot.challenge") throw new Error("expected a challenge");
    const wrong = await signResume({
      seed: (await bootKeys()).seed,
      bootId,
      challenge: challenge.challenge,
    });
    const right = await signResume({ seed: keys.seed, bootId, challenge: challenge.challenge });

    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.challenge-response", bootId, signature: wrong }),
      );
    const second = harness.sockets.open();
    await harness
      .core()
      .handleFrame(
        second,
        harness.identity,
        JSON.stringify({ type: "boot.challenge-response", bootId, signature: right }),
      );

    const error = lastOf(second);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4400);
  });

  it("refuses a challenge older than its 30 second window", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    const connection = harness.sockets.open();
    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.resume", protocol: 1, bootId }),
      );
    const challenge = lastOf(connection);
    if (challenge.type !== "boot.challenge") throw new Error("expected a challenge");
    const signature = await signResume({ seed: keys.seed, bootId, challenge: challenge.challenge });

    harness.clock.now = START + 31_000;
    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.challenge-response", bootId, signature }),
      );

    const error = lastOf(connection);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4400);
  });
});

describe("approval and delivery", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("delivers the payload to an attached socket and records DELIVERED", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);

    const result = await approve(harness, bootId);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe("DELIVERED");
    const approved = lastOf(connection);
    expect(approved.type).toBe("boot.approved");
    if (approved.type !== "boot.approved") return;
    expect(approved.environmentId).toBe(harness.environmentId);
    expect(approved.projectId).toBe(harness.projectId);
    expect(approved.secrets).toHaveLength(1);
    expect(approved.payloadExpiresAt).toBe(
      new Date(START + PAYLOAD_TTL_SECONDS * 1000).toISOString(),
    );

    const row = await getBootRequest(harness.db, bootId);
    expect(row?.status).toBe("DELIVERED");
    const events = await listAuditEventsByBoot(harness.db, { id: bootId, limit: 20, before: null });
    expect(events.map((event) => event.action)).toContain("boot.approved");
    expect(events.map((event) => event.action)).toContain("boot.delivered");
  });

  it("writes the approval record binding both fingerprints and the evidence digest", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    const view = harness.core().get(bootId);

    await approve(harness, bootId);

    const approval = await harness.db
      .prepare(
        `SELECT approver_user_id AS userId, approver_credential_id AS credentialId,
                client_signing_fingerprint AS signing, client_encryption_fingerprint AS encryption,
                evidence_digest AS digest
         FROM boot_approvals WHERE boot_id = ?`,
      )
      .bind(bootId)
      .first<{
        userId: string;
        credentialId: string;
        signing: string;
        encryption: string;
        digest: string;
      }>();

    expect(approval?.userId).toBe("user_1");
    expect(approval?.credentialId).toBe("cred_1");
    expect(approval?.signing).toBe(view?.signingFingerprint);
    expect(approval?.encryption).toBe(view?.encryptionFingerprint);
    expect(approval?.digest).toBe(await summaryDigest(view?.provenance ?? []));
  });

  it("lets exactly one of two approvals of the same boot win", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    const view = harness.core().get(bootId);

    const first = await approve(harness, bootId, harness.core(), view);
    const second = await approve(harness, bootId, harness.core(), view);

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.reason).toBe("conflict");
  });

  it("refuses an approval carrying a stale evidence digest", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    const result = await harness.core().approve({
      bootId,
      approverUserId: "user_1",
      approverCredentialId: "cred_1",
      evidenceDigest: "f".repeat(64),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("evidence_mismatch");
    expect(harness.core().get(bootId)?.status).toBe("PENDING");
  });

  it("refuses an approval once the bootstrap token was revoked", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    await revokeBootstrapToken(harness.db, {
      tokenRowId: harness.tokenId,
      now: "2026-09-05T10:01:00.000Z",
    });

    const result = await approve(harness, bootId);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("token_invalid");
  });

  it("expires a pending boot at approval time rather than approving it late", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    harness.clock.now = START + (PENDING_TTL_SECONDS + 1) * 1000;

    const result = await approve(harness, bootId);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("expired");
    expect(harness.core().get(bootId)?.status).toBe("EXPIRED");
  });

  it("holds the payload when no socket is attached and sends it on resume", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");

    const result = await approve(harness, bootId);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe("APPROVED");

    const reconnected = await resume(harness, keys, bootId);

    const sent = frames(reconnected);
    expect(sent[sent.length - 2]?.type).toBe("boot.resumed");
    const resumed = sent[sent.length - 2];
    if (resumed?.type !== "boot.resumed") return;
    expect(resumed.status).toBe("APPROVED");
    expect(lastOf(reconnected).type).toBe("boot.approved");
    expect(harness.core().get(bootId)?.status).toBe("DELIVERED");
  });

  it("redelivers the identical frame after a reconnect inside the payload TTL", async () => {
    const keys = await bootKeys();
    const first = await startBoot(harness, keys);
    await approve(harness, first.bootId);
    const delivered = first.connection.lastFrame();
    first.connection.close(1006, "network dropped");

    harness.clock.now = START + 60_000;
    const reconnected = await resume(harness, keys, first.bootId);

    expect(reconnected.lastFrame()).toBe(delivered);
    expect(harness.core().get(first.bootId)?.status).toBe("DELIVERED");
  });
});

describe("acknowledgement", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("consumes the boot on a matching digest and closes with 1000", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    await approve(harness, bootId);
    const payloadDigest = await sha256HexOfText(connection.lastFrame());

    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.received", bootId, payloadDigest }),
      );

    expect(lastOf(connection).type).toBe("boot.consumed");
    expect(connection.closedCode).toBe(1000);
    expect(harness.core().get(bootId)?.status).toBe("CONSUMED");
    const stored = harness.storage
      .prepare("SELECT delivered_frame AS frame FROM boots WHERE id = ?")
      .get(bootId);
    expect(stored?.["frame"]).toBeNull();
    const row = await getBootRequest(harness.db, bootId);
    expect(row?.status).toBe("CONSUMED");
  });

  it("rejects a mismatched digest with 4400 and leaves the boot DELIVERED", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    await approve(harness, bootId);

    await harness.core().handleFrame(
      connection,
      harness.identity,
      JSON.stringify({
        type: "boot.received",
        bootId,
        payloadDigest: "0".repeat(64),
      }),
    );

    const error = lastOf(connection);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4400);
    expect(harness.core().get(bootId)?.status).toBe("DELIVERED");
  });

  it("refuses an acknowledgement from a socket that does not own the boot", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    await approve(harness, bootId);
    const payloadDigest = await sha256HexOfText(connection.lastFrame());
    const stranger = harness.sockets.open();

    await harness
      .core()
      .handleFrame(
        stranger,
        harness.identity,
        JSON.stringify({ type: "boot.received", bootId, payloadDigest }),
      );

    const error = lastOf(stranger);
    expect(error.type).toBe("boot.error");
    if (error.type !== "boot.error") return;
    expect(error.code).toBe(4404);
    expect(harness.core().get(bootId)?.status).toBe("DELIVERED");
  });
});

describe("expiry, decline and cancellation", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("expires a pending boot when the alarm fires and tells the socket", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);

    harness.clock.now = START + PENDING_TTL_SECONDS * 1000;
    await harness.core().onAlarm();

    expect(lastOf(connection).type).toBe("boot.expired");
    expect(connection.closedCode).toBe(4410);
    expect(harness.core().get(bootId)?.status).toBe("EXPIRED");
    expect(harness.alarms.at(-1)).toBeNull();
    const row = await getBootRequest(harness.db, bootId);
    expect(row?.status).toBe("EXPIRED");
  });

  it("expires an approved payload at the payload TTL, not the pending TTL", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    await approve(harness, bootId);

    harness.clock.now = START + PAYLOAD_TTL_SECONDS * 1000;
    await harness.core().onAlarm();

    expect(harness.core().get(bootId)?.status).toBe("EXPIRED");
    const stored = harness.storage
      .prepare("SELECT delivered_frame AS frame FROM boots WHERE id = ?")
      .get(bootId);
    expect(stored?.["frame"]).toBeNull();
  });

  it("declines a boot, sends boot.declined and closes 4410", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);

    const result = await harness
      .core()
      .decline({ bootId, approverUserId: "user_1", reason: "not this deployment" });

    expect(result.ok).toBe(true);
    const declined = lastOf(connection);
    expect(declined.type).toBe("boot.declined");
    if (declined.type !== "boot.declined") return;
    expect(declined.reason).toBe("not this deployment");
    expect(connection.closedCode).toBe(4410);
    expect(harness.core().get(bootId)?.status).toBe("DECLINED");
  });

  it("cancels every live boot for a revoked token and closes their sockets", async () => {
    const keys = await bootKeys();
    const pending = await startBoot(harness, keys);
    const approvedKeys = await bootKeys();
    const approved = await startBoot(harness, approvedKeys);
    // Closing the socket first leaves the boot APPROVED rather than DELIVERED,
    // which is the state the revocation rule in spec section 38 names.
    approved.connection.close(1006, "network dropped");
    await approve(harness, approved.bootId);

    const canceled = await harness.core().cancelForToken(harness.tokenId, "token revoked");

    expect(canceled).toBe(2);
    expect(harness.core().get(pending.bootId)?.status).toBe("CANCELED");
    expect(harness.core().get(approved.bootId)?.status).toBe("CANCELED");
    const frame = lastOf(pending.connection);
    expect(frame.type).toBe("boot.canceled");
    if (frame.type !== "boot.canceled") return;
    expect(frame.reason).toBe("token revoked");
    expect(pending.connection.closedCode).toBe(4410);
  });

  it("leaves a delivered boot alone, because the payload already went out", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    await approve(harness, bootId);

    const canceled = await harness.core().cancelForToken(harness.tokenId, "token revoked");

    expect(canceled).toBe(0);
    expect(harness.core().get(bootId)?.status).toBe("DELIVERED");
  });

  it("leaves a consumed boot alone when the token is revoked", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    await approve(harness, bootId);
    const payloadDigest = await sha256HexOfText(connection.lastFrame());
    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.received", bootId, payloadDigest }),
      );

    const canceled = await harness.core().cancelForToken(harness.tokenId, "token revoked");

    expect(canceled).toBe(0);
    expect(harness.core().get(bootId)?.status).toBe("CONSUMED");
  });

  it("cancels every live boot in the environment when it is deleted", async () => {
    await startBoot(harness, await bootKeys());
    await startBoot(harness, await bootKeys());

    const canceled = await harness.core().cancel("environment deleted");

    expect(canceled).toBe(2);
    expect(harness.core().listLive()).toHaveLength(0);
  });

  it("answers a resume for a terminal boot with its terminal frame", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    await harness.core().decline({ bootId, approverUserId: "user_1", reason: "no" });

    const connection = harness.sockets.open();
    await harness
      .core()
      .handleFrame(
        connection,
        harness.identity,
        JSON.stringify({ type: "boot.resume", protocol: 1, bootId }),
      );

    expect(lastOf(connection).type).toBe("boot.declined");
    expect(connection.closedCode).toBe(4410);
  });
});

describe("hibernation", () => {
  it("sees the same state from a core built fresh over the same storage", async () => {
    const harness = await createHarness();
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "durable object hibernated");

    const woken = harness.restart();
    expect(woken.get(bootId)?.status).toBe("PENDING");

    const result = await approve(harness, bootId, woken);
    expect(result.ok).toBe(true);

    const afterApproval = harness.restart();
    expect(afterApproval.get(bootId)?.status).toBe("APPROVED");

    const reconnected = await resume(harness, keys, bootId, afterApproval);
    expect(lastOf(reconnected).type).toBe("boot.approved");
    expect(harness.restart().get(bootId)?.status).toBe("DELIVERED");
  });
});

describe("provenance policy", () => {
  it("blocks approval under REQUIRED when nothing verified", async () => {
    const harness = await createHarness("REQUIRED");
    await upsertProvenancePolicy(harness.db, {
      id: generatePrefixedUlid("pol"),
      environmentId: harness.environmentId,
      verifierType: "signed-build-manifest-v1",
      configurationJson: "{}",
      required: true,
      enabled: true,
      now: "2026-09-05T09:00:00.000Z",
    });
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    const result = await approve(harness, bootId);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("policy_blocked");
    expect(result.message).toContain("signed-build-manifest-v1");
    expect(harness.core().get(bootId)?.status).toBe("PENDING");
  });

  it("allows approval under ADVISORY with no evidence at all", async () => {
    const harness = await createHarness("ADVISORY");
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    const result = await approve(harness, bootId);

    expect(result.ok).toBe(true);
  });
});
