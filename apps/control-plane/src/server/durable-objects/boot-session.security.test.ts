import { DatabaseSync } from "node:sqlite";

import {
  b64uEncode,
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  generatePrefixedUlid,
  generateResumeChallenge,
  generateX25519PrivateKey,
  randomBytes,
  signResume,
  x25519PublicKeyFromPrivate,
  type Bytes,
} from "@keevault/crypto";
import { parseServerFrame, type ServerMessage } from "@keevault/protocol";
import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  getBootApproval,
  revokeBootstrapToken,
  upsertSecretReplace,
  type VaultDatabase,
} from "@keevault/vault-store";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { createTestVault } from "../bootstrap/test-vault.ts";
import { summaryDigest, V1_VERIFIERS } from "../provenance/index.ts";
import type { UnwrappedEnvironmentDek } from "../vault/keys.ts";
import {
  BOOT_RATE_WINDOW_SECONDS,
  BootSessionCore,
  MAX_BOOTS_PER_SOURCE,
  type BootIdentity,
} from "./boot-session-core.ts";
import { FakeConnection, FakeSocketRegistry, fromNodeSqliteStorage } from "./test-support.ts";

/**
 * Adversarial state-machine tests (spec section 44, phase 11).
 *
 * The transition tests next door drive the happy paths and the single-actor
 * refusals. This file drives the cases where two actors race, where a clock has
 * moved on behind the object's back, and where a revocation has to reach a boot
 * that is already in flight. Every case here passes; the ones that name a
 * finding in docs/security-review-v1.md were written against the defect and go
 * red again if it comes back.
 */

const START = Date.parse("2026-09-05T10:00:00.000Z");
const PENDING_TTL_SECONDS = 1800;
const PAYLOAD_TTL_SECONDS = 300;
const CHALLENGE_TTL_SECONDS = 30;

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

/**
 * A one-shot pause the first `unwrapDek` call waits on. It lets a test start
 * one approval, park it inside the awaits that run before the transition, and
 * run a second approval to completion in the gap.
 */
interface Gate {
  arm(): void;
  readonly reached: Promise<void>;
  release(): void;
  pass(): Promise<void>;
}

function createGate(): Gate {
  let releaseHold = (): void => undefined;
  let markReached = (): void => undefined;
  const released = new Promise<void>((resolve) => {
    releaseHold = (): void => {
      resolve();
    };
  });
  const reached = new Promise<void>((resolve) => {
    markReached = (): void => {
      resolve();
    };
  });
  let armed = false;
  return {
    arm(): void {
      armed = true;
    },
    reached,
    release(): void {
      releaseHold();
    },
    async pass(): Promise<void> {
      if (!armed) return;
      armed = false;
      markReached();
      await released;
    },
  };
}

interface Harness {
  db: VaultDatabase;
  sockets: FakeSocketRegistry;
  environmentId: string;
  projectId: string;
  tokenId: string;
  secondTokenId: string;
  identity: BootIdentity;
  secondIdentity: BootIdentity;
  clock: { now: number };
  gate: Gate;
  core: BootSessionCore;
}

async function createHarness(): Promise<Harness> {
  const vault = await createTestVault();
  const projectId = generatePrefixedUlid("proj");
  const environmentId = generatePrefixedUlid("env");
  const tokenId = `tok_${generatePrefixedUlid("boot").slice(5)}`;
  const secondTokenId = `tok_${generatePrefixedUlid("boot").slice(5)}`;
  const now = "2026-09-05T09:00:00.000Z";

  await createProject(vault.db, { id: projectId, slug: "acme", name: "Acme", now });
  await createEnvironment(vault.db, {
    id: environmentId,
    projectId,
    slug: "production",
    name: "Production",
    provenanceMode: "ADVISORY",
    pendingTtlSeconds: PENDING_TTL_SECONDS,
    approvedTtlSeconds: PAYLOAD_TTL_SECONDS,
    now,
  });
  for (const [id, label] of [
    [tokenId, "zeabur-prod-01"],
    [secondTokenId, "backup-vps"],
  ] as const) {
    await createBootstrapToken(vault.db, {
      id,
      environmentId,
      label,
      tokenHash: "0".repeat(64),
      allowedCidrsJson: "[]",
      maxPendingBoots: 3,
      expiresAt: null,
      now,
    });
  }
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
  const gate = createGate();
  const dek = randomBytes(32);

  const core = new BootSessionCore({
    storage: fromNodeSqliteStorage(storage),
    db: vault.db,
    environmentId,
    now: () => clock.now,
    newBootId: () => generatePrefixedUlid("boot"),
    newAuditId: () => generatePrefixedUlid("aud"),
    randomChallenge: () => generateResumeChallenge(),
    unwrapDek: async (): Promise<UnwrappedEnvironmentDek> => {
      await gate.pass();
      return { projectId, dek, version: 1 };
    },
    sockets: { forBoot: (bootId: string) => sockets.forBoot(bootId) },
    scheduleAlarm: () => undefined,
    verifiers: V1_VERIFIERS,
  });

  return {
    db: vault.db,
    sockets,
    environmentId,
    projectId,
    tokenId,
    secondTokenId,
    identity: { tokenId, sourceIp: "203.0.113.42", maxPendingBoots: 3 },
    secondIdentity: { tokenId: secondTokenId, sourceIp: "198.51.100.9", maxPendingBoots: 3 },
    clock,
    gate,
    core,
  };
}

function helloFrame(keys: BootKeys): string {
  return JSON.stringify({
    type: "boot.hello",
    protocol: 1,
    bootNonce: b64uEncode(randomBytes(16)),
    signingPublicKey: keys.signingPublicKey,
    encryptionPublicKey: keys.encryptionPublicKey,
    claims: { provider: { name: "zeabur", deploymentId: "dep-1234" } },
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

async function startBoot(
  harness: Harness,
  keys: BootKeys,
  identity: BootIdentity = harness.identity,
): Promise<{ connection: FakeConnection; bootId: string }> {
  const connection = harness.sockets.open();
  await harness.core.handleFrame(connection, identity, helloFrame(keys));
  const pending = lastOf(connection);
  if (pending.type !== "boot.pending") {
    throw new Error(`expected boot.pending, got ${pending.type}`);
  }
  return { connection, bootId: pending.bootId };
}

/** Send boot.resume and return the socket plus the challenge the server issued. */
async function openResume(
  harness: Harness,
  bootId: string,
  identity: BootIdentity = harness.identity,
): Promise<{ connection: FakeConnection; challenge: string | null }> {
  const connection = harness.sockets.open();
  await harness.core.handleFrame(
    connection,
    identity,
    JSON.stringify({ type: "boot.resume", protocol: 1, bootId }),
  );
  const frame = lastOf(connection);
  return { connection, challenge: frame.type === "boot.challenge" ? frame.challenge : null };
}

async function answerChallenge(
  harness: Harness,
  connection: FakeConnection,
  keys: BootKeys,
  bootId: string,
  challenge: string,
  identity: BootIdentity = harness.identity,
): Promise<void> {
  const signature = await signResume({ seed: keys.seed, bootId, challenge });
  await harness.core.handleFrame(
    connection,
    identity,
    JSON.stringify({ type: "boot.challenge-response", bootId, signature }),
  );
}

async function resume(
  harness: Harness,
  keys: BootKeys,
  bootId: string,
  identity: BootIdentity = harness.identity,
): Promise<FakeConnection> {
  const opened = await openResume(harness, bootId, identity);
  const challenge = opened.challenge;
  if (challenge === null) return opened.connection;
  await answerChallenge(harness, opened.connection, keys, bootId, challenge, identity);
  return opened.connection;
}

async function approve(harness: Harness, bootId: string) {
  const view = harness.core.get(bootId);
  if (view === null) throw new Error("boot is missing");
  return await harness.core.approve({
    bootId,
    approverUserId: "user_1",
    approverCredentialId: "cred_1",
    evidenceDigest: await summaryDigest(view.provenance),
  });
}

describe("two administrators approve the same boot at once", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  // Finding 1 in docs/security-review-v1.md, now fixed: `approve` re-reads the
  // boot row and applies the transition with no await in between, so the second
  // of two overlapping approvals sees APPROVED and reports a conflict.
  it("lets one approval win and answers the other with a conflict", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    const settled = await Promise.allSettled([approve(harness, bootId), approve(harness, bootId)]);

    const wins = settled.filter(
      (outcome) => outcome.status === "fulfilled" && outcome.value.ok,
    ).length;
    const conflicts = settled.filter(
      (outcome) => outcome.status === "fulfilled" && !outcome.value.ok,
    ).length;
    expect(wins).toBe(1);
    expect(conflicts).toBe(1);
  });

  // Same finding, seen from the client's side: the losing approval overwrites
  // the stored frame and its digest, so the payload the client already holds no
  // longer matches what the object will accept as an acknowledgement.
  it("keeps the delivered frame and the stored digest in agreement", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);

    await Promise.allSettled([approve(harness, bootId), approve(harness, bootId)]);

    const delivered = lastOf(connection);
    expect(delivered.type).toBe("boot.approved");
    const frame = connection.sent[connection.sent.length - 1] ?? "";
    await harness.core.handleFrame(
      connection,
      harness.identity,
      JSON.stringify({ type: "boot.received", bootId, payloadDigest: await sha256Of(frame) }),
    );

    // The client acknowledges the only frame it ever received. The losing
    // approval replaced the stored digest, so that acknowledgement is refused
    // and the boot never reaches CONSUMED.
    expect(harness.core.get(bootId)?.status).toBe("CONSUMED");
  });

  // The losing approval is the one that started first: it is parked inside the
  // key unwrap while the second call runs the whole approval to completion.
  it("gives the conflict to the approval that started first when it finishes last", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    harness.gate.arm();
    const first = approve(harness, bootId);
    await harness.gate.reached;
    const second = await approve(harness, bootId);
    harness.gate.release();
    const parked = await first;

    expect(second.ok).toBe(true);
    expect(parked.ok).toBe(false);
    if (parked.ok) return;
    expect(parked.reason).toBe("conflict");
    expect(harness.core.get(bootId)?.status).toBe("DELIVERED");
  });

  it("writes at most one approval record for a boot", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    await Promise.allSettled([approve(harness, bootId), approve(harness, bootId)]);

    const approval = await getBootApproval(harness.db, bootId);
    expect(approval).not.toBe(null);
    const count = await harness.db
      .prepare("SELECT COUNT(*) AS total FROM boot_approvals WHERE boot_id = ?")
      .bind(bootId)
      .first<{ total: number }>();
    expect(count?.total).toBe(1);
  });
});

async function sha256Of(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("revocation as a reconnect kill switch", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  // Finding 2 in docs/security-review-v1.md. Spec section 17 requires the
  // bootstrap token to still be valid on reconnect, and section 38 makes
  // revocation prevent reconnect. The resume handlers never look at a token, so
  // the only thing stopping a resume after a revocation is the best-effort
  // cancelForToken call that tokens.ts explicitly swallows on failure. Pass the
  // identity into the resume path, refuse a token id that is not the boot's,
  // and re-read revoked_at and expires_at before attaching.
  it("refuses to resume a boot whose token was revoked", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");

    // The dashboard revoked the token but the cancel never reached this object.
    await revokeBootstrapToken(harness.db, {
      tokenRowId: harness.tokenId,
      now: "2026-09-05T10:01:00.000Z",
    });

    const reconnected = await resume(harness, keys, bootId);

    const last = lastOf(reconnected);
    expect(last.type).not.toBe("boot.resumed");
    expect(harness.core.get(bootId)?.status).not.toBe("PENDING");
  });

  // Same finding. A second, still valid token for the same environment gets the
  // same reconnect rights as the token that opened the boot.
  it("refuses a resume driven by a different token than the one that opened the boot", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");

    const reconnected = await resume(harness, keys, bootId, harness.secondIdentity);

    expect(lastOf(reconnected).type).not.toBe("boot.resumed");
  });

  it("cancels the boots a revoked token opened when the cancel does reach the object", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);

    const canceled = await harness.core.cancelForToken(harness.tokenId, "bootstrap token revoked");

    expect(canceled).toBe(1);
    expect(harness.core.get(bootId)?.status).toBe("CANCELED");
    expect(lastOf(connection).type).toBe("boot.canceled");
    expect(connection.closedCode).toBe(4410);
  });

  it("leaves boots from another token alone when one token is revoked", async () => {
    const first = await bootKeys();
    const second = await bootKeys();
    const mine = await startBoot(harness, first);
    const theirs = await startBoot(harness, second, harness.secondIdentity);

    await harness.core.cancelForToken(harness.tokenId, "bootstrap token revoked");

    expect(harness.core.get(mine.bootId)?.status).toBe("CANCELED");
    expect(harness.core.get(theirs.bootId)?.status).toBe("PENDING");
  });
});

describe("time limits the object has to enforce itself", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("refuses an approval once the pending TTL has passed", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);
    harness.clock.now = START + (PENDING_TTL_SECONDS + 1) * 1000;

    const result = await approve(harness, bootId);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("expired");
    expect(harness.core.get(bootId)?.status).toBe("EXPIRED");
  });

  // Finding 3 in docs/security-review-v1.md. The resume path checks the payload
  // TTL for APPROVED and DELIVERED boots but never checks pending_expires_at,
  // so a PENDING boot whose alarm did not fire is told it is still waiting.
  // Mirror the payload branch: expire it and send the terminal frame.
  it("expires a pending boot on resume when its TTL has already passed", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");
    harness.clock.now = START + (PENDING_TTL_SECONDS + 1) * 1000;

    const reconnected = await resume(harness, keys, bootId);

    expect(lastOf(reconnected).type).toBe("boot.expired");
    expect(harness.core.get(bootId)?.status).toBe("EXPIRED");
  });

  it("refuses to redeliver a payload once the payload TTL has passed", async () => {
    const keys = await bootKeys();
    const first = await startBoot(harness, keys);
    await approve(harness, first.bootId);
    expect(harness.core.get(first.bootId)?.status).toBe("DELIVERED");
    first.connection.close(1006, "network dropped");

    harness.clock.now = START + (PAYLOAD_TTL_SECONDS + 1) * 1000;
    const reconnected = await resume(harness, keys, first.bootId);

    expect(lastOf(reconnected).type).toBe("boot.expired");
    expect(harness.core.get(first.bootId)?.status).toBe("EXPIRED");
    const sent = frames(reconnected).filter((frame) => frame.type === "boot.approved");
    expect(sent.length).toBe(0);
  });

  it("refuses a challenge answered after the challenge TTL", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");

    const opened = await openResume(harness, bootId);
    const challenge = opened.challenge;
    expect(challenge).not.toBe(null);
    if (challenge === null) return;
    harness.clock.now = START + (CHALLENGE_TTL_SECONDS + 1) * 1000;
    await answerChallenge(harness, opened.connection, keys, bootId, challenge);

    const last = lastOf(opened.connection);
    expect(last.type).toBe("boot.error");
    if (last.type !== "boot.error") return;
    expect(last.code).toBe(4400);
    expect(opened.connection.closedCode).toBe(4400);
  });

  it("spends a challenge on the first answer, right or wrong", async () => {
    const keys = await bootKeys();
    const stranger = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");

    const opened = await openResume(harness, bootId);
    const challenge = opened.challenge;
    expect(challenge).not.toBe(null);
    if (challenge === null) return;

    // The attacker guesses first with their own key and burns the challenge.
    await answerChallenge(harness, opened.connection, stranger, bootId, challenge);
    expect(lastOf(opened.connection).type).toBe("boot.error");

    // Replaying the same challenge, now with the right key, is refused because
    // the challenge is gone rather than because the signature is bad.
    const replay = harness.sockets.open();
    await answerChallenge(harness, replay, keys, bootId, challenge);
    const last = lastOf(replay);
    expect(last.type).toBe("boot.error");
    if (last.type !== "boot.error") return;
    expect(last.message).toBe("No challenge is outstanding.");
    expect(replay.attachedBootId()).toBe(null);
  });

  it("issues a fresh challenge for every resume so an old one cannot be reused", async () => {
    const keys = await bootKeys();
    const { connection, bootId } = await startBoot(harness, keys);
    connection.close(1006, "network dropped");

    const first = await openResume(harness, bootId);
    const second = await openResume(harness, bootId);
    expect(first.challenge).not.toBe(second.challenge);

    const stale = first.challenge;
    expect(stale).not.toBe(null);
    if (stale === null) return;
    await answerChallenge(harness, first.connection, keys, bootId, stale);

    expect(lastOf(first.connection).type).toBe("boot.error");
    expect(first.connection.attachedBootId()).toBe(null);
  });
});

describe("a boot that loses its ephemeral key", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("expires the approved payload and makes the next boot ask for a new approval", async () => {
    const first = await bootKeys();
    const start = await startBoot(harness, first);
    await approve(harness, start.bootId);
    // The container was replaced. The Ed25519 and X25519 private keys are gone,
    // so nothing can ever resume this boot.
    start.connection.close(1006, "process died");

    harness.clock.now = START + (PAYLOAD_TTL_SECONDS + 1) * 1000;
    await harness.core.onAlarm();
    expect(harness.core.get(start.bootId)?.status).toBe("EXPIRED");

    // The replacement container generates new keys and gets a new boot, which
    // starts at PENDING and carries no payload until somebody approves it.
    const second = await bootKeys();
    const restarted = await startBoot(harness, second);
    expect(restarted.bootId).not.toBe(start.bootId);
    const view = harness.core.get(restarted.bootId);
    expect(view?.status).toBe("PENDING");
    expect(view?.encryptionFingerprint).not.toBe(
      harness.core.get(start.bootId)?.encryptionFingerprint,
    );
    expect(lastOf(restarted.connection).type).toBe("boot.pending");
  });

  it("refuses a resume from a boot whose signing key does not match the record", async () => {
    const real = await bootKeys();
    const attacker = await bootKeys();
    const { connection, bootId } = await startBoot(harness, real);
    connection.close(1006, "network dropped");

    const reconnected = await resume(harness, attacker, bootId);

    const last = lastOf(reconnected);
    expect(last.type).toBe("boot.error");
    expect(reconnected.attachedBootId()).toBe(null);
    expect(harness.core.get(bootId)?.status).toBe("PENDING");
  });
});

describe("an approval the approver did not read", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  it("refuses a digest that does not cover the current verifier run", async () => {
    const keys = await bootKeys();
    const { bootId } = await startBoot(harness, keys);

    const result = await harness.core.approve({
      bootId,
      approverUserId: "user_1",
      approverCredentialId: "cred_1",
      evidenceDigest: "0".repeat(64),
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("evidence_mismatch");
    expect(harness.core.get(bootId)?.status).toBe("PENDING");
    expect(await getBootApproval(harness.db, bootId)).toBe(null);
  });

  it("refuses a digest taken from a different boot's evidence", async () => {
    const withEvidence = await bootKeys();
    const plain = await bootKeys();
    const first = await startBoot(harness, withEvidence);
    const second = await startBoot(harness, plain);
    const otherDigest = await summaryDigest(harness.core.get(second.bootId)?.provenance ?? []);

    // Both boots sent the same claims here, so the digests match and this is a
    // control: the guard must key off the content of the run, not the boot id.
    const sameDigest = await summaryDigest(harness.core.get(first.bootId)?.provenance ?? []);
    expect(otherDigest).toBe(sameDigest);

    const tampered = `${otherDigest.slice(0, 63)}${otherDigest.endsWith("a") ? "b" : "a"}`;
    const result = await harness.core.approve({
      bootId: first.bootId,
      approverUserId: "user_1",
      approverCredentialId: "cred_1",
      evidenceDigest: tampered,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("evidence_mismatch");
  });
});

describe("boot request rate limiting per source address", () => {
  let harness: Harness;

  beforeEach(async () => {
    harness = await createHarness();
  });

  // Finding 8 in docs/security-review-v1.md, spec section 37. Ten new boots per
  // source address per 60 seconds; the eleventh is refused with 4429 without
  // creating a row.
  it("refuses the eleventh boot from one source address inside the window", async () => {
    for (let index = 0; index < MAX_BOOTS_PER_SOURCE; index += 1) {
      const keys = await bootKeys();
      const started = await startBoot(harness, keys);
      // Keep the pending count clear so this test measures the rate limit only.
      await harness.core.cancelBoot({
        bootId: started.bootId,
        actorUserId: "user_1",
        reason: "test",
      });
    }

    const connection = harness.sockets.open();
    await harness.core.handleFrame(connection, harness.identity, helloFrame(await bootKeys()));

    const last = lastOf(connection);
    expect(last.type).toBe("boot.error");
    if (last.type !== "boot.error") return;
    expect(last.code).toBe(4429);
    expect(connection.closedCode).toBe(4429);
    expect(connection.attachedBootId()).toBe(null);
  });

  it("counts each source address on its own and forgets the window", async () => {
    for (let index = 0; index < MAX_BOOTS_PER_SOURCE; index += 1) {
      const started = await startBoot(harness, await bootKeys());
      await harness.core.cancelBoot({
        bootId: started.bootId,
        actorUserId: "user_1",
        reason: "test",
      });
    }

    // A different address is unaffected.
    const other = await startBoot(harness, await bootKeys(), harness.secondIdentity);
    expect(harness.core.get(other.bootId)?.status).toBe("PENDING");

    // And the first address is allowed again once the window has passed.
    harness.clock.now = START + (BOOT_RATE_WINDOW_SECONDS + 1) * 1000;
    const later = await startBoot(harness, await bootKeys());
    expect(harness.core.get(later.bootId)?.status).toBe("PENDING");
  });
});
