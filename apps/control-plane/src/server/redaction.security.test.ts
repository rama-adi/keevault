import { DatabaseSync } from "node:sqlite";

import {
  b64uEncode,
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  generatePrefixedUlid,
  generateResumeChallenge,
  generateX25519PrivateKey,
  hexEncode,
  randomBytes,
  signResume,
  x25519PublicKeyFromPrivate,
  type Bytes,
} from "@env-vault/crypto";
import { parseServerFrame, type ServerMessage } from "@env-vault/protocol";
import type { VaultDatabase } from "@env-vault/vault-store";
import { afterEach, beforeEach, expect, test } from "vite-plus/test";
import { z } from "zod";

import { routeBootstrapUpgrade } from "./bootstrap/upgrade.ts";
import { BootSessionCore, type BootIdentity } from "./durable-objects/boot-session-core.ts";
import {
  FakeConnection,
  FakeSocketRegistry,
  fromNodeSqliteStorage,
} from "./durable-objects/test-support.ts";
import { log } from "./log.ts";
import { V1_VERIFIERS, summaryDigest } from "./provenance/index.ts";
import { unwrapEnvironmentDek } from "./vault/keys.ts";
import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  importDotenv,
  listAuditEvents,
  putSecret,
  revokeBootstrapToken,
  rotateEnvironmentKey,
} from "./vault/service.ts";
import { createTestContext } from "./vault/test-context.ts";

/**
 * One scenario, every writer that could leak (spec sections 35 and 36).
 *
 * The point is not that each writer is careful on its own; the other tests
 * already check that. The point is that a whole administrative session plus a
 * whole boot, run end to end, produces no line and no stored row anywhere that
 * contains a secret value, a bootstrap token, an environment key or a master
 * key. Every output the server produced during the run is concatenated and
 * searched for the same marker list.
 */

const DATABASE_URL = "postgres://vault:hunter2@db.internal:5432/app";
const API_KEY = "sk-live-0123456789abcdef";
const STRIPE_KEY = "rk_live_51ABCDEFGHIJKLMNOP";
const START = Date.parse("2026-09-05T10:00:00.000Z");

interface ConsoleCapture {
  lines: string[];
  restore: () => void;
}

/**
 * Replace the three console methods `log()` writes through and keep every line.
 * This is a global stub, not a module mock: the log layer is imported normally
 * and is the code under test.
 */
function captureConsole(): ConsoleCapture {
  const lines: string[] = [];
  const original = {
    log: globalThis.console.log,
    warn: globalThis.console.warn,
    error: globalThis.console.error,
  };
  const collect = (line: string): void => {
    lines.push(line);
  };
  globalThis.console.log = collect;
  globalThis.console.warn = collect;
  globalThis.console.error = collect;
  return {
    lines,
    restore: (): void => {
      globalThis.console.log = original.log;
      globalThis.console.warn = original.warn;
      globalThis.console.error = original.error;
    },
  };
}

let capture: ConsoleCapture;

beforeEach(() => {
  capture = captureConsole();
});

afterEach(() => {
  capture.restore();
});

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

function lastOf(connection: FakeConnection): ServerMessage {
  const text = connection.sent[connection.sent.length - 1] ?? "";
  const parsed = parseServerFrame(text);
  if (!parsed.ok) throw new Error(`server sent an invalid frame: ${parsed.error}`);
  return parsed.message;
}

const rowsSchema = z.array(z.record(z.string(), z.union([z.string(), z.number(), z.null()])));
const tableNamesSchema = z.array(z.object({ name: z.string() }));

/** Every table in the vault database, serialised. */
async function dumpVault(db: VaultDatabase): Promise<string> {
  const listed = await db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
  const parts: string[] = [];
  for (const table of tableNamesSchema.parse(listed.results)) {
    const rows = await db.prepare(`SELECT * FROM "${table.name}"`).all();
    parts.push(`${table.name}: ${JSON.stringify(rowsSchema.parse(rows.results))}`);
  }
  return parts.join("\n");
}

/** Every table in the Durable Object's own storage, serialised. */
function dumpObjectStorage(storage: DatabaseSync): string {
  const listed = tableNamesSchema.parse(
    storage.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all(),
  );
  const parts: string[] = [];
  for (const table of listed) {
    const rows = storage.prepare(`SELECT * FROM "${table.name}"`).all();
    parts.push(`${table.name}: ${JSON.stringify(rowsSchema.parse(rows))}`);
  }
  return parts.join("\n");
}

test("a full administrative session and boot leak nothing through logs or stored rows", async () => {
  const { context } = await createTestContext();

  // 1. An operator sets up a project, an environment and its secrets.
  const project = await createProject(context, { slug: "acme", name: "Acme" });
  const environment = await createEnvironment(context, {
    projectId: project.id,
    slug: "production",
    name: "Production",
  });
  await putSecret(context, {
    environmentId: environment.id,
    name: "DATABASE_URL",
    value: DATABASE_URL,
  });
  await importDotenv(context, {
    environmentId: environment.id,
    content: [`API_KEY="${API_KEY}"`, `# a comment`, `export STRIPE_KEY='${STRIPE_KEY}'`].join(
      "\n",
    ),
  });
  const minted = await createBootstrapToken(context, {
    environmentId: environment.id,
    label: "zeabur-prod-01",
    allowedCidrs: ["203.0.113.0/24"],
    expiresAt: null,
    maxPendingBoots: 3,
  });
  await rotateEnvironmentKey(context, environment.id);

  // 2. A stranger tries the endpoint with a wrong token, then the real client
  //    connects. Both paths write a line through the redacting log layer.
  const [tokenPrefix] = minted.token.split(".");
  const wrongToken = `${tokenPrefix ?? ""}.${"A".repeat(43)}`;
  const upgrade = (token: string, ip: string): Request =>
    new Request("https://vault.test/bootstrap/v1", {
      method: "GET",
      headers: new Headers({
        Upgrade: "websocket",
        Authorization: `Bearer ${token}`,
        "CF-Connecting-IP": ip,
        Cookie: "better-auth.session_token=a-session-nobody-should-see",
      }),
    });
  const router = {
    fetchEnvironment: (): Promise<Response> => Promise.resolve(new Response(null, { status: 200 })),
  };
  await routeBootstrapUpgrade(upgrade(wrongToken, "198.51.100.7"), context.db, router);
  await routeBootstrapUpgrade(upgrade(minted.token, "198.51.100.7"), context.db, router);
  await routeBootstrapUpgrade(upgrade(minted.token, "203.0.113.42"), context.db, router);

  // 3. A boot runs to CONSUMED against the real key hierarchy.
  const objectStorage = new DatabaseSync(":memory:");
  const sockets = new FakeSocketRegistry();
  const clock = { now: START };
  const core = new BootSessionCore({
    storage: fromNodeSqliteStorage(objectStorage),
    db: context.db,
    environmentId: environment.id,
    now: () => clock.now,
    newBootId: () => generatePrefixedUlid("boot"),
    newAuditId: () => generatePrefixedUlid("aud"),
    randomChallenge: () => generateResumeChallenge(),
    unwrapDek: async () => await unwrapEnvironmentDek(context.db, context.keyring, environment.id),
    sockets: { forBoot: (bootId: string) => sockets.forBoot(bootId) },
    scheduleAlarm: () => undefined,
    verifiers: V1_VERIFIERS,
  });

  const tokenRowId = (
    await context.db
      .prepare("SELECT id AS id FROM bootstrap_tokens WHERE environment_id = ?")
      .bind(environment.id)
      .first<{ id: string }>()
  )?.id;
  expect(tokenRowId).toBeDefined();
  const identity: BootIdentity = {
    tokenId: tokenRowId ?? "",
    sourceIp: "203.0.113.42",
    maxPendingBoots: 3,
  };

  const keys = await bootKeys();
  const connection = sockets.open();
  await core.handleFrame(
    connection,
    identity,
    JSON.stringify({
      type: "boot.hello",
      protocol: 1,
      bootNonce: b64uEncode(randomBytes(16)),
      signingPublicKey: keys.signingPublicKey,
      encryptionPublicKey: keys.encryptionPublicKey,
      claims: { provider: { name: "zeabur", deploymentId: "dep-1234" } },
      evidence: [],
    }),
  );
  const pending = lastOf(connection);
  expect(pending.type).toBe("boot.pending");
  if (pending.type !== "boot.pending") return;
  const bootId = pending.bootId;

  const view = core.get(bootId);
  const approved = await core.approve({
    bootId,
    approverUserId: "user_1",
    approverCredentialId: "cred_1",
    evidenceDigest: await summaryDigest(view?.provenance ?? []),
  });
  expect(approved.ok).toBe(true);

  // A reconnect too, so the challenge table gets written and read.
  connection.close(1006, "network dropped");
  const reconnected = sockets.open();
  await core.handleFrame(
    reconnected,
    identity,
    JSON.stringify({ type: "boot.resume", protocol: 1, bootId }),
  );
  const challengeFrame = lastOf(reconnected);
  expect(challengeFrame.type).toBe("boot.challenge");
  if (challengeFrame.type !== "boot.challenge") return;
  await core.handleFrame(
    reconnected,
    identity,
    JSON.stringify({
      type: "boot.challenge-response",
      bootId,
      signature: await signResume({
        seed: keys.seed,
        bootId,
        challenge: challengeFrame.challenge,
      }),
    }),
  );
  const deliveredFrame = reconnected.sent[reconnected.sent.length - 1] ?? "";
  const payloadDigest = hexEncode(
    new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(deliveredFrame)),
    ),
  );
  await core.handleFrame(
    reconnected,
    identity,
    JSON.stringify({ type: "boot.received", bootId, payloadDigest }),
  );
  expect(core.get(bootId)?.status).toBe("CONSUMED");

  // 4. The token is revoked, which writes one more audit event and one more log
  //    line when the object cannot be reached.
  await revokeBootstrapToken(context, tokenRowId ?? "");

  // Everything the server wrote down during the run.
  const audit = await listAuditEvents(context, {
    projectId: null,
    environmentId: null,
    before: null,
    limit: 500,
  });
  const dek = await unwrapEnvironmentDek(context.db, context.keyring, environment.id);
  const masterKey = context.keyring.key(context.keyring.activeVersion);

  const written = [
    capture.lines.join("\n"),
    JSON.stringify(audit.events),
    await dumpVault(context.db),
    dumpObjectStorage(objectStorage),
  ].join("\n");

  // The scenario has to have produced output, otherwise the search below is
  // vacuous.
  expect(capture.lines.length).toBeGreaterThan(2);
  expect(audit.events.length).toBeGreaterThan(8);
  expect(written).toContain("bootstrap.upgrade.accepted");
  expect(written).toContain("boot.consumed");

  const markers = new Map<string, string>([
    ["a secret value written through the dashboard", DATABASE_URL],
    ["a password inside a secret value", "hunter2"],
    ["a secret value imported from a dotenv file", API_KEY],
    ["a quoted secret value imported from a dotenv file", STRIPE_KEY],
    ["the whole bootstrap token", minted.token],
    ["the secret half of the bootstrap token", minted.token.split(".")[1] ?? ""],
    ["the environment key as base64url", b64uEncode(dek.dek)],
    ["the environment key as hex", hexEncode(dek.dek)],
    ["the master key as base64url", b64uEncode(masterKey)],
    ["the master key as hex", hexEncode(masterKey)],
    ["the session cookie sent on the upgrade", "a-session-nobody-should-see"],
  ]);
  for (const [description, marker] of markers) {
    expect(marker.length).toBeGreaterThan(6);
    if (written.includes(marker)) {
      throw new Error(`${description} appears in something the server wrote down`);
    }
  }
});

test("the log layer cannot be handed a value that is not in its field list", () => {
  log({
    level: "warn",
    event: "test.only",
    outcome: "denied",
    reason: "step_up_required",
    tokenId: "tok_01K4M4X31X2Z5G9C7Q8D3E6F4G",
    method: "POST",
    path: "/bootstrap/v1",
    status: 401,
  });

  const line = capture.lines[0] ?? "";
  const parsed = JSON.parse(line);
  expect(Object.keys(parsed).sort()).toEqual(
    ["event", "level", "method", "outcome", "path", "reason", "status", "tokenId"].sort(),
  );
  // No query string, no body, no headers: there is nowhere in the shape for one
  // to go.
  expect(line).not.toContain("?");
});
