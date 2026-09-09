import { expect, test } from "vite-plus/test";
import { z } from "zod";

import {
  appendAuditEvent,
  createBootstrapToken,
  createEnvironment,
  createProject,
  upsertSecretReplace,
} from "../src/index.ts";
import { createTestVault, NOW } from "./helpers.ts";

const tableNameRowSchema = z.object({ name: z.string() });

const MARKER_PLAINTEXT = "SUPER-SECRET-PLAINTEXT-VALUE";
const SEALED_CIPHERTEXT = "b3BhcXVlLWNpcGhlcnRleHQtZm9yLXRoZS1tYXJrZXI";

test("no table holds the plaintext of a stored secret", async () => {
  const vault = await createTestVault();
  const db = vault.db;

  await createProject(db, { id: "proj_ONE", slug: "acme", name: "Acme", now: NOW });
  await createEnvironment(db, {
    id: "env_ONE",
    projectId: "proj_ONE",
    slug: "production",
    name: "Production",
    provenanceMode: "ADVISORY",
    pendingTtlSeconds: 1800,
    approvedTtlSeconds: 300,
    now: NOW,
  });
  await createBootstrapToken(db, {
    id: "tok_ONE",
    environmentId: "env_ONE",
    label: "zeabur-prod-1",
    tokenHash: "a".repeat(64),
    allowedCidrsJson: "[]",
    maxPendingBoots: 3,
    expiresAt: null,
    now: NOW,
  });
  await upsertSecretReplace(db, {
    expectedVersion: 0,
    id: "sec_ONE",
    environmentId: "env_ONE",
    name: "DATABASE_URL",
    ciphertext: SEALED_CIPHERTEXT,
    nonce: "bm9uY2UtZm9yLXRoZS1tYXJrZXI",
    envKeyVersion: 1,
    now: NOW,
  });
  await appendAuditEvent(db, {
    id: "aud_ONE",
    timestamp: NOW,
    actorType: "user",
    actorId: "user_1",
    action: "secret.created",
    projectId: "proj_ONE",
    environmentId: "env_ONE",
    bootId: null,
    metadataJson: JSON.stringify({ name: "DATABASE_URL", version: 1 }),
  });

  const tables = vault.sqlite
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
    .all()
    .map((row) => tableNameRowSchema.parse(row).name);
  expect(tables).toContain("secrets");

  let scannedRows = 0;
  for (const table of tables) {
    const rows = vault.sqlite.prepare(`SELECT * FROM "${table}"`).all();
    scannedRows += rows.length;
    expect(JSON.stringify(rows)).not.toContain(MARKER_PLAINTEXT);
  }
  expect(scannedRows).toBeGreaterThan(0);

  const storedSecret = vault.sqlite.prepare("SELECT ciphertext FROM secrets").all();
  expect(JSON.stringify(storedSecret)).toContain(SEALED_CIPHERTEXT);
});
