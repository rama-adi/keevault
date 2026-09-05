import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { fromNodeSqlite, runMigrations } from "../src/index.ts";
import type { VaultDatabase } from "../src/index.ts";

const migrationSql = readFileSync(
  new URL("../../../migrations/vault/0001_init.sql", import.meta.url),
  "utf8",
);

export interface TestVault {
  sqlite: DatabaseSync;
  db: VaultDatabase;
}

/** An in-memory vault database with the real 0001_init.sql applied. */
export async function createTestVault(): Promise<TestVault> {
  const sqlite = new DatabaseSync(":memory:");
  const db = fromNodeSqlite(sqlite);
  await runMigrations(db, migrationSql);
  return { sqlite, db };
}

export const NOW = "2026-09-05T10:00:00.000Z";
export const LATER = "2026-09-05T11:00:00.000Z";
