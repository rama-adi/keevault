import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

import { fromNodeSqlite, runMigrations } from "@env-vault/vault-store";
import type { VaultDatabase } from "@env-vault/vault-store";

/**
 * An in-memory vault database with the real migration applied.
 *
 * Test support only. Nothing in the Worker bundle imports this module, and it
 * must stay that way: `node:sqlite` does not exist in workerd.
 */
const migrationSql = readFileSync(
  new URL("../../../../../migrations/vault/0001_init.sql", import.meta.url),
  "utf8",
);

export interface TestVault {
  readonly sqlite: DatabaseSync;
  readonly db: VaultDatabase;
}

export async function createTestVault(): Promise<TestVault> {
  const sqlite = new DatabaseSync(":memory:");
  const db = fromNodeSqlite(sqlite);
  await runMigrations(db, migrationSql);
  return { sqlite, db };
}
