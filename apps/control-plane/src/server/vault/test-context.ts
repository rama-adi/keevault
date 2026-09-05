/**
 * Test support for the vault service.
 *
 * Builds a `VaultContext` over an in-memory database with the real migration
 * applied and a freshly generated master key. Nothing in the Worker bundle
 * imports this module.
 */

import { b64uEncode, generateKey32 } from "@env-vault/crypto";
import type { VaultDatabase } from "@env-vault/vault-store";

import { createTestVault } from "../bootstrap/test-vault.ts";
import type { AuditActor } from "./audit.ts";
import type { VaultContext } from "./context.ts";
import { loadMasterKeys, type MasterKeyEnv } from "./keys.ts";

export interface TestVaultContext {
  context: VaultContext;
  db: VaultDatabase;
  /** Advance the fake clock by one second and return the new time. */
  tick: () => string;
}

const TEST_ACTOR: AuditActor = { type: "user", id: "user_test" };

/** A Worker environment carrying one generated master key at version 1. */
export function createTestEnv(activeVersion = 1): MasterKeyEnv {
  const bindings = new Map<string, string>([
    ["VAULT_MASTER_KEY_ACTIVE_VERSION", String(activeVersion)],
  ]);
  for (let version = 1; version <= activeVersion; version += 1) {
    bindings.set(`VAULT_MASTER_KEY_V${version}`, b64uEncode(generateKey32()));
  }
  return {
    ...Object.fromEntries(bindings),
    VAULT_MASTER_KEY_ACTIVE_VERSION: String(activeVersion),
  };
}

export async function createTestContext(): Promise<TestVaultContext> {
  const vault = await createTestVault();
  const keyring = loadMasterKeys(createTestEnv());
  let clock = Date.parse("2026-09-05T10:00:00.000Z");
  const tick = (): string => {
    clock += 1000;
    return new Date(clock).toISOString();
  };
  const context: VaultContext = {
    db: vault.db,
    keyring,
    actor: TEST_ACTOR,
    now: tick,
  };
  return { context, db: vault.db, tick };
}
