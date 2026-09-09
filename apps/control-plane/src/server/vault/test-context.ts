/**
 * Test support for the vault service.
 *
 * Builds a `VaultContext` over an in-memory database with the real migration
 * applied and a freshly generated master key. Nothing in the Worker bundle
 * imports this module.
 */

import { b64uEncode, generateKey32 } from "@keevault/crypto";
import type { VaultDatabase } from "@keevault/vault-store";

import { createTestVault } from "../bootstrap/test-vault.ts";
import type { AuditActor } from "./audit.ts";
import type { BootSessionControl, VaultContext } from "./context.ts";
import { loadMasterKeys, type MasterKeyEnv } from "./keys.ts";

/** One recorded call to the boot control. */
export interface RecordedBootCancel {
  kind: "token" | "environment";
  environmentId: string;
  /** The `tok_`-prefixed row id, or null for a whole-environment cancel. */
  tokenRowId: string | null;
  reason: string;
}

/**
 * A boot control that records what it was asked to cancel.
 *
 * `fail` makes both calls throw, which is how a test proves the token still
 * ends up revoked when the Durable Object cannot be reached.
 */
export interface RecordingBootControl extends BootSessionControl {
  readonly calls: RecordedBootCancel[];
  fail: boolean;
}

export function createRecordingBootControl(): RecordingBootControl {
  const calls: RecordedBootCancel[] = [];
  const control: RecordingBootControl = {
    calls,
    fail: false,
    async cancelForToken(
      environmentId: string,
      tokenRowId: string,
      reason: string,
    ): Promise<number> {
      if (control.fail) throw new Error("the environment object is unreachable");
      calls.push({ kind: "token", environmentId, tokenRowId, reason });
      return await Promise.resolve(1);
    },
    async cancelEnvironment(environmentId: string, reason: string): Promise<number> {
      if (control.fail) throw new Error("the environment object is unreachable");
      calls.push({ kind: "environment", environmentId, tokenRowId: null, reason });
      return await Promise.resolve(1);
    },
  };
  return control;
}

export interface TestVaultContext {
  context: VaultContext;
  db: VaultDatabase;
  /** Advance the fake clock by one second and return the new time. */
  tick: () => string;
  /** Every cancel the service asked for, in order. */
  boots: RecordingBootControl;
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
  const boots = createRecordingBootControl();
  const context: VaultContext = {
    db: vault.db,
    keyring,
    actor: TEST_ACTOR,
    now: tick,
    boots,
  };
  return { context, db: vault.db, tick, boots };
}
