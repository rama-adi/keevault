/**
 * The handle every vault service function takes.
 *
 * It carries the database, the master keyring, who is acting and the clock.
 * Nothing here reaches for a Cloudflare binding, so a test can build a context
 * over `node:sqlite` and a generated master key.
 */

import type { VaultDatabase } from "@env-vault/vault-store";

import type { AuditActor } from "./audit.ts";
import type { MasterKeyring } from "./keys.ts";

export interface VaultContext {
  readonly db: VaultDatabase;
  readonly keyring: MasterKeyring;
  readonly actor: AuditActor;
  /** RFC 3339 UTC with millisecond precision. */
  readonly now: () => string;
}

/** The default clock: the wall clock, formatted the way D1 rows store time. */
export function systemClock(): string {
  return new Date().toISOString();
}
