/**
 * The handle every vault service function takes.
 *
 * It carries the database, the master keyring, who is acting, the clock and the
 * handle used to cancel live boots. Nothing here reaches for a Cloudflare
 * binding, so a test can build a context over `node:sqlite`, a generated master
 * key and a recording boot control.
 */

import type { VaultDatabase } from "@env-vault/vault-store";

import type { AuditActor } from "./audit.ts";
import type { MasterKeyring } from "./keys.ts";

/**
 * Cancelling live boots from the vault service (spec sections 38 and 40).
 *
 * The Durable Object owns boot state, so revoking a token or removing an
 * environment has to reach it. The Worker implements this with the
 * `ENVIRONMENT_SESSION` stub; a test implements it with a recorder, which keeps
 * the service runnable over `node:sqlite`.
 *
 * Both calls return the number of boots that moved to CANCELED.
 */
export interface BootSessionControl {
  /** Cancel every live boot opened with one bootstrap token. */
  cancelForToken(environmentId: string, tokenRowId: string, reason: string): Promise<number>;
  /** Cancel every live boot in one environment. */
  cancelEnvironment(environmentId: string, reason: string): Promise<number>;
}

export interface VaultContext {
  readonly db: VaultDatabase;
  readonly keyring: MasterKeyring;
  readonly actor: AuditActor;
  /** RFC 3339 UTC with millisecond precision. */
  readonly now: () => string;
  /** Reaches the environment Durable Object to cancel boots. */
  readonly boots: BootSessionControl;
}

/** The default clock: the wall clock, formatted the way D1 rows store time. */
export function systemClock(): string {
  return new Date().toISOString();
}
