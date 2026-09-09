/**
 * Building a `VaultContext` from the live Worker request.
 *
 * Only server functions and the Worker entry import this module. It is the one
 * place that reaches for Cloudflare bindings, which keeps the service and its
 * tests free of the workerd runtime.
 */

import { fromD1 } from "@keevault/vault-store";
import { env } from "cloudflare:workers";

import type { VaultSession } from "../auth/guards.ts";
import type { BootSessionControl, VaultContext } from "./context.ts";
import { systemClock } from "./context.ts";
import { loadMasterKeys } from "./keys.ts";

/** Boot cancellation over the environment Durable Object binding. */
export const workerBootSessionControl: BootSessionControl = {
  async cancelForToken(environmentId: string, tokenRowId: string, reason: string): Promise<number> {
    return await stubFor(environmentId).cancelForToken(tokenRowId, reason);
  },
  async cancelEnvironment(environmentId: string, reason: string): Promise<number> {
    return await stubFor(environmentId).cancel(reason);
  },
};

function stubFor(environmentId: string) {
  return env.ENVIRONMENT_SESSION.get(env.ENVIRONMENT_SESSION.idFromName(environmentId));
}

/** A context acting as the signed-in operator. */
export function vaultContextForSession(session: VaultSession): VaultContext {
  return {
    db: fromD1(env.VAULT_DB),
    keyring: loadMasterKeys(env),
    actor: { type: "user", id: session.userId },
    now: systemClock,
    boots: workerBootSessionControl,
  };
}

/** The master key versions this Worker can read, for the settings page. */
export function masterKeyVersionsPresent(): number[] {
  return [...loadMasterKeys(env).versions];
}

/** The version that wraps newly generated project keys. */
export function activeMasterKeyVersion(): number {
  return loadMasterKeys(env).activeVersion;
}
