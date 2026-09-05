/**
 * The wrapper every vault server function runs its body in.
 *
 * It turns the guard, input and key errors into the encoded messages the pages
 * know how to read, so no stack trace or internal detail reaches the browser.
 */

import { encodeVaultError, type VaultErrorKind } from "../../lib/vault-errors.ts";
import { isAuthorizationError } from "../auth/guards.ts";
import { isVaultKeyError } from "../vault/keys.ts";
import { isVaultInputError } from "../vault/validation.ts";

const AUTH_KIND: ReadonlyMap<string, VaultErrorKind> = new Map<string, VaultErrorKind>([
  ["unauthenticated", "unauthenticated"],
  ["forbidden", "forbidden"],
  ["step_up_required", "step_up_required"],
]);

function toEncodedError(error: Error): Error {
  if (isAuthorizationError(error)) {
    return new Error(encodeVaultError(AUTH_KIND.get(error.code) ?? "forbidden", error.message));
  }
  if (isVaultInputError(error)) {
    return new Error(encodeVaultError("input", error.message));
  }
  if (isVaultKeyError(error)) {
    return new Error(encodeVaultError("key", error.message));
  }
  return new Error(encodeVaultError("unknown", "The vault could not complete that operation."));
}

/** Run a server function body and normalise anything it throws. */
export async function guarded<Result>(body: () => Promise<Result>): Promise<Result> {
  try {
    return await body();
  } catch (error) {
    throw toEncodedError(error instanceof Error ? error : new Error("unknown failure"));
  }
}
