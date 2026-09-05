/**
 * Carrying a typed failure across the server-function boundary.
 *
 * A thrown `Error` reaches the browser as a message and nothing else, so the
 * kind of failure is encoded into the message with a fixed prefix and read back
 * on the client. The page uses the kind to decide what to do: open the step-up
 * dialog, redirect to /login, or show the message next to the field.
 *
 * This module is imported by both browser and Worker code, so it must stay free
 * of Cloudflare bindings and Better Auth imports.
 */

export const VAULT_ERROR_KINDS = [
  "unauthenticated",
  "forbidden",
  "step_up_required",
  "input",
  "key",
  "unknown",
] as const;

export type VaultErrorKind = (typeof VAULT_ERROR_KINDS)[number];

const PREFIX = "vault-error/";

/** Build the message a server function throws. */
export function encodeVaultError(kind: VaultErrorKind, message: string): string {
  return `${PREFIX}${kind}: ${message}`;
}

export interface DecodedVaultError {
  kind: VaultErrorKind;
  message: string;
}

const KIND_BY_NAME: ReadonlyMap<string, VaultErrorKind> = new Map(
  VAULT_ERROR_KINDS.map((kind) => [kind, kind]),
);

/** Read a thrown error back. Anything unrecognised comes back as "unknown". */
export function decodeVaultError(error: Error): DecodedVaultError {
  const text = error.message;
  if (!text.startsWith(PREFIX)) {
    return { kind: "unknown", message: text };
  }
  const separator = text.indexOf(": ", PREFIX.length);
  if (separator < 0) {
    return { kind: "unknown", message: text };
  }
  const kind = KIND_BY_NAME.get(text.slice(PREFIX.length, separator));
  if (kind === undefined) {
    return { kind: "unknown", message: text };
  }
  return { kind, message: text.slice(separator + 2) };
}

/** True when the caller should re-verify with a passkey and retry. */
export function needsStepUp(error: Error): boolean {
  return decodeVaultError(error).kind === "step_up_required";
}
