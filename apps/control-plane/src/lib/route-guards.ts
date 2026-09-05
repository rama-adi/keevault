/**
 * Loader helper shared by every vault page.
 *
 * A loader that calls a guarded server function can fail because the operator is
 * not signed in. That is a redirect, not an error screen, so it is handled once
 * here instead of in every route file.
 */

import { redirect } from "@tanstack/react-router";

import { decodeVaultError } from "./vault-errors.ts";

export async function loadOrRedirect<Data>(load: () => Promise<Data>): Promise<Data> {
  try {
    return await load();
  } catch (error) {
    if (error instanceof Error && decodeVaultError(error).kind === "unauthenticated") {
      throw redirect({ to: "/login" });
    }
    throw error;
  }
}
