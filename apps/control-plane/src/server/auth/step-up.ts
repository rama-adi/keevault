import { createServerFn } from "@tanstack/react-start";

import { STEP_UP_MAX_AGE_SECONDS } from "../../lib/roles.ts";
import { log } from "../log.ts";
import { requireRecentPasskey } from "./guards.ts";

export interface StepUpResult {
  verifiedAt: string;
  expiresAt: string;
}

/**
 * Confirm that the caller just re-authenticated with a passkey and report how
 * long the step-up is good for (spec section 22).
 *
 * The passkey plugin in 1.7.2 has no re-verify endpoint, so the client runs a
 * fresh passkey sign-in (`authClient.signIn.passkey()`) immediately before
 * calling this. That assertion creates the session this function reads, and the
 * session row is stamped with `stepUpAt` at creation. Splitting it this way
 * keeps the WebAuthn ceremony in the browser, where it has to happen, and keeps
 * the authoritative timestamp on the server, where the guards read it.
 *
 * This module holds only the server function so the browser bundle can import
 * it without pulling in the Worker-only auth instance.
 */
export const stepUp = createServerFn({ method: "POST" }).handler(
  async (): Promise<StepUpResult> => {
    const session = await requireRecentPasskey();
    const verifiedAt = session.stepUpAt ?? new Date();
    log({
      level: "info",
      event: "auth.step_up.granted",
      userId: session.userId,
      role: session.role,
      outcome: "ok",
    });
    return {
      verifiedAt: verifiedAt.toISOString(),
      expiresAt: new Date(verifiedAt.getTime() + STEP_UP_MAX_AGE_SECONDS * 1000).toISOString(),
    };
  },
);
