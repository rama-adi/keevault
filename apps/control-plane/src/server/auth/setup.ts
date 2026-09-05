import { createServerFn } from "@tanstack/react-start";
import { notFound } from "@tanstack/react-router";
import { z } from "zod";

import { log } from "../log.ts";
import { createAuth } from "./auth.ts";
import { requireRole } from "./guards.ts";

/** True while the vault has no accounts at all. */
export async function ownerExists(): Promise<boolean> {
  const auth = createAuth();
  const context = await auth.$context;
  const users = await context.internalAdapter.listUsers(1);
  return users.length > 0;
}

/**
 * Route guard for /setup. Once an owner exists the route is gone for everyone,
 * signed in or not. The setup token itself is checked server side by the
 * Better Auth endpoint in setup-plugin.ts, not here.
 */
export const assertSetupOpen = createServerFn({ method: "GET" }).handler(
  async (): Promise<{ open: true }> => {
    if (await ownerExists()) {
      log({
        level: "info",
        event: "auth.setup.closed",
        outcome: "denied",
        reason: "owner_exists",
      });
      throw notFound();
    }
    return { open: true };
  },
);

const inviteAdminInput = z.object({
  email: z.email().max(254),
  name: z.string().min(1).max(128),
  role: z.enum(["admin", "viewer"]),
});

/**
 * Stub. Owners add further administrators after the ceremony (spec section 21).
 *
 * TODO(dashboard-agent): implement invitation issuance. It needs a single-use
 * invite row in the auth D1 database, a mailed or copied invite link, and a
 * claim endpoint that registers the invitee's passkey the same way the setup
 * ceremony does. Guard it with `requireRecentPasskey` as well as `requireRole`,
 * since managing administrators is an owner-only, step-up operation.
 */
export const inviteAdmin = createServerFn({ method: "POST" })
  .validator(inviteAdminInput)
  .handler(async (): Promise<never> => {
    await requireRole("owner");
    throw new Error("inviteAdmin is not implemented yet.");
  });
