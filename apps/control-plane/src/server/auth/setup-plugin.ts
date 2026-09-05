import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { env } from "cloudflare:workers";
import { z } from "zod";

import { log } from "../log.ts";
import { setupTokenAccepted } from "./setup-token.ts";

/**
 * First-owner setup ceremony (spec section 21).
 *
 * The vault ships with no accounts and public sign-up is impossible. Exactly
 * one account can be created without an existing session, and only while both
 * of these hold:
 *
 *   1. the user table is empty, and
 *   2. the request carries the `VAULT_SETUP_TOKEN` Worker secret.
 *
 * The endpoint lives inside Better Auth rather than in a TanStack server
 * function because creating the owner's session cookie needs a Better Auth
 * endpoint context (`setSessionCookie`). After it returns, the browser holds a
 * normal session and registers the owner's passkey through the ordinary
 * `/passkey/generate-register-options` flow, which keeps `requireSession` at
 * its secure default.
 *
 * Once an owner exists this endpoint answers 404 for everyone, forever.
 */

export const SETUP_ENDPOINT_PATH = "/vault-setup/claim-owner";

const claimOwnerBody = z.object({
  setupToken: z.string().min(1).max(512),
  name: z.string().min(1).max(128),
  email: z.email().max(254),
});

export function vaultSetup(): BetterAuthPlugin {
  return {
    id: "vault-setup",
    endpoints: {
      claimOwner: createAuthEndpoint(
        SETUP_ENDPOINT_PATH,
        { method: "POST", body: claimOwnerBody },
        async (ctx) => {
          const existingUsers = await ctx.context.internalAdapter.listUsers(1);
          if (existingUsers.length > 0) {
            // Indistinguishable from "no such route" on purpose.
            throw new APIError("NOT_FOUND");
          }

          // An unconfigured secret answers exactly like a wrong token, so the
          // 404 below never tells a prober how far setup has got.
          if (!setupTokenAccepted(env.VAULT_SETUP_TOKEN, ctx.body.setupToken)) {
            log({
              level: "warn",
              event: "auth.setup.rejected",
              outcome: "denied",
              reason: "bad_setup_token",
            });
            throw new APIError("NOT_FOUND");
          }

          const user = await ctx.context.internalAdapter.createUser(
            {
              name: ctx.body.name,
              email: ctx.body.email,
              emailVerified: false,
              image: null,
              role: "owner",
            },
            { method: "vault-setup" },
          );

          const session = await ctx.context.internalAdapter.createSession(user.id, false);
          await setSessionCookie(ctx, { session, user });

          log({
            level: "warn",
            event: "auth.setup.owner_created",
            userId: user.id,
            role: "owner",
            outcome: "ok",
          });

          return ctx.json({ userId: user.id });
        },
      ),
    },
  };
}
