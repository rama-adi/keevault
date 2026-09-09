import { betterAuth } from "better-auth";
import { env } from "cloudflare:workers";

import { buildAuthOptions } from "./options.ts";
import { sessionStepUpAt } from "./step-up-policy.ts";
import { vaultSetup } from "./setup-plugin.ts";

/**
 * Dashboard authentication (spec sections 21 and 41).
 *
 * Passkey only. Email and password is off, there are no social providers, and
 * public sign-up is impossible: the passkey plugin only registers a credential
 * for an already authenticated user, and the only code path that creates a user
 * is the first-owner ceremony in setup-plugin.ts.
 *
 * Better Auth 1.7.2 accepts a `D1Database` directly as `database` and selects
 * its built-in D1 Kysely dialect, so the separate `kysely-d1` package is not
 * needed.
 */

/**
 * Build the auth instance for the current request.
 *
 * Cloudflare hands bindings to the Worker per request, so the instance cannot
 * be a module-level constant built from process env. `env` from
 * "cloudflare:workers" resolves against the in-flight request, and callers get
 * a fresh instance per call.
 */
export function createAuth() {
  const options = buildAuthOptions(env.AUTH_DB, env.BETTER_AUTH_URL, env.BETTER_AUTH_SECRET);
  return betterAuth({
    ...options,
    databaseHooks: {
      session: {
        create: {
          async before(session, context) {
            return { data: { ...session, stepUpAt: sessionStepUpAt(context?.path, new Date()) } };
          },
        },
      },
    },
    plugins: [...(options.plugins ?? []), vaultSetup()],
  });
}

export type Auth = ReturnType<typeof createAuth>;
