import { passkey } from "@better-auth/passkey";
import type { BetterAuthOptions } from "better-auth";

import { SESSION_EXPIRY_SECONDS, SESSION_FRESH_AGE_SECONDS } from "../../lib/roles.ts";

/**
 * Better Auth options shared by the Worker instance (auth.ts) and the schema
 * generator config (auth.cli.ts).
 *
 * This module must not import "cloudflare:workers", because the Better Auth CLI
 * loads it in plain Node to generate migrations/auth/*.sql.
 *
 * Policy (spec sections 21 and 41): passkey only, no email and password, no
 * social providers, secure httpOnly SameSite=Strict cookies, short sessions.
 */

function relyingPartyId(baseUrl: string): string {
  return new URL(baseUrl).hostname;
}

export function buildAuthOptions(
  database: BetterAuthOptions["database"],
  baseUrl: string,
  secret: string,
): BetterAuthOptions {
  const secureCookies = baseUrl.startsWith("https://");
  return {
    appName: "keevault",
    baseURL: baseUrl,
    secret,
    database,
    trustedOrigins: [baseUrl],
    // Do not enable authentication methods we do not need.
    emailAndPassword: { enabled: false, disableSignUp: true },
    socialProviders: {},
    session: {
      expiresIn: SESSION_EXPIRY_SECONDS,
      freshAge: SESSION_FRESH_AGE_SECONDS,
      additionalFields: {
        // Timestamp of the passkey assertion that produced this session.
        // Written by `databaseHooks.session.create.before`; read by
        // `requireRecentPasskey` in guards.ts.
        stepUpAt: {
          type: "date",
          required: false,
          input: false,
        },
      },
    },
    user: {
      additionalFields: {
        role: {
          type: ["owner", "admin", "viewer"],
          required: false,
          defaultValue: "viewer",
          // Never settable from a request body. Roles are assigned server side.
          input: false,
        },
      },
      changeEmail: { enabled: false },
      deleteUser: { enabled: false },
    },
    advanced: {
      useSecureCookies: secureCookies,
      defaultCookieAttributes: {
        httpOnly: true,
        sameSite: "strict",
        secure: secureCookies,
        path: "/",
      },
    },
    plugins: [
      passkey({
        rpID: relyingPartyId(baseUrl),
        rpName: "keevault",
        origin: baseUrl,
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
      }),
    ],
  };
}
