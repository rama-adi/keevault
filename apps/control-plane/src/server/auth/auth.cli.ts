import { betterAuth } from "better-auth";
import { DatabaseSync } from "node:sqlite";

import { buildAuthOptions } from "./options.ts";

/**
 * Config file for the Better Auth schema generator, not used at runtime.
 *
 * The Worker instance in auth.ts cannot be loaded outside workerd because it
 * reads Cloudflare bindings, so the CLI gets the same options pointed at an
 * in-memory SQLite database. D1 speaks SQLite, so the generated DDL matches.
 *
 * Regenerate migrations/auth with:
 *   pnpm dlx auth@latest generate \
 *     --config src/server/auth/auth.cli.ts \
 *     --output ../../migrations/auth/0001_better_auth.sql
 */
export const auth = betterAuth(
  buildAuthOptions(
    new DatabaseSync(":memory:"),
    "http://localhost:5173",
    "generate-only-not-a-real-secret-value-000",
  ),
);
