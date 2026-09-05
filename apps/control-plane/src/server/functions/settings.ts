/**
 * Settings server functions.
 *
 * The administrator list and the master key panel are read-only views over the
 * auth database and the Worker secrets. Changing a role needs owner plus a
 * recent passkey verification (spec sections 21 and 22).
 */

import { createServerFn } from "@tanstack/react-start";
import { env } from "cloudflare:workers";
import { z } from "zod";

import { ROLES, type Role } from "../../lib/roles.ts";
import { requireRecentPasskey, requireRole, requireSession } from "../auth/guards.ts";
import { activeMasterKeyVersion, masterKeyVersionsPresent } from "../vault/runtime.ts";
import { VaultInputError } from "../vault/validation.ts";
import { guarded } from "./guarded.ts";

export interface AdministratorView {
  id: string;
  name: string;
  email: string;
  role: Role;
  createdAt: string;
}

export interface SettingsView {
  /** Role of the operator looking at the page. */
  viewerRole: Role;
  viewerId: string;
  administrators: AdministratorView[];
  masterKeyVersions: number[];
  activeMasterKeyVersion: number;
}

const administratorRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string(),
  role: z.enum(ROLES).catch("viewer"),
  createdAt: z.union([z.string(), z.number()]).transform((value) => new Date(value).toISOString()),
});

async function readAdministrators(): Promise<AdministratorView[]> {
  const result = await env.AUTH_DB.prepare(
    `SELECT id, name, email, role, createdAt FROM "user" ORDER BY createdAt, id`,
  ).all();
  return result.results.map((row) => administratorRowSchema.parse(row));
}

export const loadSettingsFn = createServerFn({ method: "GET" }).handler(
  async (): Promise<SettingsView> =>
    await guarded(async () => {
      const session = await requireSession();
      return {
        viewerRole: session.role,
        viewerId: session.userId,
        administrators: await readAdministrators(),
        masterKeyVersions: masterKeyVersionsPresent(),
        activeMasterKeyVersion: activeMasterKeyVersion(),
      };
    }),
);

/**
 * Change one operator's role.
 *
 * This is the whole of administrator management in V1. Inviting a new operator
 * is not possible: Better Auth 1.7.2 can create a user row, but the only way to
 * attach a passkey is `/passkey/generate-register-options`, which requires an
 * authenticated session, and the only sign-in method is a passkey. An invited
 * account would therefore have no way to reach its first credential.
 */
export const setAdministratorRoleFn = createServerFn({ method: "POST" })
  .validator(z.object({ userId: z.string().min(1).max(128), role: z.enum(ROLES) }))
  .handler(
    async ({ data }): Promise<{ updated: true }> =>
      await guarded(async () => {
        const session = await requireRole("owner");
        await requireRecentPasskey();
        if (data.userId === session.userId) {
          throw new VaultInputError("userId", "An owner cannot change their own role.");
        }
        await env.AUTH_DB.prepare(`UPDATE "user" SET role = ?, updatedAt = ? WHERE id = ?`)
          .bind(data.role, new Date().toISOString(), data.userId)
          .run();
        return { updated: true };
      }),
  );
