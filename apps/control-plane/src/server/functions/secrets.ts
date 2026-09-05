/**
 * Secret server functions (spec section 23).
 *
 * Reads return metadata only. There is no server function anywhere that returns
 * a secret value, so no dashboard route can reveal one.
 */

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireRole, requireSession } from "../auth/guards.ts";
import { vaultContextForSession } from "../vault/runtime.ts";
import {
  deleteSecret,
  importDotenv,
  listSecretsMetadata,
  putSecret,
  type ImportDotenvResult,
  type SecretSummary,
} from "../vault/service.ts";
import { environmentIdSchema, secretNameSchema, secretValueSchema } from "../vault/validation.ts";
import { guarded } from "./guarded.ts";

export const listSecretsFn = createServerFn({ method: "GET" })
  .validator(z.object({ environmentId: environmentIdSchema }))
  .handler(
    async ({ data }): Promise<SecretSummary[]> =>
      await guarded(async () => {
        const session = await requireSession();
        return await listSecretsMetadata(vaultContextForSession(session), data.environmentId);
      }),
  );

export const putSecretFn = createServerFn({ method: "POST" })
  .validator(
    z.object({
      environmentId: environmentIdSchema,
      name: secretNameSchema,
      value: secretValueSchema,
    }),
  )
  .handler(
    async ({ data }): Promise<SecretSummary> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        const result = await putSecret(vaultContextForSession(session), data);
        return result.secret;
      }),
  );

export const deleteSecretFn = createServerFn({ method: "POST" })
  .validator(z.object({ environmentId: environmentIdSchema, name: secretNameSchema }))
  .handler(
    async ({ data }): Promise<{ deleted: true }> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await deleteSecret(vaultContextForSession(session), data);
        return { deleted: true };
      }),
  );

/** The pasted file is at most 1 MiB, which is far more than any real .env. */
const dotenvContentSchema = z
  .string()
  .min(1)
  .max(1024 * 1024);

export const importDotenvFn = createServerFn({ method: "POST" })
  .validator(z.object({ environmentId: environmentIdSchema, content: dotenvContentSchema }))
  .handler(
    async ({ data }): Promise<ImportDotenvResult> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        return await importDotenv(vaultContextForSession(session), data);
      }),
  );
