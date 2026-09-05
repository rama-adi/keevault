/**
 * Bootstrap token and trusted signer server functions.
 *
 * `createBootstrapTokenFn` is the only function in the app that returns a
 * plaintext credential, and it returns it exactly once: nothing stores it and
 * no later read can produce it again.
 */

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireRecentPasskey, requireRole, requireSession } from "../auth/guards.ts";
import { vaultContextForSession } from "../vault/runtime.ts";
import {
  addTrustedSigner,
  createBootstrapToken,
  listBootstrapTokens,
  listTrustedSigners,
  revokeBootstrapToken,
  revokeTrustedSigner,
  updateTokenCidrs,
  type BootstrapTokenSummary,
  type CreatedBootstrapToken,
  type TrustedSignerSummary,
} from "../vault/service.ts";
import {
  cidrListSchema,
  displayNameSchema,
  environmentIdSchema,
  maxPendingBootsSchema,
  publicKeyB64uSchema,
  rfc3339Schema,
  signerIdSchema,
  tokenIdSchema,
} from "../vault/validation.ts";
import { guarded } from "./guarded.ts";

export const listBootstrapTokensFn = createServerFn({ method: "GET" })
  .validator(z.object({ environmentId: environmentIdSchema }))
  .handler(
    async ({ data }): Promise<BootstrapTokenSummary[]> =>
      await guarded(async () => {
        const session = await requireSession();
        return await listBootstrapTokens(vaultContextForSession(session), data.environmentId);
      }),
  );

export const createBootstrapTokenFn = createServerFn({ method: "POST" })
  .validator(
    z.object({
      environmentId: environmentIdSchema,
      label: displayNameSchema,
      allowedCidrs: cidrListSchema,
      expiresAt: rfc3339Schema.nullable(),
      maxPendingBoots: maxPendingBootsSchema,
    }),
  )
  .handler(
    async ({ data }): Promise<CreatedBootstrapToken> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        return await createBootstrapToken(vaultContextForSession(session), data);
      }),
  );

export const revokeBootstrapTokenFn = createServerFn({ method: "POST" })
  .validator(z.object({ tokenId: tokenIdSchema }))
  .handler(
    async ({ data }): Promise<{ revoked: true }> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await revokeBootstrapToken(vaultContextForSession(session), data.tokenId);
        return { revoked: true };
      }),
  );

export const updateTokenCidrsFn = createServerFn({ method: "POST" })
  .validator(z.object({ tokenId: tokenIdSchema, allowedCidrs: cidrListSchema }))
  .handler(
    async ({ data }): Promise<BootstrapTokenSummary> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        return await updateTokenCidrs(vaultContextForSession(session), {
          tokenRowId: data.tokenId,
          allowedCidrs: data.allowedCidrs,
        });
      }),
  );

export const listTrustedSignersFn = createServerFn({ method: "GET" })
  .validator(z.object({ environmentId: environmentIdSchema }))
  .handler(
    async ({ data }): Promise<TrustedSignerSummary[]> =>
      await guarded(async () => {
        const session = await requireSession();
        return await listTrustedSigners(vaultContextForSession(session), data.environmentId);
      }),
  );

export const addTrustedSignerFn = createServerFn({ method: "POST" })
  .validator(
    z.object({
      environmentId: environmentIdSchema,
      label: displayNameSchema,
      publicKey: publicKeyB64uSchema,
      projectWide: z.boolean(),
    }),
  )
  .handler(
    async ({ data }): Promise<TrustedSignerSummary> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        return await addTrustedSigner(vaultContextForSession(session), data);
      }),
  );

export const revokeTrustedSignerFn = createServerFn({ method: "POST" })
  .validator(z.object({ environmentId: environmentIdSchema, signerId: signerIdSchema }))
  .handler(
    async ({ data }): Promise<{ revoked: true }> =>
      await guarded(async () => {
        const session = await requireRole("admin");
        await requireRecentPasskey();
        await revokeTrustedSigner(vaultContextForSession(session), data);
        return { revoked: true };
      }),
  );
