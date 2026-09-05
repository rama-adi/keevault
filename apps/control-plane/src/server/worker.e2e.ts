/**
 * Worker entry used by the end-to-end harness only.
 *
 * A passkey assertion cannot be produced headlessly, so the harness needs a
 * way to seed a vault and approve a boot without a browser. That path must
 * never exist in a shipped bundle, so it lives in this module instead of the
 * normal entry: `vite.config.ts` selects it only when `VAULT_E2E=1` is set at
 * dev or build time, and `vp run control-plane#e2e:absent` proves the normal
 * build does not contain it.
 *
 * The routes are additionally gated on a shared secret from `.dev.vars`, so a
 * dev server started with `VAULT_E2E=1` is still not open to anything on the
 * machine that can reach the port.
 */

import { fromD1, getBootRequest } from "@env-vault/vault-store";
import { z } from "zod";

import worker from "./worker.ts";
import { summaryDigest } from "./provenance/index.ts";
import type { BootActionResult, BootView } from "./durable-objects/boot-session-core.ts";
import { systemClock, type VaultContext } from "./vault/context.ts";
import { loadMasterKeys } from "./vault/keys.ts";
import { workerBootSessionControl } from "./vault/runtime.ts";
import {
  createBootstrapToken,
  createEnvironment,
  createProject,
  putSecret,
  revokeBootstrapToken,
} from "./vault/service.ts";

// Durable Object classes must be named exports of the Worker entry module.
export { EnvironmentSessionDO } from "./durable-objects/environment-session.ts";

/** Prefix every harness route shares. */
const E2E_PREFIX = "/__e2e/";

/** Header carrying the shared secret from `.dev.vars`. */
const E2E_SECRET_HEADER = "x-vault-e2e-secret";

const secretEnvSchema = z.object({ VAULT_E2E_SECRET: z.string().min(16) });

const bootIdSchema = z.string().regex(/^boot_[0-9A-HJKMNP-TV-Z]{26}$/);
const environmentIdSchema = z.string().regex(/^env_[0-9A-HJKMNP-TV-Z]{26}$/);
const tokenIdSchema = z.string().regex(/^tok_[0-9A-HJKMNP-TV-Z]{26}$/);

/** What the harness gets back from a seed. The token is shown here only. */
interface SeedResponse {
  projectId: string;
  environmentId: string;
  tokenId: string;
  token: string;
  secrets: Array<{ name: string; length: number }>;
}

interface ActionResponse {
  ok: boolean;
  status: string | null;
  reason: string | null;
  message: string | null;
}

function json(status: number, body: SeedResponse | ActionResponse | BootView[]): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function problem(status: number, message: string): Response {
  return new Response(message, { status, headers: { "content-type": "text/plain" } });
}

function contextFor(env: Env): VaultContext {
  return {
    db: fromD1(env.VAULT_DB),
    keyring: loadMasterKeys(env),
    actor: { type: "system", id: null },
    now: systemClock,
    boots: workerBootSessionControl,
  };
}

function stubFor(env: Env, environmentId: string) {
  return env.ENVIRONMENT_SESSION.get(env.ENVIRONMENT_SESSION.idFromName(environmentId));
}

function outcome(result: BootActionResult): ActionResponse {
  if (result.ok) return { ok: true, status: result.status, reason: null, message: null };
  return { ok: false, status: null, reason: result.reason, message: result.message };
}

/** A slug that is unique per seed, so repeated runs do not collide. */
function uniqueSlug(prefix: string): string {
  const stamp = Date.now().toString(36);
  const random = Math.floor(Math.random() * 0xffffff).toString(36);
  return `${prefix}-${stamp}-${random}`;
}

/** A value nobody has ever seen. Only its length leaves this process. */
function randomValue(bytes: number): string {
  const raw = new Uint8Array(bytes);
  crypto.getRandomValues(raw);
  return [...raw].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

const SEED_SECRET_NAMES = ["APP_DB_URL", "APP_API_KEY"] as const;

async function seed(env: Env): Promise<Response> {
  const context = contextFor(env);
  const project = await createProject(context, {
    slug: uniqueSlug("e2e"),
    name: "End to end",
  });
  const environment = await createEnvironment(context, {
    projectId: project.id,
    slug: "production",
    name: "Production",
  });
  const secrets: Array<{ name: string; length: number }> = [];
  for (const [index, name] of SEED_SECRET_NAMES.entries()) {
    const value = randomValue(16 + index * 4);
    await putSecret(context, { environmentId: environment.id, name, value });
    secrets.push({ name, length: value.length });
  }
  const token = await createBootstrapToken(context, {
    environmentId: environment.id,
    label: "e2e",
    allowedCidrs: [],
    expiresAt: null,
    maxPendingBoots: 3,
  });
  return json(200, {
    projectId: project.id,
    environmentId: environment.id,
    tokenId: token.summary.id,
    token: token.token,
    secrets,
  });
}

/** Find the environment a boot belongs to, the way the dashboard does. */
async function environmentOf(env: Env, bootId: string): Promise<string | null> {
  const row = await getBootRequest(fromD1(env.VAULT_DB), bootId);
  return row === null ? null : row.environmentId;
}

async function approve(env: Env, bootId: string): Promise<Response> {
  const environmentId = await environmentOf(env, bootId);
  if (environmentId === null) return problem(404, "no such boot");
  const view = await stubFor(env, environmentId).get(bootId);
  if (view === null) return problem(404, "no such boot");
  return json(
    200,
    outcome(
      await stubFor(env, environmentId).approve({
        bootId,
        approverUserId: "e2e",
        approverCredentialId: "e2e",
        evidenceDigest: await summaryDigest(view.provenance),
      }),
    ),
  );
}

async function decline(env: Env, bootId: string): Promise<Response> {
  const environmentId = await environmentOf(env, bootId);
  if (environmentId === null) return problem(404, "no such boot");
  return json(
    200,
    outcome(
      await stubFor(env, environmentId).decline({
        bootId,
        approverUserId: "e2e",
        reason: "declined by the harness",
      }),
    ),
  );
}

async function revoke(env: Env, tokenId: string): Promise<Response> {
  await revokeBootstrapToken(contextFor(env), tokenId);
  return json(200, { ok: true, status: null, reason: null, message: null });
}

async function listLive(env: Env, environmentId: string): Promise<Response> {
  return json(200, await stubFor(env, environmentId).listLive());
}

/** One boot, live or terminal, so the harness can report every transition. */
async function readBoot(env: Env, bootId: string): Promise<Response> {
  const environmentId = await environmentOf(env, bootId);
  if (environmentId === null) return problem(404, "no such boot");
  const view = await stubFor(env, environmentId).get(bootId);
  return view === null ? problem(404, "no such boot") : json(200, [view]);
}

async function route(request: Request, env: Env, url: URL): Promise<Response> {
  const secret = secretEnvSchema.safeParse(env);
  if (!secret.success) return problem(503, "VAULT_E2E_SECRET is not configured");
  if (request.headers.get(E2E_SECRET_HEADER) !== secret.data.VAULT_E2E_SECRET) {
    return problem(403, "bad harness secret");
  }

  const rest = url.pathname.slice(E2E_PREFIX.length);
  const [action, argument] = rest.split("/");
  if (action === "seed" && request.method === "POST") return await seed(env);
  if (action === "approve" && request.method === "POST") {
    const bootId = bootIdSchema.safeParse(argument);
    return bootId.success ? await approve(env, bootId.data) : problem(400, "bad boot id");
  }
  if (action === "decline" && request.method === "POST") {
    const bootId = bootIdSchema.safeParse(argument);
    return bootId.success ? await decline(env, bootId.data) : problem(400, "bad boot id");
  }
  if (action === "revoke" && request.method === "POST") {
    const tokenId = tokenIdSchema.safeParse(argument);
    return tokenId.success ? await revoke(env, tokenId.data) : problem(400, "bad token id");
  }
  if (action === "boot" && request.method === "GET") {
    const bootId = bootIdSchema.safeParse(argument);
    return bootId.success ? await readBoot(env, bootId.data) : problem(400, "bad boot id");
  }
  if (action === "boots" && request.method === "GET") {
    const environmentId = environmentIdSchema.safeParse(argument);
    return environmentId.success
      ? await listLive(env, environmentId.data)
      : problem(400, "bad environment id");
  }
  return problem(404, "no such harness route");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith(E2E_PREFIX)) {
      return await route(request, env, url);
    }
    return await worker.fetch(request, env);
  },
};
