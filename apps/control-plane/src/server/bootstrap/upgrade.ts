import { fromD1, type VaultDatabase } from "@keevault/vault-store";

import {
  INTERNAL_ENVIRONMENT_HEADER,
  INTERNAL_HEADERS,
  INTERNAL_MAX_PENDING_HEADER,
  INTERNAL_PROJECT_HEADER,
  INTERNAL_SOURCE_IP_HEADER,
  INTERNAL_TOKEN_HEADER,
} from "./headers.ts";
import { log } from "../log.ts";
import { authenticateBootstrapRequest } from "../vault/bootstrap-auth.ts";

/** The one machine endpoint (spec section 13). */
export const BOOTSTRAP_PATH = "/bootstrap/v1";

/** True when this request is for the bootstrap endpoint at all. */
export function isBootstrapRequest(url: URL): boolean {
  return url.pathname === BOOTSTRAP_PATH;
}

function isWebSocketUpgrade(request: Request): boolean {
  return (request.headers.get("Upgrade") ?? "").toLowerCase() === "websocket";
}

/**
 * Sends an authenticated upgrade to one environment's Durable Object. The
 * Worker implements it with the binding; a test implements it with a recorder.
 */
export interface EnvironmentSessionRouter {
  fetchEnvironment(environmentId: string, request: Request): Promise<Response>;
}

/**
 * Authenticate a bootstrap upgrade and hand it to the environment's Durable
 * Object.
 *
 * The token never reaches the Durable Object. The authenticated identity is
 * passed on internal headers instead, and those headers are removed from the
 * client's request first, so a client that sends them itself cannot forge an
 * identity. The Durable Object trusts them only because the only way to reach
 * it is through the stub obtained here.
 */
export async function routeBootstrapUpgrade(
  request: Request,
  db: VaultDatabase,
  router: EnvironmentSessionRouter,
): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Use GET with an Upgrade: websocket header.", {
      status: 405,
      headers: { Allow: "GET" },
    });
  }
  if (!isWebSocketUpgrade(request)) {
    return new Response("This endpoint speaks the bootstrap WebSocket protocol v1.", {
      status: 426,
      headers: { Upgrade: "websocket", Connection: "Upgrade" },
    });
  }

  const identity = await authenticateBootstrapRequest(request, db);
  if (!identity.ok) {
    log({
      level: "info",
      event: "bootstrap.upgrade.denied",
      outcome: "denied",
      reason: identity.reason,
      method: request.method,
      path: BOOTSTRAP_PATH,
      status: identity.httpStatus,
    });
    return new Response(identity.message, { status: identity.httpStatus });
  }

  const headers = new Headers(request.headers);
  // Strip anything the client sent that looks like an internal header, then set
  // the values this Worker just proved.
  for (const name of INTERNAL_HEADERS) headers.delete(name);
  headers.delete("Authorization");
  headers.set(INTERNAL_TOKEN_HEADER, identity.tokenId);
  headers.set(INTERNAL_ENVIRONMENT_HEADER, identity.environmentId);
  headers.set(INTERNAL_PROJECT_HEADER, identity.projectId);
  headers.set(INTERNAL_SOURCE_IP_HEADER, identity.sourceIp);
  headers.set(INTERNAL_MAX_PENDING_HEADER, String(identity.maxPendingBoots));

  log({
    level: "info",
    event: "bootstrap.upgrade.accepted",
    outcome: "ok",
    environmentId: identity.environmentId,
    projectId: identity.projectId,
    tokenId: identity.tokenId,
    method: request.method,
    path: BOOTSTRAP_PATH,
    status: 101,
  });

  return await router.fetchEnvironment(
    identity.environmentId,
    new Request(request.url, { method: "GET", headers }),
  );
}

/** The Worker entry point: the same routing over the live bindings. */
export async function handleBootstrapRequest(request: Request, env: Env): Promise<Response> {
  return await routeBootstrapUpgrade(request, fromD1(env.VAULT_DB), {
    fetchEnvironment: async (environmentId: string, forwarded: Request): Promise<Response> =>
      await env.ENVIRONMENT_SESSION.get(env.ENVIRONMENT_SESSION.idFromName(environmentId)).fetch(
        forwarded,
      ),
  });
}
