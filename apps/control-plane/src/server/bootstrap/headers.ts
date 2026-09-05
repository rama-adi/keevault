/**
 * The internal headers that carry an authenticated bootstrap identity from the
 * Worker to the environment's Durable Object.
 *
 * They live in their own module, free of `cloudflare:workers`, so both sides
 * and the tests can agree on the names without pulling in the runtime.
 *
 * The Durable Object trusts these headers only because the sole route to it is
 * the stub the Worker obtains after checking the token. The Worker deletes any
 * header with one of these names from the client's request before setting them.
 */

export const INTERNAL_TOKEN_HEADER = "x-env-vault-token-id";
export const INTERNAL_ENVIRONMENT_HEADER = "x-env-vault-environment-id";
export const INTERNAL_PROJECT_HEADER = "x-env-vault-project-id";
export const INTERNAL_SOURCE_IP_HEADER = "x-env-vault-source-ip";
export const INTERNAL_MAX_PENDING_HEADER = "x-env-vault-max-pending";

/** Every internal header, so the Worker can strip them from client input. */
export const INTERNAL_HEADERS: readonly string[] = [
  INTERNAL_TOKEN_HEADER,
  INTERNAL_ENVIRONMENT_HEADER,
  INTERNAL_PROJECT_HEADER,
  INTERNAL_SOURCE_IP_HEADER,
  INTERNAL_MAX_PENDING_HEADER,
];
