/**
 * Role and session-policy constants (spec sections 21, 22, 41).
 *
 * This module is imported by both browser and Worker code, so it must stay free
 * of Cloudflare bindings and Better Auth imports.
 */

export const ROLES = ["owner", "admin", "viewer"] as const;

export type Role = (typeof ROLES)[number];

/** Higher number means more authority. Used by `requireRole`. */
export const ROLE_RANK: ReadonlyMap<Role, number> = new Map([
  ["viewer", 0],
  ["admin", 1],
  ["owner", 2],
]);

/** Administrative sessions are short (spec section 41). */
export const SESSION_EXPIRY_SECONDS = 60 * 60 * 12;

/** A session older than this is not "fresh" for sensitive Better Auth flows. */
export const SESSION_FRESH_AGE_SECONDS = 60 * 60;

/** Step-up window for approvals and key operations (spec section 22). */
export const STEP_UP_MAX_AGE_SECONDS = 300;
