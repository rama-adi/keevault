import { getRequestHeaders } from "@tanstack/react-start/server";
import { z } from "zod";

import { ROLE_RANK, ROLES, STEP_UP_MAX_AGE_SECONDS, type Role } from "../../lib/roles.ts";
import { log } from "../log.ts";
import { createAuth } from "./auth.ts";

/** Error codes the UI maps to a specific recovery. */
export const AUTH_ERROR_CODES = ["unauthenticated", "forbidden", "step_up_required"] as const;

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number];

/**
 * Thrown by every guard in this file. The route and component layers switch on
 * `code`: "step_up_required" opens the verify-with-your-passkey dialog,
 * "unauthenticated" redirects to /login, "forbidden" renders a refusal.
 */
export class AuthorizationError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string) {
    super(message);
    this.name = "AuthorizationError";
    this.code = code;
  }
}

export function isAuthorizationError(error: Error): error is AuthorizationError {
  return error instanceof AuthorizationError;
}

const roleSchema = z.enum(ROLES).catch("viewer");

const dateFromSession = z.union([
  z.date(),
  z.string().transform((value) => new Date(value)),
  z.number().transform((value) => new Date(value)),
]);

const sessionSchema = z.object({
  user: z.object({
    id: z.string().min(1),
    name: z.string(),
    email: z.string(),
    role: roleSchema,
  }),
  session: z.object({
    id: z.string().min(1),
    stepUpAt: dateFromSession.nullish(),
  }),
});

/** Everything a page or server function needs about the caller. */
export interface VaultSession {
  userId: string;
  name: string;
  email: string;
  role: Role;
  sessionId: string;
  stepUpAt: Date | null;
}

/** Read the session, or null when the caller is not signed in. */
export async function getVaultSession(): Promise<VaultSession | null> {
  const auth = createAuth();
  const raw = await auth.api.getSession({ headers: getRequestHeaders() });
  if (raw === null) {
    return null;
  }
  const parsed = sessionSchema.safeParse(raw);
  if (!parsed.success) {
    log({
      level: "warn",
      event: "auth.session.unparseable",
      outcome: "denied",
      reason: "session_shape",
    });
    return null;
  }
  return {
    userId: parsed.data.user.id,
    name: parsed.data.user.name,
    email: parsed.data.user.email,
    role: parsed.data.user.role,
    sessionId: parsed.data.session.id,
    stepUpAt: parsed.data.session.stepUpAt ?? null,
  };
}

/** Require a signed-in operator. */
export async function requireSession(): Promise<VaultSession> {
  const session = await getVaultSession();
  if (session === null) {
    log({
      level: "info",
      event: "auth.session.required",
      outcome: "denied",
      reason: "unauthenticated",
    });
    throw new AuthorizationError("unauthenticated", "Sign in to continue.");
  }
  return session;
}

function rankOf(role: Role): number {
  return ROLE_RANK.get(role) ?? 0;
}

/** Require at least `minimum` authority. Ranking: viewer < admin < owner. */
export async function requireRole(minimum: Role): Promise<VaultSession> {
  const session = await requireSession();
  if (rankOf(session.role) < rankOf(minimum)) {
    log({
      level: "warn",
      event: "auth.role.denied",
      userId: session.userId,
      role: session.role,
      outcome: "denied",
      reason: `requires_${minimum}`,
    });
    throw new AuthorizationError("forbidden", `This action requires the ${minimum} role.`);
  }
  return session;
}

/**
 * Require a passkey verification newer than `maxAgeSeconds` (spec section 22).
 *
 * The passkey plugin in 1.7.2 exposes no re-verify endpoint: its only assertion
 * endpoint, /passkey/verify-authentication, is a sign-in. Re-authentication is
 * therefore a fresh passkey sign-in performed by the client, which produces a
 * new session row whose `stepUpAt` is stamped at creation
 * (`databaseHooks.session.create.before` in auth.ts). The operator's identity
 * and role live on the user row, so they survive the session swap.
 */
export async function requireRecentPasskey(
  maxAgeSeconds: number = STEP_UP_MAX_AGE_SECONDS,
): Promise<VaultSession> {
  const session = await requireSession();
  const verifiedAt = session.stepUpAt;
  const ageSeconds =
    verifiedAt === null ? Number.POSITIVE_INFINITY : (Date.now() - verifiedAt.getTime()) / 1000;
  if (ageSeconds > maxAgeSeconds) {
    log({
      level: "info",
      event: "auth.step_up.required",
      userId: session.userId,
      role: session.role,
      outcome: "denied",
      reason: "step_up_required",
    });
    throw new AuthorizationError("step_up_required", "Verify with your passkey to continue.");
  }
  return session;
}
