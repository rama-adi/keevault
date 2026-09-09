import { CLOSE_CODES, type CloseCode } from "@keevault/protocol";
import { ipAllowed, parseBootstrapToken, verifyTokenSecret } from "@keevault/crypto";
import {
  getBootstrapTokenByTokenId,
  getEnvironment,
  touchBootstrapTokenLastSeen,
} from "@keevault/vault-store";
import type { VaultDatabase } from "@keevault/vault-store";
import { z } from "zod";

/**
 * Bootstrap token authentication for `GET /bootstrap/v1` (spec section 13,
 * phase 3).
 *
 * Nothing in this module logs or returns the presented token, the stored hash,
 * or any part of either. Rejections carry a short reason code and the close
 * code the caller must use.
 */

/** Why a bootstrap request was refused. */
export const BOOTSTRAP_REJECTION_REASONS = [
  "missing_token",
  "query_token",
  "malformed_token",
  "unknown_token",
  "bad_secret",
  "revoked",
  "expired",
  "cidr",
  "unknown_environment",
] as const;

export type BootstrapRejectionReason = (typeof BOOTSTRAP_REJECTION_REASONS)[number];

/** The authenticated caller. The client never names the environment; the token does. */
export interface BootstrapIdentity {
  readonly ok: true;
  /** The `tok_`-prefixed D1 row id. */
  readonly tokenId: string;
  readonly environmentId: string;
  readonly projectId: string;
  /** The value of CF-Connecting-IP, or the empty string when the header is absent. */
  readonly sourceIp: string;
  /** Concurrent PENDING boots this token may hold. */
  readonly maxPendingBoots: number;
}

/** A refusal, with both the pre-upgrade HTTP status and the post-upgrade close code. */
export interface BootstrapRejection {
  readonly ok: false;
  readonly reason: BootstrapRejectionReason;
  readonly closeCode: CloseCode;
  readonly httpStatus: number;
  /** Safe to return to the client and to log. Never contains token material. */
  readonly message: string;
}

export type BootstrapAuthResult = BootstrapIdentity | BootstrapRejection;

const allowedCidrsSchema = z.array(z.string());

const jsonText = z.string().transform((text, context) => {
  try {
    return JSON.parse(text);
  } catch {
    context.addIssue({ code: "custom", message: "allowed_cidrs_json is not valid JSON" });
    return z.NEVER;
  }
});

/** Before the upgrade completes a refusal is an HTTP status, after it a close code. */
function httpStatusFor(closeCode: CloseCode): number {
  if (closeCode === CLOSE_CODES.UNAUTHORIZED) return 401;
  if (closeCode === CLOSE_CODES.FORBIDDEN) return 403;
  if (closeCode === CLOSE_CODES.RATE_LIMITED) return 429;
  return 400;
}

function reject(
  reason: BootstrapRejectionReason,
  closeCode: CloseCode,
  message: string,
): BootstrapRejection {
  return { ok: false, reason, closeCode, httpStatus: httpStatusFor(closeCode), message };
}

function readAllowedCidrs(allowedCidrsJson: string): string[] | null {
  const parsed = jsonText.pipe(allowedCidrsSchema).safeParse(allowedCidrsJson);
  return parsed.success ? parsed.data : null;
}

/**
 * Authenticate one bootstrap request.
 *
 * Order matters: the query string is refused before anything is parsed, so a
 * token that leaked into a URL is never even hashed. The CIDR policy is checked
 * against `CF-Connecting-IP` only. `X-Forwarded-For` is client controlled and
 * is never read here.
 */
export async function authenticateBootstrapRequest(
  request: Request,
  db: VaultDatabase,
): Promise<BootstrapAuthResult> {
  const url = new URL(request.url);
  if (url.searchParams.has("token")) {
    return reject(
      "query_token",
      CLOSE_CODES.UNAUTHORIZED,
      "Send the bootstrap token in the Authorization header, never in the query string.",
    );
  }

  const header = request.headers.get("Authorization");
  if (header === null || !header.startsWith("Bearer ")) {
    return reject("missing_token", CLOSE_CODES.UNAUTHORIZED, "Missing bootstrap token.");
  }
  const presented = parseBootstrapToken(header.slice("Bearer ".length));
  if (presented === null) {
    return reject("malformed_token", CLOSE_CODES.UNAUTHORIZED, "Malformed bootstrap token.");
  }

  const token = await getBootstrapTokenByTokenId(db, presented.tokenId);
  if (token === null) {
    return reject("unknown_token", CLOSE_CODES.UNAUTHORIZED, "Unknown bootstrap token.");
  }
  if (!(await verifyTokenSecret(presented.secret, token.tokenHash))) {
    return reject("bad_secret", CLOSE_CODES.UNAUTHORIZED, "Unknown bootstrap token.");
  }

  const now = new Date();
  if (token.revokedAt !== null) {
    return reject("revoked", CLOSE_CODES.FORBIDDEN, "This bootstrap token was revoked.");
  }
  const expiresAt = token.expiresAt;
  if (expiresAt !== null && Date.parse(expiresAt) <= now.getTime()) {
    return reject("expired", CLOSE_CODES.FORBIDDEN, "This bootstrap token has expired.");
  }

  const sourceIp = request.headers.get("CF-Connecting-IP") ?? "";
  const allowedCidrs = readAllowedCidrs(token.allowedCidrsJson);
  if (allowedCidrs === null || !ipAllowed(sourceIp, allowedCidrs)) {
    return reject(
      "cidr",
      CLOSE_CODES.FORBIDDEN,
      "This source address is outside the token's allowed range.",
    );
  }

  const environment = await getEnvironment(db, token.environmentId);
  if (environment === null) {
    return reject(
      "unknown_environment",
      CLOSE_CODES.FORBIDDEN,
      "The environment for this token no longer exists.",
    );
  }

  await touchBootstrapTokenLastSeen(db, {
    tokenRowId: token.id,
    now: now.toISOString(),
  });

  return {
    ok: true,
    tokenId: token.id,
    environmentId: environment.id,
    projectId: environment.projectId,
    sourceIp,
    maxPendingBoots: token.maxPendingBoots,
  };
}
