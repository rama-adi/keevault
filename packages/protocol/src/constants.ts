/** The only protocol version this package understands. */
export const PROTOCOL_VERSION = 1;

/**
 * WebSocket close codes used by /bootstrap/v1. The server closes with one of
 * these after sending the matching terminal frame.
 */
export const CLOSE_CODES = {
  /** The boot finished. The server sends boot.consumed, then closes. */
  NORMAL: 1000,
  /** A frame was not JSON, not a known message type, or failed schema validation. */
  PROTOCOL_ERROR: 4400,
  /** The Authorization header was missing, malformed, or the token did not exist. */
  UNAUTHORIZED: 4401,
  /** The token was revoked or expired, or the client IP failed the CIDR check. */
  FORBIDDEN: 4403,
  /** The bootId in a resume or acknowledgement is unknown to this environment. */
  UNKNOWN_BOOT: 4404,
  /** Too many pending boots for the token, or the requested transition conflicts. */
  CONFLICT: 4409,
  /** The boot reached a terminal state: declined, expired, canceled, or consumed. */
  TERMINAL: 4410,
  /** The client exceeded the rate limit for connections or frames. */
  RATE_LIMITED: 4429,
} as const;

/** Every close code as a union of the numeric literals above. */
export type CloseCode = (typeof CLOSE_CODES)[keyof typeof CLOSE_CODES];

/** All close codes in ascending numeric order. */
export const CLOSE_CODE_VALUES: readonly CloseCode[] = [
  CLOSE_CODES.NORMAL,
  CLOSE_CODES.PROTOCOL_ERROR,
  CLOSE_CODES.UNAUTHORIZED,
  CLOSE_CODES.FORBIDDEN,
  CLOSE_CODES.UNKNOWN_BOOT,
  CLOSE_CODES.CONFLICT,
  CLOSE_CODES.TERMINAL,
  CLOSE_CODES.RATE_LIMITED,
];

/** Close codes a boot.error frame may carry. 1000 is not an error. */
export const ERROR_CLOSE_CODE_VALUES: readonly CloseCode[] = CLOSE_CODE_VALUES.filter(
  (code) => code !== CLOSE_CODES.NORMAL,
);

/** Seconds a PENDING boot waits for an approval decision before it expires. */
export const DEFAULT_PENDING_TTL_SECONDS = 1800;

/** Seconds an APPROVED or DELIVERED payload stays deliverable before it expires. */
export const DEFAULT_PAYLOAD_TTL_SECONDS = 300;

/** Seconds a resume challenge stays valid. Each challenge is single use. */
export const DEFAULT_CHALLENGE_TTL_SECONDS = 30;

/** Concurrent PENDING boots allowed per bootstrap token. */
export const MAX_PENDING_BOOTS_PER_TOKEN = 3;
