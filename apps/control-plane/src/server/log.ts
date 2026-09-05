/**
 * Redacting log layer (spec section 36).
 *
 * `LogEvent` has a fixed field set on purpose. There is no free-form payload
 * field, so no call site can smuggle a secret value, a token, key material or a
 * WebAuthn response into a log line. Add a named field here when a new event
 * needs one, and only for values that are safe to write down.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogOutcome = "ok" | "denied" | "error";

export interface LogEvent {
  /** Severity. */
  level: LogLevel;
  /** Stable dot-separated event name, for example "auth.session.denied". */
  event: string;
  /** Cloudflare ray id or another per-request correlation id. */
  requestId?: string;
  /** Better Auth user id of the acting operator. */
  userId?: string;
  /** Role the acting operator held at the time. */
  role?: string;
  /** Prefixed ULIDs. Never names or values. */
  projectId?: string;
  environmentId?: string;
  secretId?: string;
  bootId?: string;
  tokenId?: string;
  /** Result of the operation. */
  outcome?: LogOutcome;
  /** Short machine-readable reason, for example "step_up_required". */
  reason?: string;
  /** Wall-clock duration of the operation. */
  durationMs?: number;
  /** HTTP request method and path. Never the query string or the body. */
  method?: string;
  path?: string;
  status?: number;
}

const REDACTED_HEADER_NAMES: ReadonlySet<string> = new Set([
  "authorization",
  "cookie",
  "set-cookie",
]);

export const REDACTED_PLACEHOLDER = "[redacted]";

/**
 * Copy headers with the credential-bearing ones replaced by a placeholder.
 * The header name is kept so the reader can still see that it was present.
 */
export function redactHeaders(headers: Headers): Map<string, string> {
  const redacted = new Map<string, string>();
  headers.forEach((value, name) => {
    const lowered = name.toLowerCase();
    redacted.set(lowered, REDACTED_HEADER_NAMES.has(lowered) ? REDACTED_PLACEHOLDER : value);
  });
  return redacted;
}

/** True when a header name must never have its value written to a log. */
export function isRedactedHeader(name: string): boolean {
  return REDACTED_HEADER_NAMES.has(name.toLowerCase());
}

function serialize(event: LogEvent): string {
  const line = new Map<string, string | number>();
  line.set("level", event.level);
  line.set("event", event.event);
  const optional: ReadonlyArray<readonly [string, string | number | undefined]> = [
    ["requestId", event.requestId],
    ["userId", event.userId],
    ["role", event.role],
    ["projectId", event.projectId],
    ["environmentId", event.environmentId],
    ["secretId", event.secretId],
    ["bootId", event.bootId],
    ["tokenId", event.tokenId],
    ["outcome", event.outcome],
    ["reason", event.reason],
    ["durationMs", event.durationMs],
    ["method", event.method],
    ["path", event.path],
    ["status", event.status],
  ];
  for (const [name, value] of optional) {
    if (value !== undefined) {
      line.set(name, value);
    }
  }
  return JSON.stringify(Object.fromEntries(line));
}

/** Write one structured line. Only fields declared on `LogEvent` are emitted. */
export function log(event: LogEvent): void {
  const line = serialize(event);
  if (event.level === "error") {
    console.error(line);
    return;
  }
  if (event.level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
}

/** Exported for tests. Produces the exact string `log` would write. */
export function formatLogEvent(event: LogEvent): string {
  return serialize(event);
}
