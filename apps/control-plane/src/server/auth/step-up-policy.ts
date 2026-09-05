/**
 * The step-up freshness rule as a pure function (spec section 22).
 *
 * `guards.ts` reaches Cloudflare bindings through `createAuth`, so the
 * arithmetic that decides whether a passkey verification is recent enough lives
 * here instead, where a test can drive it directly. The rule fails closed: a
 * missing, unreadable or implausible timestamp is treated as infinitely old.
 */

/** How far a stored timestamp may sit in the future before it is rejected. */
export const STEP_UP_CLOCK_SKEW_SECONDS = 60;

/**
 * True when `stepUpAt` is a readable RFC 3339 timestamp no older than
 * `maxAgeSeconds` and no further ahead of `now` than the skew allowance.
 */
export function isRecentStepUp(stepUpAt: string | null, now: Date, maxAgeSeconds: number): boolean {
  if (stepUpAt === null) return false;
  const verifiedAtMillis = Date.parse(stepUpAt);
  const nowMillis = now.getTime();
  if (!Number.isFinite(verifiedAtMillis) || !Number.isFinite(nowMillis)) return false;
  const ageSeconds = (nowMillis - verifiedAtMillis) / 1000;
  if (ageSeconds < -STEP_UP_CLOCK_SKEW_SECONDS) return false;
  return ageSeconds <= maxAgeSeconds;
}
