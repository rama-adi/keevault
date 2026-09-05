import { describe, expect, it } from "vite-plus/test";

import { isRecentStepUp, STEP_UP_CLOCK_SKEW_SECONDS } from "./step-up-policy.ts";

/**
 * Finding 6 in docs/security-review-v1.md. The old guard computed the age of
 * the last passkey assertion with plain arithmetic, so an unreadable timestamp
 * produced NaN and `NaN > 300` granted the step-up. Every case here asserts the
 * refusal direction: anything the function cannot read is infinitely old.
 */

const NOW = new Date("2026-09-05T10:00:00.000Z");
const MAX_AGE_SECONDS = 300;

describe("isRecentStepUp", () => {
  it("accepts a verification inside the window", () => {
    expect(isRecentStepUp("2026-09-05T09:56:00.000Z", NOW, MAX_AGE_SECONDS)).toBe(true);
  });

  it("accepts a verification made at this instant", () => {
    expect(isRecentStepUp(NOW.toISOString(), NOW, MAX_AGE_SECONDS)).toBe(true);
  });

  it("accepts a verification exactly at the limit", () => {
    expect(isRecentStepUp("2026-09-05T09:55:00.000Z", NOW, MAX_AGE_SECONDS)).toBe(true);
  });

  it("refuses a verification one second past the limit", () => {
    expect(isRecentStepUp("2026-09-05T09:54:59.000Z", NOW, MAX_AGE_SECONDS)).toBe(false);
  });

  it("refuses a missing timestamp", () => {
    expect(isRecentStepUp(null, NOW, MAX_AGE_SECONDS)).toBe(false);
  });

  it("refuses an empty timestamp", () => {
    expect(isRecentStepUp("", NOW, MAX_AGE_SECONDS)).toBe(false);
  });

  it("refuses a timestamp the Date constructor cannot read", () => {
    expect(isRecentStepUp("not a date", NOW, MAX_AGE_SECONDS)).toBe(false);
    expect(isRecentStepUp("0000-00-00", NOW, MAX_AGE_SECONDS)).toBe(false);
  });

  it("tolerates a small clock skew into the future", () => {
    const ahead = new Date(NOW.getTime() + (STEP_UP_CLOCK_SKEW_SECONDS - 1) * 1000);
    expect(isRecentStepUp(ahead.toISOString(), NOW, MAX_AGE_SECONDS)).toBe(true);
  });

  it("refuses a timestamp further in the future than the skew allowance", () => {
    const ahead = new Date(NOW.getTime() + (STEP_UP_CLOCK_SKEW_SECONDS + 1) * 1000);
    expect(isRecentStepUp(ahead.toISOString(), NOW, MAX_AGE_SECONDS)).toBe(false);
  });

  it("refuses a timestamp years in the future", () => {
    expect(isRecentStepUp("2099-01-01T00:00:00.000Z", NOW, MAX_AGE_SECONDS)).toBe(false);
  });

  it("refuses everything when the clock itself is unreadable", () => {
    expect(isRecentStepUp(NOW.toISOString(), new Date(Number.NaN), MAX_AGE_SECONDS)).toBe(false);
  });
});
