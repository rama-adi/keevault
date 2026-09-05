import { describe, expect, it } from "vite-plus/test";

import { formatLogEvent, isRedactedHeader, redactHeaders, REDACTED_PLACEHOLDER } from "./log.ts";

describe("redactHeaders", () => {
  it("replaces the value of every credential-bearing header", () => {
    const headers = new Headers();
    headers.set("authorization", "Bearer vlt_boot_01ARZ3NDEKTSV4RRFFQ69G5FAV.x");
    headers.set("cookie", "better-auth.session_token=abc");
    headers.set("set-cookie", "better-auth.session_token=abc; HttpOnly");

    const redacted = redactHeaders(headers);

    expect(redacted.get("authorization")).toBe(REDACTED_PLACEHOLDER);
    expect(redacted.get("cookie")).toBe(REDACTED_PLACEHOLDER);
    expect(redacted.get("set-cookie")).toBe(REDACTED_PLACEHOLDER);
  });

  it("redacts regardless of header name casing", () => {
    const headers = new Headers();
    headers.set("Authorization", "Bearer token");
    headers.set("Cookie", "session=1");

    const redacted = redactHeaders(headers);

    expect(redacted.get("authorization")).toBe(REDACTED_PLACEHOLDER);
    expect(redacted.get("cookie")).toBe(REDACTED_PLACEHOLDER);
  });

  it("keeps the header name so the reader knows it was present", () => {
    const headers = new Headers();
    headers.set("authorization", "Bearer token");

    expect([...redactHeaders(headers).keys()]).toContain("authorization");
  });

  it("passes other headers through unchanged", () => {
    const headers = new Headers();
    headers.set("content-type", "application/json");
    headers.set("cf-connecting-ip", "203.0.113.7");

    const redacted = redactHeaders(headers);

    expect(redacted.get("content-type")).toBe("application/json");
    expect(redacted.get("cf-connecting-ip")).toBe("203.0.113.7");
  });

  it("never leaks a redacted value into the returned map", () => {
    const headers = new Headers();
    headers.set("authorization", "Bearer super-secret-value");

    const serialized = JSON.stringify([...redactHeaders(headers)]);

    expect(serialized).not.toContain("super-secret-value");
  });

  it("returns an empty map for headers with nothing in them", () => {
    expect(redactHeaders(new Headers()).size).toBe(0);
  });
});

describe("isRedactedHeader", () => {
  it("reports the blacklisted names", () => {
    expect(isRedactedHeader("Authorization")).toBe(true);
    expect(isRedactedHeader("COOKIE")).toBe(true);
    expect(isRedactedHeader("set-cookie")).toBe(true);
  });

  it("reports other names as safe", () => {
    expect(isRedactedHeader("content-type")).toBe(false);
    expect(isRedactedHeader("cf-ray")).toBe(false);
  });
});

describe("formatLogEvent", () => {
  it("emits only the fields that were set", () => {
    const line = formatLogEvent({
      level: "info",
      event: "auth.session.granted",
      userId: "user_1",
    });

    expect(line).toBe('{"level":"info","event":"auth.session.granted","userId":"user_1"}');
  });

  it("keeps level and event first so lines stay greppable", () => {
    const line = formatLogEvent({
      level: "warn",
      event: "auth.step_up.required",
      outcome: "denied",
      reason: "step_up_required",
    });

    expect(line.startsWith('{"level":"warn","event":"auth.step_up.required"')).toBe(true);
  });

  it("drops undefined optional fields rather than writing nulls", () => {
    const line = formatLogEvent({ level: "info", event: "boot.created" });

    expect(line).toBe('{"level":"info","event":"boot.created"}');
  });
});
