import { describe, expect, it } from "vite-plus/test";

import { constantTimeEquals, setupTokenAccepted } from "./setup-token.ts";

/**
 * Finding 7 in docs/security-review-v1.md. The setup endpoint read
 * `env.VAULT_SETUP_TOKEN.length` directly, so an unconfigured Worker secret
 * threw a TypeError and answered 500 where every other refusal answers 404.
 * A prober could tell the two vaults apart. The comparison now lives here and
 * answers false for both.
 */

describe("setupTokenAccepted", () => {
  it("accepts the configured token", () => {
    expect(setupTokenAccepted("s3tup-token", "s3tup-token")).toBe(true);
  });

  it("refuses a wrong token", () => {
    expect(setupTokenAccepted("s3tup-token", "guess")).toBe(false);
  });

  it("refuses when the secret is not configured at all", () => {
    expect(setupTokenAccepted(undefined, "s3tup-token")).toBe(false);
  });

  it("refuses when the secret is configured empty", () => {
    expect(setupTokenAccepted("", "")).toBe(false);
    expect(setupTokenAccepted("", "anything")).toBe(false);
  });

  it("refuses a prefix of the configured token", () => {
    expect(setupTokenAccepted("s3tup-token", "s3tup")).toBe(false);
  });
});

describe("constantTimeEquals", () => {
  it("compares equal strings as equal", () => {
    expect(constantTimeEquals("abc", "abc")).toBe(true);
  });

  it("separates strings of different lengths", () => {
    expect(constantTimeEquals("abc", "abcd")).toBe(false);
  });

  it("separates strings that differ in the last byte", () => {
    expect(constantTimeEquals("abc", "abd")).toBe(false);
  });

  it("compares multi-byte characters by their UTF-8 bytes", () => {
    expect(constantTimeEquals("é", "é")).toBe(true);
    expect(constantTimeEquals("é", "e")).toBe(false);
  });
});
