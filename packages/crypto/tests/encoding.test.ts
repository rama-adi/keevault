import { describe, expect, it } from "vite-plus/test";

import {
  b64uDecode,
  b64uEncode,
  constantTimeEqual,
  constantTimeEqualText,
  hexDecode,
  hexEncode,
  utf8Decode,
  utf8Encode,
} from "../src/index.ts";

describe("b64u", () => {
  it("round trips every length up to 64 bytes", () => {
    for (let length = 0; length <= 64; length += 1) {
      const bytes = new Uint8Array(length);
      for (let index = 0; index < length; index += 1) bytes[index] = (index * 7 + 3) & 0xff;
      const text = b64uEncode(bytes);
      expect(text).not.toContain("=");
      expect(text).not.toContain("+");
      expect(text).not.toContain("/");
      expect(Array.from(b64uDecode(text))).toEqual(Array.from(bytes));
    }
  });

  it("matches known values", () => {
    expect(b64uEncode(utf8Encode("hello"))).toBe("aGVsbG8");
    expect(utf8Decode(b64uDecode("aGVsbG8"))).toBe("hello");
    expect(b64uEncode(new Uint8Array([0xff, 0xef, 0xfe]))).toBe("_-_-");
  });

  it("rejects padding and foreign characters", () => {
    expect(() => b64uDecode("aGVsbG8=")).toThrow();
    expect(() => b64uDecode("aGVs bG8")).toThrow();
    expect(() => b64uDecode("a")).toThrow();
  });
});

describe("hex", () => {
  it("round trips and rejects bad input", () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xa0, 0xff]);
    expect(hexEncode(bytes)).toBe("000fa0ff");
    expect(Array.from(hexDecode("000FA0FF"))).toEqual(Array.from(bytes));
    expect(() => hexDecode("abc")).toThrow();
    expect(() => hexDecode("zz")).toThrow();
  });
});

describe("constant time comparison", () => {
  it("compares content, not identity", () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(constantTimeEqualText("abc", "abc")).toBe(true);
    expect(constantTimeEqualText("abc", "abd")).toBe(false);
  });
});
