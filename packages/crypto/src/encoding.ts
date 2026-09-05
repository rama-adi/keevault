/**
 * Byte and text encodings shared by the TypeScript and Go implementations.
 *
 * Every binary field on the wire is base64url without padding (RFC 4648 section 5).
 * Every hash shown to a human is lowercase hex.
 */

const B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX_ALPHABET = "0123456789abcdef";

const B64U_VALUES = new Map<string, number>(
  Array.from(B64U_ALPHABET, (character, index) => [character, index]),
);
const HEX_VALUES = new Map<string, number>(
  Array.from("0123456789abcdefABCDEF", (character) => [character, Number.parseInt(character, 16)]),
);

/**
 * A byte string backed by a plain ArrayBuffer.
 *
 * Web Crypto's BufferSource only accepts ArrayBuffer-backed views, so every public
 * byte value in this package is pinned to that buffer kind.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

/** Encode text as UTF-8 bytes. */
export function utf8Encode(text: string): Bytes {
  return textEncoder.encode(text);
}

/** Decode UTF-8 bytes, throwing on invalid sequences. */
export function utf8Decode(bytes: Bytes): string {
  return textDecoder.decode(bytes);
}

/** Encode bytes as base64url without padding. */
export function b64uEncode(bytes: Bytes): string {
  let out = "";
  let index = 0;
  while (index + 3 <= bytes.length) {
    const a = bytes[index] ?? 0;
    const b = bytes[index + 1] ?? 0;
    const c = bytes[index + 2] ?? 0;
    out += B64U_ALPHABET[a >> 2];
    out += B64U_ALPHABET[((a & 0x03) << 4) | (b >> 4)];
    out += B64U_ALPHABET[((b & 0x0f) << 2) | (c >> 6)];
    out += B64U_ALPHABET[c & 0x3f];
    index += 3;
  }
  const remaining = bytes.length - index;
  if (remaining === 1) {
    const a = bytes[index] ?? 0;
    out += B64U_ALPHABET[a >> 2];
    out += B64U_ALPHABET[(a & 0x03) << 4];
  } else if (remaining === 2) {
    const a = bytes[index] ?? 0;
    const b = bytes[index + 1] ?? 0;
    out += B64U_ALPHABET[a >> 2];
    out += B64U_ALPHABET[((a & 0x03) << 4) | (b >> 4)];
    out += B64U_ALPHABET[(b & 0x0f) << 2];
  }
  return out;
}

/** Decode base64url without padding. Throws on padding, whitespace or foreign characters. */
export function b64uDecode(text: string): Bytes {
  if (text.length % 4 === 1) {
    throw new Error("b64u: invalid length");
  }
  const fullGroups = Math.floor(text.length / 4);
  const tailLength = text.length - fullGroups * 4;
  const tailBytes = tailLength === 0 ? 0 : tailLength - 1;
  const out = new Uint8Array(fullGroups * 3 + tailBytes);

  let outIndex = 0;
  let accumulator = 0;
  let bitsHeld = 0;
  for (const character of text) {
    const value = B64U_VALUES.get(character);
    if (value === undefined) {
      throw new Error("b64u: invalid character");
    }
    accumulator = (accumulator << 6) | value;
    bitsHeld += 6;
    if (bitsHeld >= 8) {
      bitsHeld -= 8;
      out[outIndex] = (accumulator >> bitsHeld) & 0xff;
      outIndex += 1;
    }
  }
  if (bitsHeld > 0 && (accumulator & ((1 << bitsHeld) - 1)) !== 0) {
    throw new Error("b64u: non-canonical trailing bits");
  }
  return out;
}

/** Encode bytes as lowercase hex. */
export function hexEncode(bytes: Bytes): string {
  let out = "";
  for (const byte of bytes) {
    out += HEX_ALPHABET[byte >> 4];
    out += HEX_ALPHABET[byte & 0x0f];
  }
  return out;
}

/** Decode hex, accepting either case. Throws on odd length or foreign characters. */
export function hexDecode(text: string): Bytes {
  if (text.length % 2 !== 0) {
    throw new Error("hex: odd length");
  }
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    const high = HEX_VALUES.get(text.charAt(index * 2));
    const low = HEX_VALUES.get(text.charAt(index * 2 + 1));
    if (high === undefined || low === undefined) {
      throw new Error("hex: invalid character");
    }
    out[index] = (high << 4) | low;
  }
  return out;
}

/** Compare byte strings without an early exit on the first differing byte. */
export function constantTimeEqual(left: Bytes, right: Bytes): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

/** Compare two hex or base64url strings without an early exit on the first difference. */
export function constantTimeEqualText(left: string, right: string): boolean {
  return constantTimeEqual(utf8Encode(left), utf8Encode(right));
}

/** Fill a new buffer from the platform CSPRNG. */
export function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Concatenate byte strings into one new buffer. */
export function concatBytes(parts: readonly Bytes[]): Bytes {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
