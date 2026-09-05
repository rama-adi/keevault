/**
 * IPv4 and IPv6 address parsing and CIDR matching with no dependencies.
 *
 * Used for the bootstrap-token allowed-CIDR check against `CF-Connecting-IP`.
 * An IPv4-mapped IPv6 address (`::ffff:203.0.113.44`) is reduced to its IPv4 form so
 * that it matches an IPv4 CIDR.
 */

import type { Bytes } from "./encoding.ts";

const IPV4_BYTES = 4;
const IPV6_BYTES = 16;

const IPV4_MAPPED_MARKER = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);

function parseDecimalOctet(text: string): number | null {
  if (text.length === 0 || text.length > 3) return null;
  if (text.length > 1 && text.startsWith("0")) return null;
  let value = 0;
  for (const character of text) {
    const digit = "0123456789".indexOf(character);
    if (digit < 0) return null;
    value = value * 10 + digit;
  }
  return value > 255 ? null : value;
}

function parseHexGroup(text: string): number | null {
  if (text.length === 0 || text.length > 4) return null;
  let value = 0;
  for (const character of text) {
    const digit = "0123456789abcdef".indexOf(character.toLowerCase());
    if (digit < 0) return null;
    value = value * 16 + digit;
  }
  return value;
}

/** Parse dotted-quad IPv4 into 4 bytes. Returns null when the text is not an IPv4 address. */
export function parseIpv4(text: string): Bytes | null {
  const parts = text.split(".");
  if (parts.length !== IPV4_BYTES) return null;
  const out = new Uint8Array(IPV4_BYTES);
  for (let index = 0; index < IPV4_BYTES; index += 1) {
    const octet = parseDecimalOctet(parts[index] ?? "");
    if (octet === null) return null;
    out[index] = octet;
  }
  return out;
}

function writeGroups(groups: readonly number[], out: Bytes, offset: number): void {
  let position = offset;
  for (const group of groups) {
    out[position] = (group >> 8) & 0xff;
    out[position + 1] = group & 0xff;
    position += 2;
  }
}

/** Parse an IPv6 address into 16 bytes, including the trailing-IPv4 form. */
export function parseIpv6(text: string): Bytes | null {
  if (text.includes(":::")) return null;
  const compressionIndex = text.indexOf("::");
  if (compressionIndex !== text.lastIndexOf("::")) return null;

  const head: number[] = [];
  const tail: number[] = [];
  let trailingIpv4: Bytes | null = null;

  const readSection = (section: string, target: number[]): boolean => {
    if (section.length === 0) return true;
    const pieces = section.split(":");
    for (let index = 0; index < pieces.length; index += 1) {
      const piece = pieces[index] ?? "";
      if (piece.includes(".")) {
        if (index !== pieces.length - 1) return false;
        const embedded = parseIpv4(piece);
        if (embedded === null) return false;
        trailingIpv4 = embedded;
        continue;
      }
      const group = parseHexGroup(piece);
      if (group === null) return false;
      target.push(group);
    }
    return true;
  };

  if (compressionIndex < 0) {
    if (!readSection(text, head)) return null;
    const expected = trailingIpv4 === null ? 8 : 6;
    if (head.length !== expected) return null;
    const out = new Uint8Array(IPV6_BYTES);
    writeGroups(head, out, 0);
    if (trailingIpv4 !== null) out.set(trailingIpv4, 12);
    return out;
  }

  const headText = text.slice(0, compressionIndex);
  const tailText = text.slice(compressionIndex + 2);
  if (!readSection(headText, head)) return null;
  if (!readSection(tailText, tail)) return null;
  const tailBytes = tail.length * 2 + (trailingIpv4 === null ? 0 : IPV4_BYTES);
  const headBytes = head.length * 2;
  if (headBytes + tailBytes > IPV6_BYTES - 2) return null;
  const out = new Uint8Array(IPV6_BYTES);
  writeGroups(head, out, 0);
  const tailOffset = IPV6_BYTES - tailBytes;
  writeGroups(tail, out, tailOffset);
  if (trailingIpv4 !== null) out.set(trailingIpv4, IPV6_BYTES - IPV4_BYTES);
  return out;
}

function isIpv4Mapped(bytes: Bytes): boolean {
  if (bytes.length !== IPV6_BYTES) return false;
  for (let index = 0; index < IPV4_MAPPED_MARKER.length; index += 1) {
    if (bytes[index] !== IPV4_MAPPED_MARKER[index]) return false;
  }
  return true;
}

/**
 * Parse an IPv4 or IPv6 address into its bytes.
 *
 * IPv4-mapped IPv6 addresses come back as 4 bytes.
 */
export function parseIpAddress(text: string): Bytes | null {
  if (text.includes(":")) {
    const bytes = parseIpv6(text);
    if (bytes === null) return null;
    return isIpv4Mapped(bytes) ? bytes.slice(12) : bytes;
  }
  return parseIpv4(text);
}

function formatIpv4(bytes: Bytes): string {
  return Array.from(bytes, (byte) => String(byte)).join(".");
}

function formatIpv6(bytes: Bytes): string {
  const groups: number[] = [];
  for (let index = 0; index < IPV6_BYTES; index += 2) {
    groups.push(((bytes[index] ?? 0) << 8) | (bytes[index + 1] ?? 0));
  }
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index += 1) {
    const isZero = index < groups.length && groups[index] === 0;
    if (isZero && runStart < 0) runStart = index;
    if (!isZero && runStart >= 0) {
      const runLength = index - runStart;
      if (runLength > bestLength) {
        bestLength = runLength;
        bestStart = runStart;
      }
      runStart = -1;
    }
  }
  const rendered = groups.map((group) => group.toString(16));
  if (bestLength < 2) return rendered.join(":");
  const head = rendered.slice(0, bestStart).join(":");
  const tail = rendered.slice(bestStart + bestLength).join(":");
  return `${head}::${tail}`;
}

/** Render an address in its canonical text form, or null when it does not parse. */
export function normalizeIpAddress(text: string): string | null {
  const bytes = parseIpAddress(text);
  if (bytes === null) return null;
  return bytes.length === IPV4_BYTES ? formatIpv4(bytes) : formatIpv6(bytes);
}

/** An address and the number of leading bits that a candidate must match. */
export interface ParsedCidr {
  readonly address: Bytes;
  readonly prefixLength: number;
}

/** Parse `address/prefix`. Returns null on a bad address, a bad prefix or a missing slash. */
export function parseCidr(text: string): ParsedCidr | null {
  const slash = text.lastIndexOf("/");
  if (slash < 0) return null;
  const address = parseIpAddress(text.slice(0, slash));
  if (address === null) return null;
  const prefixText = text.slice(slash + 1);
  if (prefixText.length === 0 || prefixText.length > 3) return null;
  if (prefixText.length > 1 && prefixText.startsWith("0")) return null;
  let prefixLength = 0;
  for (const character of prefixText) {
    const digit = "0123456789".indexOf(character);
    if (digit < 0) return null;
    prefixLength = prefixLength * 10 + digit;
  }
  if (prefixLength > address.length * 8) return null;
  return { address, prefixLength };
}

function bytesInPrefix(candidate: Bytes, network: ParsedCidr): boolean {
  const fullBytes = Math.floor(network.prefixLength / 8);
  const spareBits = network.prefixLength % 8;
  for (let index = 0; index < fullBytes; index += 1) {
    if (candidate[index] !== network.address[index]) return false;
  }
  if (spareBits === 0) return true;
  const mask = (0xff << (8 - spareBits)) & 0xff;
  return ((candidate[fullBytes] ?? 0) & mask) === ((network.address[fullBytes] ?? 0) & mask);
}

/** Return whether an address falls inside a CIDR block. Mismatched families never match. */
export function ipInCidr(ip: string, cidr: string): boolean {
  const candidate = parseIpAddress(ip);
  const network = parseCidr(cidr);
  if (candidate === null || network === null) return false;
  if (candidate.length !== network.address.length) return false;
  return bytesInPrefix(candidate, network);
}

/** Apply a token's allowed-CIDR policy. An empty list means the check is skipped. */
export function ipAllowed(ip: string, allowedCidrs: readonly string[]): boolean {
  if (allowedCidrs.length === 0) return true;
  return allowedCidrs.some((cidr) => ipInCidr(ip, cidr));
}
