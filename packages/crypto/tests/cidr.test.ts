import { describe, expect, it } from "vite-plus/test";

import {
  ipAllowed,
  ipInCidr,
  normalizeIpAddress,
  parseCidr,
  parseIpAddress,
} from "../src/index.ts";

describe("address parsing", () => {
  it("parses IPv4", () => {
    expect(Array.from(parseIpAddress("203.0.113.44") ?? [])).toEqual([203, 0, 113, 44]);
    expect(parseIpAddress("203.0.113")).toBeNull();
    expect(parseIpAddress("203.0.113.256")).toBeNull();
    expect(parseIpAddress("203.0.113.04")).toBeNull();
    expect(parseIpAddress("203.0.113.44.5")).toBeNull();
    expect(parseIpAddress("")).toBeNull();
  });

  it("parses IPv6 including compression and embedded IPv4", () => {
    expect(normalizeIpAddress("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
    expect(normalizeIpAddress("::1")).toBe("::1");
    expect(normalizeIpAddress("::")).toBe("::");
    expect(normalizeIpAddress("::ffff:203.0.113.44")).toBe("203.0.113.44");
    expect(normalizeIpAddress("2001:db8::203.0.113.44")).toBe("2001:db8::cb00:712c");
    expect(parseIpAddress("2001:db8:::1")).toBeNull();
    expect(parseIpAddress("2001:db8::1::2")).toBeNull();
    expect(parseIpAddress("2001:db8:0:0:0:0:0:0:1")).toBeNull();
    expect(parseIpAddress("2001:db8:0:0:0:0:1")).toBeNull();
    expect(parseIpAddress("gggg::1")).toBeNull();
  });
});

describe("cidr parsing", () => {
  it("rejects bad prefixes", () => {
    expect(parseCidr("203.0.113.0")).toBeNull();
    expect(parseCidr("203.0.113.0/33")).toBeNull();
    expect(parseCidr("203.0.113.0/")).toBeNull();
    expect(parseCidr("203.0.113.0/08")).toBeNull();
    expect(parseCidr("2001:db8::/129")).toBeNull();
    expect(parseCidr("2001:db8::/64")?.prefixLength).toBe(64);
  });
});

describe("ipInCidr", () => {
  it("matches IPv4 blocks", () => {
    expect(ipInCidr("203.0.113.44", "203.0.113.44/32")).toBe(true);
    expect(ipInCidr("203.0.113.45", "203.0.113.44/32")).toBe(false);
    expect(ipInCidr("198.51.100.7", "198.51.100.0/24")).toBe(true);
    expect(ipInCidr("198.51.101.7", "198.51.100.0/24")).toBe(false);
    expect(ipInCidr("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(ipInCidr("11.1.2.3", "10.0.0.0/8")).toBe(false);
    expect(ipInCidr("192.0.2.1", "192.0.2.0/31")).toBe(true);
    expect(ipInCidr("192.0.2.2", "192.0.2.0/31")).toBe(false);
    expect(ipInCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
    expect(ipInCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
  });

  it("matches IPv6 blocks", () => {
    expect(ipInCidr("2001:db8::1", "2001:db8::1/128")).toBe(true);
    expect(ipInCidr("2001:db8::2", "2001:db8::1/128")).toBe(false);
    expect(ipInCidr("2001:db8:0:0:1::9", "2001:db8::/32")).toBe(true);
    expect(ipInCidr("2001:db9::1", "2001:db8::/32")).toBe(false);
    expect(ipInCidr("2001:db8:0:1::1", "2001:db8:0:0::/64")).toBe(false);
    expect(ipInCidr("::1", "::/0")).toBe(true);
    expect(ipInCidr("2001:db8::1", "2001:db8::/33")).toBe(true);
    expect(ipInCidr("2001:db8:8000::1", "2001:db8::/33")).toBe(false);
  });

  it("does not match across address families", () => {
    expect(ipInCidr("203.0.113.44", "2001:db8::/32")).toBe(false);
    expect(ipInCidr("2001:db8::1", "0.0.0.0/0")).toBe(false);
    expect(ipInCidr("::ffff:203.0.113.44", "203.0.113.0/24")).toBe(true);
  });

  it("rejects unparseable input rather than matching it", () => {
    expect(ipInCidr("not-an-ip", "0.0.0.0/0")).toBe(false);
    expect(ipInCidr("203.0.113.44", "not-a-cidr")).toBe(false);
  });
});

describe("ipAllowed", () => {
  it("skips the check when no policy exists", () => {
    expect(ipAllowed("203.0.113.44", [])).toBe(true);
  });

  it("accepts a match in any listed block", () => {
    expect(ipAllowed("198.51.100.7", ["203.0.113.44/32", "198.51.100.0/24"])).toBe(true);
    expect(ipAllowed("192.0.2.7", ["203.0.113.44/32", "198.51.100.0/24"])).toBe(false);
  });
});
