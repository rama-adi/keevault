import { describe, expect, it } from "vite-plus/test";

import {
  b64uDecode,
  buildResumeMessage,
  ed25519PublicKeyFromSeed,
  formatFingerprint,
  generateBootstrapToken,
  generateEd25519Seed,
  generatePrefixedUlid,
  generateResumeChallenge,
  generateUlid,
  hashTokenSecret,
  hexDecode,
  isPrefixedUlid,
  isUlid,
  keyFingerprint,
  parseBootstrapToken,
  signResume,
  verifyResume,
  verifyTokenSecret,
} from "../src/index.ts";

const BOOT_ID = "boot_01K4M4X31X2Z5G9C7Q8D3E6F4G";

describe("resume proof", () => {
  it("builds the canonical message", () => {
    expect(buildResumeMessage(BOOT_ID, "Y2hhbGxlbmdl")).toBe(
      `vault-resume:v1\n${BOOT_ID}\nY2hhbGxlbmdl`,
    );
  });

  it("verifies a signature over the right boot id and challenge", async () => {
    const seed = generateEd25519Seed();
    const publicKey = await ed25519PublicKeyFromSeed(seed);
    const challenge = generateResumeChallenge();
    expect(b64uDecode(challenge).length).toBe(32);
    const signature = await signResume({ seed, bootId: BOOT_ID, challenge });
    expect(b64uDecode(signature).length).toBe(64);
    expect(await verifyResume({ publicKey, bootId: BOOT_ID, challenge, signature })).toBe(true);
  });

  it("fails over a wrong boot id", async () => {
    const seed = generateEd25519Seed();
    const publicKey = await ed25519PublicKeyFromSeed(seed);
    const challenge = generateResumeChallenge();
    const signature = await signResume({ seed, bootId: BOOT_ID, challenge });
    expect(
      await verifyResume({
        publicKey,
        bootId: "boot_01K4M4X31X2Z5G9C7Q8D3E6F4H",
        challenge,
        signature,
      }),
    ).toBe(false);
  });

  it("fails over a wrong challenge or a foreign key", async () => {
    const seed = generateEd25519Seed();
    const publicKey = await ed25519PublicKeyFromSeed(seed);
    const challenge = generateResumeChallenge();
    const signature = await signResume({ seed, bootId: BOOT_ID, challenge });
    expect(
      await verifyResume({
        publicKey,
        bootId: BOOT_ID,
        challenge: generateResumeChallenge(),
        signature,
      }),
    ).toBe(false);
    const otherKey = await ed25519PublicKeyFromSeed(generateEd25519Seed());
    expect(await verifyResume({ publicKey: otherKey, bootId: BOOT_ID, challenge, signature })).toBe(
      false,
    );
  });

  it("rejects a signature of the wrong length", async () => {
    const publicKey = await ed25519PublicKeyFromSeed(generateEd25519Seed());
    expect(
      await verifyResume({ publicKey, bootId: BOOT_ID, challenge: "abc", signature: "AAAA" }),
    ).toBe(false);
  });
});

describe("bootstrap token", () => {
  it("mints a token that parses back to its id and secret", async () => {
    const minted = await generateBootstrapToken();
    expect(minted.token.startsWith("vlt_boot_")).toBe(true);
    const parsed = parseBootstrapToken(minted.token);
    expect(parsed).not.toBeNull();
    expect(parsed?.tokenId).toBe(minted.tokenId);
    expect(parsed?.secret.length).toBe(43);
    expect(minted.secretHash.length).toBe(64);
    expect(await hashTokenSecret(parsed?.secret ?? "")).toBe(minted.secretHash);
    expect(await verifyTokenSecret(parsed?.secret ?? "", minted.secretHash)).toBe(true);
    expect(await verifyTokenSecret("not-the-secret", minted.secretHash)).toBe(false);
  });

  it("rejects malformed tokens", () => {
    expect(parseBootstrapToken("")).toBeNull();
    expect(parseBootstrapToken("vlt_boot_")).toBeNull();
    expect(parseBootstrapToken("Bearer vlt_boot_01K4M4X34A5C8K2F0T1G6H9J7K.abc")).toBeNull();
  });

  it("hashes the secret string, not its decoded bytes", async () => {
    expect(await hashTokenSecret("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("fingerprint", () => {
  it("hashes the raw key", async () => {
    const fingerprint = await keyFingerprint(hexDecode("00".repeat(32)));
    expect(fingerprint).toBe("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925");
    expect(formatFingerprint("00ff11")).toBe("00:ff:11");
  });
});

describe("ulid", () => {
  it("produces 26 uppercase Crockford characters", () => {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const value = generateUlid();
      expect(value.length).toBe(26);
      expect(isUlid(value)).toBe(true);
    }
  });

  it("does not repeat", () => {
    const seen = new Set<string>();
    for (let attempt = 0; attempt < 500; attempt += 1) seen.add(generateUlid());
    expect(seen.size).toBe(500);
  });

  it("prefixes identifiers", () => {
    const bootIdentifier = generatePrefixedUlid("boot");
    expect(bootIdentifier.startsWith("boot_")).toBe(true);
    expect(isPrefixedUlid("boot", bootIdentifier)).toBe(true);
    expect(isPrefixedUlid("env", bootIdentifier)).toBe(false);
    expect(isUlid("01K4M4X34A5C8K2F0T1G6H9J7I")).toBe(false);
  });
});
