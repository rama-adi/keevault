import { describe, expect, it } from "vite-plus/test";

import {
  canonicalizeManifest,
  canonicalizeManifestNode,
  ed25519PublicKeyFromSeed,
  generateEd25519Seed,
  manifestInteger,
  manifestNode,
  manifestText,
  signManifest,
  signedBuildManifestNode,
  utf8Decode,
  manifestSigningMessage,
  verifyManifest,
  type SignedBuildManifest,
} from "../src/index.ts";

const MANIFEST: SignedBuildManifest = {
  version: 1,
  source: { repository: "github.com/acme/foo", commit: "a".repeat(40) },
  artifact: {
    type: "oci",
    repository: "ghcr.io/acme/foo",
    digest: `sha256:${"b".repeat(64)}`,
  },
  builder: "acme-ci",
  issuedAt: "2026-09-05T10:00:00.000Z",
};

describe("canonicalisation", () => {
  it("sorts keys at every level and emits no whitespace", () => {
    const canonical = canonicalizeManifest(MANIFEST);
    expect(canonical).toBe(
      '{"artifact":{"digest":"sha256:' +
        "b".repeat(64) +
        '","repository":"ghcr.io/acme/foo","type":"oci"},"builder":"acme-ci",' +
        '"issuedAt":"2026-09-05T10:00:00.000Z","source":{"commit":"' +
        "a".repeat(40) +
        '","repository":"github.com/acme/foo"},"version":1}',
    );
    expect(canonical).not.toContain(" ");
    expect(canonical).not.toContain("\n");
  });

  it("does not depend on the order the entries were built in", () => {
    const forward = canonicalizeManifestNode(
      manifestNode([
        { key: "a", value: manifestText("1") },
        { key: "B", value: manifestText("2") },
        { key: "b", value: manifestText("3") },
      ]),
    );
    const backward = canonicalizeManifestNode(
      manifestNode([
        { key: "b", value: manifestText("3") },
        { key: "a", value: manifestText("1") },
        { key: "B", value: manifestText("2") },
      ]),
    );
    expect(forward).toBe(backward);
    expect(forward).toBe('{"B":"2","a":"1","b":"3"}');
  });

  it("rejects an integer other than 1", () => {
    expect(() =>
      canonicalizeManifestNode(manifestNode([{ key: "version", value: manifestInteger(2) }])),
    ).toThrow();
    expect(() => canonicalizeManifest({ ...MANIFEST, version: 2 })).toThrow();
    expect(() =>
      canonicalizeManifestNode(manifestNode([{ key: "version", value: manifestInteger(0) }])),
    ).toThrow();
  });

  it("rejects duplicate keys", () => {
    expect(() =>
      canonicalizeManifestNode(
        manifestNode([
          { key: "builder", value: manifestText("one") },
          { key: "builder", value: manifestText("two") },
        ]),
      ),
    ).toThrow();
  });

  it("escapes strings the way JSON does", () => {
    expect(
      canonicalizeManifestNode(manifestNode([{ key: "b", value: manifestText('a"\n<b>') }])),
    ).toBe('{"b":"a\\"\\n<b>"}');
  });
});

describe("signing", () => {
  it("prefixes the canonical bytes", () => {
    const message = utf8Decode(manifestSigningMessage(signedBuildManifestNode(MANIFEST)));
    expect(message).toBe(`vault:signed-build-manifest:v1\n${canonicalizeManifest(MANIFEST)}`);
  });

  it("round trips a signature", async () => {
    const seed = generateEd25519Seed();
    const publicKey = await ed25519PublicKeyFromSeed(seed);
    const node = signedBuildManifestNode(MANIFEST);
    const signature = await signManifest({ seed, manifest: node });
    expect(await verifyManifest({ publicKey, manifest: node, signature })).toBe(true);
  });

  it("fails for a changed manifest or a foreign signer", async () => {
    const seed = generateEd25519Seed();
    const publicKey = await ed25519PublicKeyFromSeed(seed);
    const node = signedBuildManifestNode(MANIFEST);
    const signature = await signManifest({ seed, manifest: node });
    const changed = signedBuildManifestNode({ ...MANIFEST, builder: "other-ci" });
    expect(await verifyManifest({ publicKey, manifest: changed, signature })).toBe(false);
    const otherKey = await ed25519PublicKeyFromSeed(generateEd25519Seed());
    expect(await verifyManifest({ publicKey: otherKey, manifest: node, signature })).toBe(false);
  });
});
