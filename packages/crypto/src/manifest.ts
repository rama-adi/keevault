/**
 * Signed build manifest v1: canonical bytes and Ed25519 signatures.
 *
 * Canonical bytes are the JSON serialisation with object keys sorted by UTF-16 code
 * unit order at every level, no whitespace, and values limited to strings and the
 * integer 1. The signed message is `vault:signed-build-manifest:v1\n` followed by the
 * canonical JSON.
 *
 * The manifest tree is modelled as a tagged union rather than a JSON dictionary so
 * that a rejected value is a value the caller can construct and this module can
 * refuse without a runtime type probe.
 */

import { b64uDecode, b64uEncode, utf8Encode, type Bytes } from "./encoding.ts";
import { importEd25519PrivateKey, importEd25519PublicKey, SIGNATURE_LENGTH } from "./keys.ts";

export const MANIFEST_SIGNING_PREFIX = "vault:signed-build-manifest:v1\n";

/** The only integer a manifest may carry. */
export const MANIFEST_VERSION = 1;

export interface ManifestText {
  readonly kind: "text";
  readonly text: string;
}

export interface ManifestInteger {
  readonly kind: "integer";
  readonly integer: number;
}

export interface ManifestNode {
  readonly kind: "node";
  readonly entries: readonly ManifestEntry[];
}

export type ManifestValue = ManifestText | ManifestInteger | ManifestNode;

/** One key and its value inside a manifest node. */
export interface ManifestEntry {
  readonly key: string;
  readonly value: ManifestValue;
}

/** Wrap a string value. */
export function manifestText(text: string): ManifestText {
  return { kind: "text", text };
}

/** Wrap an integer value. Only 1 survives canonicalisation. */
export function manifestInteger(integer: number): ManifestInteger {
  return { kind: "integer", integer };
}

/** Wrap a set of entries. Order here does not matter; canonicalisation sorts them. */
export function manifestNode(entries: readonly ManifestEntry[]): ManifestNode {
  return { kind: "node", entries };
}

/** The v1 manifest as it appears in evidence. */
export interface SignedBuildManifest {
  readonly version: number;
  readonly source: ManifestSource;
  readonly artifact: ManifestArtifact;
  readonly builder: string;
  readonly issuedAt: string;
}

export interface ManifestSource {
  readonly repository: string;
  readonly commit: string;
}

export interface ManifestArtifact {
  readonly type: string;
  readonly repository: string;
  readonly digest: string;
}

/** Convert a typed v1 manifest into the canonicalisable tree. */
export function signedBuildManifestNode(manifest: SignedBuildManifest): ManifestNode {
  return manifestNode([
    { key: "version", value: manifestInteger(manifest.version) },
    {
      key: "source",
      value: manifestNode([
        { key: "repository", value: manifestText(manifest.source.repository) },
        { key: "commit", value: manifestText(manifest.source.commit) },
      ]),
    },
    {
      key: "artifact",
      value: manifestNode([
        { key: "type", value: manifestText(manifest.artifact.type) },
        { key: "repository", value: manifestText(manifest.artifact.repository) },
        { key: "digest", value: manifestText(manifest.artifact.digest) },
      ]),
    },
    { key: "builder", value: manifestText(manifest.builder) },
    { key: "issuedAt", value: manifestText(manifest.issuedAt) },
  ]);
}

function compareKeys(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function canonicalizeValue(value: ManifestValue): string {
  switch (value.kind) {
    case "text":
      return JSON.stringify(value.text);
    case "integer":
      if (value.integer !== MANIFEST_VERSION) {
        throw new Error("manifest values must be strings or the integer 1");
      }
      return String(MANIFEST_VERSION);
    case "node": {
      const seen = new Set<string>();
      for (const entry of value.entries) {
        if (seen.has(entry.key)) {
          throw new Error(`manifest node has a duplicate key: ${entry.key}`);
        }
        seen.add(entry.key);
      }
      const sorted = [...value.entries].sort((left, right) => compareKeys(left.key, right.key));
      const rendered = sorted.map(
        (entry) => `${JSON.stringify(entry.key)}:${canonicalizeValue(entry.value)}`,
      );
      return `{${rendered.join(",")}}`;
    }
  }
}

/** Canonical JSON text for a manifest tree. */
export function canonicalizeManifestNode(node: ManifestNode): string {
  return canonicalizeValue(node);
}

/** Canonical JSON text for a typed v1 manifest. */
export function canonicalizeManifest(manifest: SignedBuildManifest): string {
  return canonicalizeManifestNode(signedBuildManifestNode(manifest));
}

/** The exact bytes that are signed. */
export function manifestSigningMessage(node: ManifestNode): Bytes {
  return utf8Encode(MANIFEST_SIGNING_PREFIX + canonicalizeManifestNode(node));
}

export interface SignManifestInput {
  readonly seed: Bytes;
  readonly manifest: ManifestNode;
}

/** Sign a manifest with an Ed25519 seed. Returns the signature as b64u. */
export async function signManifest(input: SignManifestInput): Promise<string> {
  const privateKey = await importEd25519PrivateKey(input.seed);
  const signature = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    manifestSigningMessage(input.manifest),
  );
  return b64uEncode(new Uint8Array(signature));
}

export interface VerifyManifestInput {
  readonly publicKey: Bytes;
  readonly manifest: ManifestNode;
  readonly signature: string;
}

/** Verify a manifest signature. */
export async function verifyManifest(input: VerifyManifestInput): Promise<boolean> {
  const signature = b64uDecode(input.signature);
  if (signature.length !== SIGNATURE_LENGTH) return false;
  const publicKey = await importEd25519PublicKey(input.publicKey);
  return await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signature,
    manifestSigningMessage(input.manifest),
  );
}
