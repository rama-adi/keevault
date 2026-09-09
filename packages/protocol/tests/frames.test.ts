import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, test } from "vite-plus/test";
import { z } from "zod";

import { parseClientFrame, parseServerFrame } from "../src/parse.ts";
import { WorkloadClaims } from "../src/messages.ts";

const VectorFile = z.strictObject({
  description: z.string().min(1),
  vectors: z
    .array(
      z.strictObject({
        name: z.string().min(1),
        direction: z.enum(["client", "server"]),
        valid: z.boolean(),
        reason: z.string().min(1).optional(),
        frame: z.string(),
      }),
    )
    .min(1),
});

const vectorPath = fileURLToPath(
  new URL("../../../protocol/test-vectors/frames.json", import.meta.url),
);
const vectors = VectorFile.parse(JSON.parse(readFileSync(vectorPath, "utf8"))).vectors;

function parse(direction: "client" | "server", frame: string): boolean {
  return direction === "client" ? parseClientFrame(frame).ok : parseServerFrame(frame).ok;
}

test("every vector file entry is exercised", () => {
  expect(vectors.filter((vector) => vector.valid).length).toBeGreaterThanOrEqual(13);
  expect(vectors.filter((vector) => !vector.valid).length).toBeGreaterThanOrEqual(10);
});

test("valid frames parse", () => {
  for (const vector of vectors) {
    if (!vector.valid) continue;
    expect(parse(vector.direction, vector.frame), vector.name).toBe(true);
  }
});

test("invalid frames are rejected with a reason and no exception", () => {
  for (const vector of vectors) {
    if (vector.valid) continue;
    expect(vector.reason, vector.name).toBeDefined();
    expect(parse(vector.direction, vector.frame), vector.name).toBe(false);
  }
});

test("every message type has at least one valid vector", () => {
  const seen = new Set(
    vectors
      .filter((vector) => vector.valid)
      .map((vector) => {
        const result =
          vector.direction === "client"
            ? parseClientFrame(vector.frame)
            : parseServerFrame(vector.frame);
        return result.ok ? result.message.type : "unparsed";
      }),
  );
  expect([...seen].sort()).toEqual([
    "boot.approved",
    "boot.canceled",
    "boot.challenge",
    "boot.challenge-response",
    "boot.consumed",
    "boot.declined",
    "boot.error",
    "boot.expired",
    "boot.hello",
    "boot.pending",
    "boot.received",
    "boot.resume",
    "boot.resumed",
  ]);
});

test("a rejected frame returns an error string", () => {
  const result = parseClientFrame("{}");
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error.length).toBeGreaterThan(0);
});

test("a non-JSON frame is rejected instead of throwing", () => {
  expect(parseClientFrame("not json").ok).toBe(false);
  expect(parseServerFrame("").ok).toBe(false);
});

test("unknown evidence is kept as sent", () => {
  const vector = vectors.find((entry) => entry.name.includes("unknown evidence"));
  expect(vector).toBeDefined();
  if (vector === undefined) return;
  const result = parseClientFrame(vector.frame);
  expect(result.ok).toBe(true);
  if (!result.ok || result.message.type !== "boot.hello") return;
  const evidence = result.message.evidence[0];
  expect(evidence).toBeDefined();
  expect(evidence?.type).toBe("zeabur-metadata-v9");
});

test("client reports are optional and bounded, with only lowercase SHA-256 digests", () => {
  const client = { version: "v1.2.3", os: "linux", arch: "arm64", sha256: "a".repeat(64) };
  expect(WorkloadClaims.parse({ client }).client).toEqual(client);
  expect(WorkloadClaims.parse({})).toEqual({});
  expect(
    WorkloadClaims.parse({ client: { version: "dev", os: "linux", arch: "amd64" } }).client?.sha256,
  ).toBeUndefined();
  for (const invalid of [
    { ...client, version: "x".repeat(65) },
    { ...client, version: "v1.0.0\nforged" },
    { ...client, os: "" },
    { ...client, arch: "x".repeat(33) },
    { ...client, sha256: "A".repeat(64) },
    { ...client, sha256: "a".repeat(63) },
    { ...client, verified: true },
  ]) {
    expect(WorkloadClaims.safeParse({ client: invalid }).success).toBe(false);
  }
});
