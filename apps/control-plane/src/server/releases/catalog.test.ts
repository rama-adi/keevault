import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { fromNodeSqlite } from "@keevault/vault-store";
import { afterEach, expect, test } from "vite-plus/test";

import { compareVersions, handleBinaryRequest, type ReleaseEnv } from "./catalog.ts";

const databases: DatabaseSync[] = [];
afterEach(() => {
  for (const db of databases.splice(0)) db.close();
});
function environment(): ReleaseEnv {
  const sqlite = new DatabaseSync(":memory:");
  databases.push(sqlite);
  sqlite.exec(
    readFileSync(
      new URL("../../../../../migrations/vault/0002_binary_releases.sql", import.meta.url),
      "utf8",
    ),
  );
  return { VAULT_DB: fromNodeSqlite(sqlite), KEEVAULT_RELEASE_KEY: "release-secret" };
}
function publication(version = "v1.0.0", hash = "a".repeat(64)): string {
  return JSON.stringify({
    version,
    binaries: ["amd64", "arm64"].map((arch) => ({
      arch,
      hash,
      url: `https://github.com/rama-adi/keevault/releases/download/${version}/keevault-linux-${arch}`,
    })),
  });
}
function post(body: string, key = "release-secret"): Request {
  return new Request("https://vault.example/binary.json", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}` },
    body,
  });
}
function get(): Request {
  return new Request("https://vault.example/binary.json");
}

test("rejects missing configuration and bad credentials without writing", async () => {
  const env = environment();
  expect((await handleBinaryRequest(post(publication(), "wrong"), env)).status).toBe(401);
  delete env.KEEVAULT_RELEASE_KEY;
  expect((await handleBinaryRequest(post(publication(), ""), env)).status).toBe(401);
  expect(await (await handleBinaryRequest(get(), env)).json()).toEqual({
    latest: null,
    binaries: [],
  });
});

test("publishes both assets, preserves IDs on retries, and selects highest version", async () => {
  const env = environment();
  const first = await (await handleBinaryRequest(post(publication("v1.10.0")), env)).json();
  expect(await (await handleBinaryRequest(post(publication("v1.10.0")), env)).json()).toEqual(
    first,
  );
  await handleBinaryRequest(post(publication("v1.9.0")), env);
  const response = await handleBinaryRequest(get(), env);
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  expect(await response.json()).toMatchObject({ latest: "v1.10.0", binaries: expect.any(Array) });
  expect(
    await env.VAULT_DB.prepare("SELECT COUNT(*) AS count FROM binary_releases").first(),
  ).toEqual({ count: 4 });
});

test("conflicting publication rolls back the entire transaction", async () => {
  const env = environment();
  await handleBinaryRequest(post(publication()), env);
  await env.VAULT_DB.prepare("DELETE FROM binary_releases WHERE arch = 'amd64'").run();
  expect((await handleBinaryRequest(post(publication("v1.0.0", "b".repeat(64))), env)).status).toBe(
    409,
  );
  expect(await env.VAULT_DB.prepare("SELECT arch, hash FROM binary_releases").all()).toMatchObject({
    results: [{ arch: "arm64", hash: "a".repeat(64) }],
  });
});

test("rejects incomplete, malformed, oversized and mismatched releases", async () => {
  const env = environment();
  for (const body of [
    "{",
    JSON.stringify({ version: "v1.0.0", binaries: [] }),
    publication("v01.0.0"),
    publication("v1.0.0-01"),
    publication().replace('"arm64"', '"amd64"'),
    publication().replace("github.com", "evil.example"),
    publication().replace('"arch":"amd64"', '"arch":"x86"'),
  ]) {
    expect((await handleBinaryRequest(post(body), env)).status).toBe(400);
  }
  expect((await handleBinaryRequest(post("x".repeat(4097)), env)).status).toBe(413);
  expect(
    (
      await handleBinaryRequest(
        new Request("https://vault.example/binary.json", { method: "DELETE" }),
        env,
      )
    ).status,
  ).toBe(405);
  expect(await (await handleBinaryRequest(get(), env)).json()).toEqual({
    latest: null,
    binaries: [],
  });
});

test("SemVer handles stable, prerelease, numeric identifiers and large versions", () => {
  const ordered = [
    "v1.0.0-alpha",
    "v1.0.0-alpha.1",
    "v1.0.0-alpha.2",
    "v1.0.0-alpha.10",
    "v1.0.0-beta",
    "v1.0.0-rc.1",
    "v1.0.0",
    "v1.9.0",
    "v1.10.0",
    "v999999999999999999999.0.0",
  ];
  expect([...ordered].reverse().sort(compareVersions)).toEqual(ordered);
  expect(compareVersions("v1.0.0", "v1.0.0")).toBe(0);
  expect(compareVersions("v1.0.0-rc.1", "v1.0.0-rc.1")).toBe(0);
});
