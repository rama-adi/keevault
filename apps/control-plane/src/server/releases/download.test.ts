import { createHash } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
  mkdirSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fromNodeSqlite } from "@keevault/vault-store";
import { afterEach, expect, test } from "vite-plus/test";

import { handleDownloadRequest } from "./download.ts";
import type { ReleaseEnv } from "./catalog.ts";

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0)) cleanup();
});
const payload = "test binary contents\n";
const digest = createHash("sha256").update(payload).digest("hex");

async function fixture(populated = true) {
  const sqlite = new DatabaseSync(":memory:");
  cleanups.push(() => sqlite.close());
  sqlite.exec(
    readFileSync(
      new URL("../../../../../migrations/vault/0002_binary_releases.sql", import.meta.url),
      "utf8",
    ),
  );
  if (populated) {
    for (const version of ["v1.9.0", "v1.10.0"]) {
      for (const arch of ["amd64", "arm64"]) {
        sqlite
          .prepare("INSERT INTO binary_releases VALUES (?, ?, ?, ?, ?, ?)")
          .run(
            `${version}-${arch}`,
            version,
            arch,
            digest,
            "2026-09-10T00:00:00Z",
            `https://github.com/rama-adi/keevault/releases/download/${version}/keevault-linux-${arch}`,
          );
      }
    }
  }
  const env: ReleaseEnv = { VAULT_DB: fromNodeSqlite(sqlite) };
  const response = await handleDownloadRequest(
    new Request("https://vault.example/download.sh"),
    env,
  );
  const dir = mkdtempSync(join(tmpdir(), "keevault-download-test-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, "bin");
  mkdirSync(bin);
  writeFileSync(join(dir, "download.sh"), await response.text());
  writeFileSync(
    join(bin, "uname"),
    '#!/bin/sh\ncase "$1" in -s) echo "${TEST_OS:-Linux}";; -m) echo "${TEST_ARCH:-x86_64}";; esac\n',
    { mode: 0o755 },
  );
  writeFileSync(
    join(bin, "curl"),
    `#!/bin/sh
[ "\${TEST_CURL_FAIL:-0}" = 0 ] || exit 22
for argument do
  case "$argument" in https://*) printf '%s' "$argument" > requested-url;; esac
  output=$argument
done
printf '%s\\n' 'test binary contents' > "$output"
[ "\${TEST_CORRUPT:-0}" = 0 ] || printf '%s' 'corrupt' >> "$output"
`,
    { mode: 0o755 },
  );
  function run(version = "", arch = "x86_64", corrupt = "0", os = "Linux", fail = "0") {
    return spawnSync("/bin/sh", ["download.sh"], {
      cwd: dir,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:/usr/bin:/bin`,
        KEEVAULT_VER: version,
        TEST_ARCH: arch,
        TEST_CORRUPT: corrupt,
        TEST_OS: os,
        TEST_CURL_FAIL: fail,
      },
    });
  }
  return { dir, run, env, response };
}

test("serves an uncached shell script and handles HTTP methods", async () => {
  const { response, env } = await fixture();
  expect(response.headers.get("Content-Type")).toContain("text/x-shellscript");
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  const head = await handleDownloadRequest(
    new Request("https://vault.example/download.sh", { method: "HEAD" }),
    env,
  );
  expect(await head.text()).toBe("");
  expect(
    (
      await handleDownloadRequest(
        new Request("https://vault.example/download.sh", { method: "POST" }),
        env,
      )
    ).status,
  ).toBe(405);
});

test("downloads latest amd64 and an explicitly selected arm64 release, then verifies and installs", async () => {
  const { dir, run } = await fixture();
  expect(run().status).toBe(0);
  expect(readFileSync(join(dir, "requested-url"), "utf8")).toContain(
    "/v1.10.0/keevault-linux-amd64",
  );
  expect(readFileSync(join(dir, "keevault"), "utf8")).toBe(payload);
  expect(statSync(join(dir, "keevault")).mode & 0o777).toBe(0o755);
  expect(run("v1.9.0", "aarch64").status).toBe(0);
  expect(readFileSync(join(dir, "requested-url"), "utf8")).toContain(
    "/v1.9.0/keevault-linux-arm64",
  );
  expect(run("latest", "arm64").status).toBe(0);
  expect(readFileSync(join(dir, "requested-url"), "utf8")).toContain(
    "/v1.10.0/keevault-linux-arm64",
  );
  expect(readdirSync(dir).some((name) => name.startsWith(".keevault-download."))).toBe(false);
});

test("checksum and HTTP failures preserve an existing binary and remove temporary downloads", async () => {
  const { dir, run } = await fixture();
  writeFileSync(join(dir, "keevault"), "original");
  const corrupt = run("", "x86_64", "1");
  expect(corrupt.status).not.toBe(0);
  expect(corrupt.stderr).toContain("SHA-256 mismatch");
  expect(run("", "x86_64", "0", "Linux", "1").status).not.toBe(0);
  expect(readFileSync(join(dir, "keevault"), "utf8")).toBe("original");
  expect(readdirSync(dir).some((name) => name.startsWith(".keevault-download."))).toBe(false);
});

test("fails for missing releases, unsupported systems and directory destinations", async () => {
  const { dir, run } = await fixture();
  expect(run("v99.0.0").stderr).toContain("No published");
  expect(run("", "riscv64").stderr).toContain("Unsupported CPU");
  expect(run("", "arm64", "0", "Darwin").stderr).toContain("Linux only");
  mkdirSync(join(dir, "keevault"));
  expect(run().status).not.toBe(0);
  expect(readdirSync(join(dir, "keevault"))).toEqual([]);
  const empty = await fixture(false);
  expect(empty.run().stderr).toContain("No published");
});
