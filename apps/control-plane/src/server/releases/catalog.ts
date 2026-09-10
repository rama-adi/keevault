import type { VaultDatabase } from "@keevault/vault-store";
import { z } from "zod";

import { constantTimeEquals } from "../auth/setup-token.ts";

const versionSchema = z
  .string()
  .max(128)
  .regex(
    /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$/,
  );
const binarySchema = z.object({
  arch: z.enum(["amd64", "arm64"]),
  hash: z.string().regex(/^[a-f0-9]{64}$/),
  url: z.string().max(512),
});
const publicationSchema = z
  .object({
    version: versionSchema,
    binaries: z.array(binarySchema).length(2),
  })
  .strict();
const rowSchema = binarySchema.extend({
  id: z.string(),
  version: versionSchema,
  createdat: z.string(),
});

export interface ReleaseEnv {
  VAULT_DB: VaultDatabase;
  KEEVAULT_RELEASE_KEY?: string;
}

/** Compare validated SemVer tags, including numeric prerelease identifiers. */
export function compareVersions(left: string, right: string): number {
  const [leftCore = "", ...leftSuffix] = left.slice(1).split("-");
  const [rightCore = "", ...rightSuffix] = right.slice(1).split("-");
  const a = leftCore.split(".");
  const b = rightCore.split(".");
  for (let i = 0; i < 3; i += 1) {
    const x = BigInt(a[i] ?? "0");
    const y = BigInt(b[i] ?? "0");
    if (x !== y) return x > y ? 1 : -1;
  }
  if (!leftSuffix.length || !rightSuffix.length)
    return Number(!leftSuffix.length) - Number(!rightSuffix.length);
  const x = leftSuffix.join("-").split(".");
  const y = rightSuffix.join("-").split(".");
  for (let i = 0; i < Math.max(x.length, y.length); i += 1) {
    const l = x[i];
    const r = y[i];
    if (l === undefined) return -1;
    if (r === undefined) return 1;
    if (l === r) continue;
    const ln = /^[0-9]+$/.test(l);
    const rn = /^[0-9]+$/.test(r);
    if (ln && rn) return BigInt(l) > BigInt(r) ? 1 : -1;
    if (ln !== rn) return ln ? -1 : 1;
    return l > r ? 1 : -1;
  }
  return 0;
}

export async function readBinaryCatalog(db: VaultDatabase) {
  const result = await db
    .prepare("SELECT id, version, arch, hash, createdat, url FROM binary_releases")
    .all();
  const binaries = z.array(rowSchema).parse(result.results);
  binaries.sort((a, b) => compareVersions(b.version, a.version) || a.arch.localeCompare(b.arch));
  return { latest: binaries[0]?.version ?? null, binaries };
}

async function catalog(db: VaultDatabase): Promise<Response> {
  return Response.json(await readBinaryCatalog(db), { headers: { "Cache-Control": "no-store" } });
}

export async function handleBinaryRequest(request: Request, env: ReleaseEnv): Promise<Response> {
  if (request.method === "GET") return catalog(env.VAULT_DB);
  if (request.method !== "POST")
    return new Response(null, { status: 405, headers: { Allow: "GET, POST" } });
  const key = env.KEEVAULT_RELEASE_KEY;
  const authorization = request.headers.get("Authorization") ?? "";
  if (!key || !constantTimeEquals(authorization, `Bearer ${key}`)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  // Bound the body even when the caller omits Content-Length.
  const reader = request.body?.getReader();
  if (!reader) return Response.json({ error: "Missing body" }, { status: 400 });
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.byteLength;
    if (size > 4096) {
      await reader.cancel();
      return Response.json({ error: "Body too large" }, { status: 413 });
    }
    chunks.push(chunk.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  let parsed;
  try {
    parsed = publicationSchema.safeParse(JSON.parse(new TextDecoder().decode(bytes)));
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!parsed.success) return Response.json({ error: "Invalid release" }, { status: 400 });
  const { version, binaries } = parsed.data;
  if (
    new Set(binaries.map((binary) => binary.arch)).size !== 2 ||
    binaries.some(
      (binary) =>
        binary.url !==
        `https://github.com/rama-adi/keevault/releases/download/${version}/keevault-linux-${binary.arch}`,
    )
  )
    return Response.json(
      { error: "Expected both architectures and matching GitHub release URLs" },
      { status: 400 },
    );
  const now = new Date().toISOString();
  // A conflicting immutable asset violates NOT NULL and rolls back the entire batch.
  const statements = binaries.map((binary) =>
    env.VAULT_DB.prepare(`
    INSERT INTO binary_releases (id, version, arch, hash, createdat, url) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(version, arch) DO UPDATE SET hash = CASE
      WHEN binary_releases.hash = excluded.hash AND binary_releases.url = excluded.url
      THEN binary_releases.hash ELSE NULL END
  `).bind(crypto.randomUUID(), version, binary.arch, binary.hash, now, binary.url),
  );
  try {
    await env.VAULT_DB.batch(statements);
  } catch (error) {
    if (error instanceof Error && error.message.includes("NOT NULL constraint failed")) {
      return Response.json({ error: "Published releases cannot be changed" }, { status: 409 });
    }
    throw error;
  }
  return catalog(env.VAULT_DB);
}
