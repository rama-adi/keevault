import { readFile } from "node:fs/promises";
import "./validate-release-version.mjs";

const key = process.env.KEEVAULT_RELEASE_KEY;
if (!key) throw new Error("KEEVAULT_RELEASE_KEY is required");
// The key is retrieved at runtime, so register it with Actions' log masking.
console.log(
  `::add-mask::${key.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A")}`,
);
const version = process.env.RELEASE_VERSION;
const sums = await readFile("dist/SHA256SUMS", "utf8");
const binaries = ["amd64", "arm64"].map((arch) => {
  const filename = `keevault-linux-${arch}`;
  const match = sums.split("\n").find((line) => line.endsWith(`  ${filename}`));
  const hash = match?.split(" ")[0];
  if (!hash || !/^[a-f0-9]{64}$/.test(hash)) throw new Error(`Missing checksum for ${arch}`);
  return {
    arch,
    hash,
    url: `https://github.com/rama-adi/keevault/releases/download/${version}/${filename}`,
  };
});
const response = await fetch("https://vault.keevault.my.id/binary.json", {
  method: "POST",
  headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
  body: JSON.stringify({ version, binaries }),
  signal: AbortSignal.timeout(60_000),
});
if (!response.ok) throw new Error(`Release registration failed: HTTP ${response.status}`);
console.log(`Registered ${version}`);
