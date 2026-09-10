/**
 * Fail if a normal build contains the end-to-end harness.
 *
 * The harness entry serves seed and approve routes that bypass passkey
 * step-up. It must exist only when VAULT_E2E=1 selects it, so a shipped bundle
 * must not contain the string that every harness route path starts with.
 */

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { exit } from "node:process";

const MARKER = "__e2e";
const ROOT = "dist/server";

async function* files(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* files(path);
    else yield path;
  }
}

const offenders = [];
for await (const path of files(ROOT)) {
  const text = await readFile(path, "utf8");
  if (text.includes(MARKER)) offenders.push(path);
}

if (offenders.length > 0) {
  console.error(`The build contains the harness marker ${MARKER}:`);
  for (const path of offenders) console.error(`  ${path}`);
  console.error("Build without VAULT_E2E=1 before shipping.");
  exit(1);
}
console.log(`No harness routes in ${ROOT}.`);

// A Workers runtime import prevents the browser from hydrating any route.
// In particular, an unhydrated setup form must never fall back to a GET.
const clientOffenders = [];
for await (const path of files("dist/client")) {
  if (!path.endsWith(".js")) continue;
  const text = await readFile(path, "utf8");
  if (text.includes("cloudflare:")) clientOffenders.push(path);
}
if (clientOffenders.length > 0) {
  console.error("The browser bundle contains a Workers runtime import:");
  for (const path of clientOffenders) console.error(`  ${path}`);
  exit(1);
}
console.log("No Workers runtime imports in dist/client.");
