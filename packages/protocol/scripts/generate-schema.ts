import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { messagesJsonSchema } from "../src/json-schema.ts";

const target = fileURLToPath(new URL("../../../protocol/messages.schema.json", import.meta.url));

await writeFile(target, messagesJsonSchema(), "utf8");

// The repository formatter owns the layout of committed JSON. Run it here so a
// generated file never fails `vp check` at the root.
execFileSync("vp", ["fmt", target], { stdio: "inherit" });

process.stdout.write(`wrote ${target}\n`);
