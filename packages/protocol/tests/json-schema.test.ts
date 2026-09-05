import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, test } from "vite-plus/test";

import { messagesJsonSchema } from "../src/json-schema.ts";

const schemaPath = fileURLToPath(
  new URL("../../../protocol/messages.schema.json", import.meta.url),
);

test("the committed JSON Schema is the generated one", () => {
  // Compare parsed documents, not bytes: the repository formatter rewrites the
  // committed file's whitespace after the generator runs.
  expect(JSON.parse(readFileSync(schemaPath, "utf8"))).toEqual(JSON.parse(messagesJsonSchema()));
});

test("the schema documents both directions", () => {
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  expect(Object.keys(schema.properties)).toEqual(["clientMessage", "serverMessage"]);
  expect(schema.properties.clientMessage.oneOf).toHaveLength(4);
  expect(schema.properties.serverMessage.oneOf).toHaveLength(9);
});
