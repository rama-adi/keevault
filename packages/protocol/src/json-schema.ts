import { z } from "zod";

import { ClientMessage, ServerMessage } from "./messages.ts";

const document = z
  .strictObject({
    clientMessage: ClientMessage,
    serverMessage: ServerMessage,
  })
  .meta({
    title: "keevault bootstrap protocol v1",
    description:
      "Frames exchanged on GET /bootstrap/v1. clientMessage holds every frame a bootstrap client may send, serverMessage every frame the server may send. Generated from packages/protocol; edit the zod schemas, not this file.",
  });

/**
 * Build the JSON Schema document committed at protocol/messages.schema.json.
 * The schema script writes the return value; a test compares it to the file.
 */
export function messagesJsonSchema(): string {
  const generated = z.toJSONSchema(document, {
    target: "draft-2020-12",
    io: "input",
    unrepresentable: "any",
  });
  return `${JSON.stringify(generated, null, 2)}\n`;
}
