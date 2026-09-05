import { z } from "zod";

import { ClientMessage, ServerMessage } from "./messages.ts";
import type {
  ClientMessage as ClientMessageType,
  ServerMessage as ServerMessageType,
} from "./messages.ts";

/** The outcome of parsing one client text frame. */
export type ClientFrameResult =
  | { readonly ok: true; readonly message: ClientMessageType }
  | { readonly ok: false; readonly error: string };

/** The outcome of parsing one server text frame. */
export type ServerFrameResult =
  | { readonly ok: true; readonly message: ServerMessageType }
  | { readonly ok: false; readonly error: string };

const jsonText = z.string().transform((text, context) => {
  try {
    return JSON.parse(text);
  } catch {
    context.addIssue({ code: "custom", message: "frame is not valid JSON" });
    return z.NEVER;
  }
});

const clientFrame = jsonText.pipe(ClientMessage);
const serverFrame = jsonText.pipe(ServerMessage);

/**
 * Parse one text frame sent by a client. Never throws. On failure the error
 * string names the failing fields and is safe to log: it contains no frame
 * values, only paths and reasons.
 */
export function parseClientFrame(text: string): ClientFrameResult {
  const parsed = clientFrame.safeParse(text);
  if (parsed.success) return { ok: true, message: parsed.data };
  return { ok: false, error: z.prettifyError(parsed.error) };
}

/**
 * Parse one text frame sent by the server. Never throws. The error string is
 * safe to log for the same reason as parseClientFrame.
 */
export function parseServerFrame(text: string): ServerFrameResult {
  const parsed = serverFrame.safeParse(text);
  if (parsed.success) return { ok: true, message: parsed.data };
  return { ok: false, error: z.prettifyError(parsed.error) };
}
