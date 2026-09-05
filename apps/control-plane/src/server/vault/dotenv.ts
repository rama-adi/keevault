/**
 * Parser for a pasted or uploaded .env file (spec section 23).
 *
 * The parser handles what an operator's .env realistically contains: comments,
 * blank lines, an optional `export ` prefix, and values that are bare, single
 * quoted or double quoted. Escapes are expanded inside double quotes only.
 * A value that opens a quote and never closes it on the same line is an error;
 * multi-line values are not supported in V1.
 *
 * Nothing here logs. The returned values go straight into an encrypt call.
 */

import { SECRET_NAME_PATTERN } from "./validation.ts";

/** One accepted assignment. */
export interface DotenvEntry {
  readonly name: string;
  readonly value: string;
}

/** A line that could not be used, described without its value. */
export interface DotenvProblem {
  readonly lineNumber: number;
  readonly reason: "malformed_line" | "invalid_name" | "unterminated_quote";
  /** Present only when the reason is `invalid_name`, and truncated. */
  readonly name: string | null;
}

export interface DotenvParseResult {
  readonly entries: readonly DotenvEntry[];
  readonly problems: readonly DotenvProblem[];
}

const DOUBLE_QUOTE_ESCAPES: ReadonlyMap<string, string> = new Map([
  ["n", "\n"],
  ["r", "\r"],
  ["t", "\t"],
  ["b", "\b"],
  ["f", "\f"],
  ['"', '"'],
  ["\\", "\\"],
  ["$", "$"],
]);

function expandDoubleQuoted(raw: string): string {
  let out = "";
  let index = 0;
  while (index < raw.length) {
    const character = raw[index] ?? "";
    if (character === "\\" && index + 1 < raw.length) {
      const next = raw[index + 1] ?? "";
      const replacement = DOUBLE_QUOTE_ESCAPES.get(next);
      if (replacement === undefined) {
        out += character + next;
      } else {
        out += replacement;
      }
      index += 2;
      continue;
    }
    out += character;
    index += 1;
  }
  return out;
}

/** Strip a trailing ` # comment` from an unquoted value. */
function stripTrailingComment(raw: string): string {
  const marker = raw.search(/\s#/);
  return marker < 0 ? raw : raw.slice(0, marker);
}

function readValue(raw: string): { value: string } | { unterminated: true } {
  const trimmed = raw.trim();
  const opener = trimmed[0];
  if (opener === '"' || opener === "'") {
    if (trimmed.length < 2 || !trimmed.endsWith(opener)) {
      return { unterminated: true };
    }
    const inner = trimmed.slice(1, -1);
    return { value: opener === '"' ? expandDoubleQuoted(inner) : inner };
  }
  return { value: stripTrailingComment(trimmed).trimEnd() };
}

/**
 * Parse dotenv text. Later assignments to the same name win, matching how a
 * shell sourcing the file would behave.
 */
export function parseDotenv(text: string): DotenvParseResult {
  const byName = new Map<string, string>();
  const problems: DotenvProblem[] = [];
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    const lineNumber = index + 1;
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) continue;

    const assignment = trimmed.startsWith("export ") ? trimmed.slice("export ".length) : trimmed;
    const separator = assignment.indexOf("=");
    if (separator < 1) {
      problems.push({ lineNumber, reason: "malformed_line", name: null });
      continue;
    }
    const name = assignment.slice(0, separator).trim();
    if (!SECRET_NAME_PATTERN.test(name)) {
      problems.push({ lineNumber, reason: "invalid_name", name: name.slice(0, 64) });
      continue;
    }
    const read = readValue(assignment.slice(separator + 1));
    if ("unterminated" in read) {
      problems.push({ lineNumber, reason: "unterminated_quote", name });
      continue;
    }
    byName.set(name, read.value);
  }

  const entries = [...byName].map(([name, value]) => ({ name, value }));
  return { entries, problems };
}
