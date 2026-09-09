/** Prefixed ULID generation for vault rows. */

import { generatePrefixedUlid, type UlidPrefix } from "@keevault/crypto";

/** Generate a prefixed ULID, for example `proj_01K4...`. */
export function generatePrefixedUlidId(prefix: UlidPrefix): string {
  return generatePrefixedUlid(prefix);
}
