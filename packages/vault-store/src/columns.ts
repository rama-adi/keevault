import { z } from "zod";

/** RFC 3339 UTC timestamp stored as TEXT. */
export const timestampColumn = z.string();

/** Nullable TEXT column. */
export const nullableTextColumn = z.string().nullable();

/** INTEGER column holding a non-negative version or count. */
export const integerColumn = z.number().int();

/** INTEGER column holding 0 or 1, read as a boolean. */
export const booleanColumn = z
  .union([z.literal(0), z.literal(1)])
  .transform((value) => value === 1);

/** Key lifecycle status shared by project and environment keys. */
export const keyStatusColumn = z.enum(["active", "retired"]);
export type KeyStatus = z.infer<typeof keyStatusColumn>;

/** Provenance enforcement mode on an environment. */
export const provenanceModeColumn = z.enum(["OFF", "ADVISORY", "REQUIRED"]);
export type ProvenanceMode = z.infer<typeof provenanceModeColumn>;
export const keyModeColumn = z.enum(["CLOUD", "COLD"]);
export type KeyMode = z.infer<typeof keyModeColumn>;

/** Boot request lifecycle states (spec section 15). */
export const bootStatusColumn = z.enum([
  "PENDING",
  "APPROVED",
  "DELIVERED",
  "CONSUMED",
  "DECLINED",
  "EXPIRED",
  "CANCELED",
]);
export type BootStatus = z.infer<typeof bootStatusColumn>;
