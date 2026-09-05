/**
 * The narrow SQL surface the boot state machine needs.
 *
 * `BootSessionCore` never touches `SqlStorage` directly. Everything it does is
 * one synchronous `exec`, which the Durable Object satisfies with
 * `ctx.storage.sql` and tests satisfy with `node:sqlite`. That is what lets the
 * whole state machine run under `vp test` without workerd.
 */

/** Every value the boot tables bind or return. Timestamps are epoch milliseconds. */
export type BootSqlValue = string | number | null;

/** One row as SQLite hands it back. Callers validate it with a zod schema. */
export type BootSqlRow = Record<string, BootSqlValue>;

export interface BootSqlStorage {
  exec(sql: string, ...bindings: BootSqlValue[]): BootSqlRow[];
}

/** Adapt a Durable Object's SQLite storage. */
export function fromSqlStorage(sql: SqlStorage): BootSqlStorage {
  return {
    exec(query: string, ...bindings: BootSqlValue[]): BootSqlRow[] {
      // SAFETY: the boot schema declares TEXT, INTEGER and NULL columns only, so
      // no BLOB can come back, and every read validates the row with zod.
      return sql.exec(query, ...bindings).toArray() as BootSqlRow[];
    },
  };
}
