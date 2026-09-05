import type { DatabaseSync } from "node:sqlite";

/** Value types the vault binds into SQL. Every binary field is stored as b64u text. */
export type VaultBindValue = string | number | null;

export interface VaultRunResult {
  success: boolean;
}

export interface VaultQueryResult<Row> {
  results: Row[];
  success: boolean;
}

/** The subset of a D1 prepared statement the vault store uses. */
export interface VaultPreparedStatement {
  bind(...values: VaultBindValue[]): VaultPreparedStatement;
  first<Row>(): Promise<Row | null>;
  run(): Promise<VaultRunResult>;
  all<Row>(): Promise<VaultQueryResult<Row>>;
}

/** The subset of a D1 database the vault store uses. */
export interface VaultDatabase {
  prepare(sql: string): VaultPreparedStatement;
  batch<Row>(statements: VaultPreparedStatement[]): Promise<VaultQueryResult<Row>[]>;
}

/**
 * The part of a Cloudflare D1 binding `fromD1` narrows.
 *
 * The shape is written out here instead of imported from
 * `@cloudflare/workers-types`, whose published entry declares its types as
 * globals and exports nothing, so a bundled declaration file cannot resolve an
 * import from it.
 */
export interface D1BindingLike {
  prepare(sql: string): VaultPreparedStatement;
  batch<Row>(statements: VaultPreparedStatement[]): Promise<VaultQueryResult<Row>[]>;
}

/**
 * Adapt a Cloudflare D1 binding. D1 already has the shape the store needs, so this
 * is a typed narrowing rather than a wrapper.
 */
export function fromD1(db: D1BindingLike): VaultDatabase {
  return db;
}

class NodeSqliteStatement implements VaultPreparedStatement {
  readonly #db: DatabaseSync;
  readonly #sql: string;
  readonly #params: readonly VaultBindValue[];

  constructor(db: DatabaseSync, sql: string, params: readonly VaultBindValue[]) {
    this.#db = db;
    this.#sql = sql;
    this.#params = params;
  }

  bind(...values: VaultBindValue[]): VaultPreparedStatement {
    return new NodeSqliteStatement(this.#db, this.#sql, values);
  }

  first<Row>(): Promise<Row | null> {
    try {
      const statement = this.#db.prepare(this.#sql);
      const row = statement.get(...this.#params);
      if (row === undefined || row === null) return Promise.resolve(null);
      // SAFETY: node:sqlite returns untyped column maps; every caller validates the
      // row with a zod schema before using it.
      return Promise.resolve(row as Row);
    } catch (error) {
      return Promise.reject(error);
    }
  }

  run(): Promise<VaultRunResult> {
    try {
      const statement = this.#db.prepare(this.#sql);
      statement.run(...this.#params);
      return Promise.resolve({ success: true });
    } catch (error) {
      return Promise.reject(error);
    }
  }

  all<Row>(): Promise<VaultQueryResult<Row>> {
    try {
      const statement = this.#db.prepare(this.#sql);
      const rows = statement.all(...this.#params);
      // SAFETY: node:sqlite returns untyped column maps; every caller validates each
      // row with a zod schema before using it.
      return Promise.resolve({ results: rows as Row[], success: true });
    } catch (error) {
      return Promise.reject(error);
    }
  }
}

class NodeSqliteDatabase implements VaultDatabase {
  readonly #db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.#db = db;
  }

  prepare(sql: string): VaultPreparedStatement {
    return new NodeSqliteStatement(this.#db, sql, []);
  }

  async batch<Row>(statements: VaultPreparedStatement[]): Promise<VaultQueryResult<Row>[]> {
    this.#db.exec("BEGIN");
    try {
      const results: VaultQueryResult<Row>[] = [];
      for (const statement of statements) {
        results.push(await statement.all<Row>());
      }
      this.#db.exec("COMMIT");
      return results;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }
}

/**
 * Adapt a `node:sqlite` database for tests. Foreign keys are off by default in
 * SQLite, so this turns them on to match D1 behaviour.
 */
export function fromNodeSqlite(db: DatabaseSync): VaultDatabase {
  db.exec("PRAGMA foreign_keys = ON;");
  return new NodeSqliteDatabase(db);
}
