import { DatabaseSync } from "node:sqlite";

import type { BootSqlRow, BootSqlStorage, BootSqlValue } from "./boot-storage.ts";
import type { BootConnection, BootSocket } from "./boot-session-core.ts";

/**
 * Test doubles for the boot state machine.
 *
 * The Durable Object satisfies `BootSqlStorage` with `ctx.storage.sql` and
 * `BootSocketRegistry` with the hibernating WebSocket API. These implement the
 * same interfaces over `node:sqlite` and plain objects, which is what lets the
 * transition tests run under `vp test` without workerd. Nothing outside a test
 * imports this module.
 */

const SELECT = /^\s*select/i;

/** Adapt a `node:sqlite` database to the storage interface the core takes. */
export function fromNodeSqliteStorage(db: DatabaseSync): BootSqlStorage {
  return {
    exec(sql: string, ...bindings: BootSqlValue[]): BootSqlRow[] {
      const statement = db.prepare(sql);
      if (!SELECT.test(sql)) {
        statement.run(...bindings);
        return [];
      }
      // SAFETY: node:sqlite returns untyped column maps; every read in the core
      // validates the row with a zod schema before using it.
      return statement.all(...bindings) as BootSqlRow[];
    },
  };
}

/** One socket, recording what the core wrote to it. */
export class FakeConnection implements BootConnection {
  readonly sent: string[] = [];
  closedCode: number | null = null;
  closedReason: string | null = null;
  #bootId: string | null = null;
  #generation: number | null = null;

  send(text: string): void {
    this.sent.push(text);
  }

  close(code: number, reason: string): void {
    this.closedCode = code;
    this.closedReason = reason;
  }

  attachedBootId(): string | null {
    return this.#bootId;
  }

  attach(bootId: string, generation: number): void {
    this.#bootId = bootId;
    this.#generation = generation;
  }

  /** The generation stamped on the attachment, for assertions about reattachment. */
  generation(): number | null {
    return this.#generation;
  }

  /** The last frame the core wrote, parsed enough to read its `type`. */
  lastFrame(): string {
    return this.sent[this.sent.length - 1] ?? "";
  }

  /** True once the socket is closed, so a test can assert delivery stopped. */
  isClosed(): boolean {
    return this.closedCode !== null;
  }
}

/** Every connection a test made, filtered by attachment the way the DO filters. */
export class FakeSocketRegistry {
  readonly connections: FakeConnection[] = [];

  open(): FakeConnection {
    const connection = new FakeConnection();
    this.connections.push(connection);
    return connection;
  }

  forBoot(bootId: string): readonly BootSocket[] {
    return this.connections.filter(
      (connection) => !connection.isClosed() && connection.attachedBootId() === bootId,
    );
  }
}
