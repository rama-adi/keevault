import type { ZodType } from "zod";

import type { VaultPreparedStatement, VaultQueryResult, VaultRunResult } from "./d1.ts";

/** Read at most one row and validate it against a row schema. */
export async function selectOne<Row>(
  statement: VaultPreparedStatement,
  schema: ZodType<Row>,
): Promise<Row | null> {
  const row = await statement.first<Row>();
  if (row === null) return null;
  return schema.parse(row);
}

/** Read one row that must exist. */
export async function selectRequired<Row>(
  statement: VaultPreparedStatement,
  schema: ZodType<Row>,
): Promise<Row> {
  const row = await selectOne(statement, schema);
  if (row === null) throw new Error("expected exactly one row, got none");
  return row;
}

/** Read every row and validate each one against a row schema. */
export async function selectMany<Row>(
  statement: VaultPreparedStatement,
  schema: ZodType<Row>,
): Promise<Row[]> {
  const result: VaultQueryResult<Row> = await statement.all<Row>();
  return result.results.map((row) => schema.parse(row));
}

/** Execute a write statement. */
export async function execute(statement: VaultPreparedStatement): Promise<VaultRunResult> {
  return await statement.run();
}
