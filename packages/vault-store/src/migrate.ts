import type { VaultDatabase } from "./d1.ts";

/**
 * Split a migration file into executable statements. Semicolons inside string
 * literals and comments do not end a statement.
 */
export function splitSqlStatements(sqlText: string): string[] {
  const statements: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;
  let index = 0;

  while (index < sqlText.length) {
    const character = sqlText[index] ?? "";
    const next = sqlText[index + 1] ?? "";

    if (inLineComment) {
      if (character === "\n") inLineComment = false;
      index += 1;
      continue;
    }
    if (inBlockComment) {
      if (character === "*" && next === "/") {
        inBlockComment = false;
        index += 2;
        continue;
      }
      index += 1;
      continue;
    }
    if (inSingleQuote) {
      current += character;
      if (character === "'") {
        if (next === "'") {
          current += next;
          index += 2;
          continue;
        }
        inSingleQuote = false;
      }
      index += 1;
      continue;
    }
    if (character === "-" && next === "-") {
      inLineComment = true;
      index += 2;
      continue;
    }
    if (character === "/" && next === "*") {
      inBlockComment = true;
      index += 2;
      continue;
    }
    if (character === "'") {
      inSingleQuote = true;
      current += character;
      index += 1;
      continue;
    }
    if (character === ";") {
      const statement = current.trim();
      if (statement.length > 0) statements.push(statement);
      current = "";
      index += 1;
      continue;
    }
    current += character;
    index += 1;
  }

  const trailing = current.trim();
  if (trailing.length > 0) statements.push(trailing);
  return statements;
}

/** Apply a migration file to a database, one statement at a time. */
export async function runMigrations(db: VaultDatabase, sqlText: string): Promise<void> {
  for (const statement of splitSqlStatements(sqlText)) {
    await db.prepare(statement).run();
  }
}
