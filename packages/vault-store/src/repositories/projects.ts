import { z } from "zod";

import { integerColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { execute, selectMany, selectOne, selectRequired } from "../sql.ts";

export const projectRowSchema = z.object({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  currentProjectKeyVersion: integerColumn,
  createdAt: timestampColumn,
  updatedAt: timestampColumn,
});

export type ProjectRow = z.infer<typeof projectRowSchema>;

const projectColumns = `
  id AS id,
  slug AS slug,
  name AS name,
  current_project_key_version AS currentProjectKeyVersion,
  created_at AS createdAt,
  updated_at AS updatedAt
`;

export interface CreateProjectInput {
  id: string;
  slug: string;
  name: string;
  now: string;
}

export async function createProject(
  db: VaultDatabase,
  input: CreateProjectInput,
): Promise<ProjectRow> {
  const statement = db
    .prepare(
      `INSERT INTO projects (id, slug, name, current_project_key_version, created_at, updated_at)
       VALUES (?, ?, ?, 0, ?, ?)
       RETURNING ${projectColumns}`,
    )
    .bind(input.id, input.slug, input.name, input.now, input.now);
  return await selectRequired(statement, projectRowSchema);
}

export async function getProjectById(
  db: VaultDatabase,
  projectId: string,
): Promise<ProjectRow | null> {
  const statement = db
    .prepare(`SELECT ${projectColumns} FROM projects WHERE id = ?`)
    .bind(projectId);
  return await selectOne(statement, projectRowSchema);
}

export async function getProjectBySlug(
  db: VaultDatabase,
  slug: string,
): Promise<ProjectRow | null> {
  const statement = db.prepare(`SELECT ${projectColumns} FROM projects WHERE slug = ?`).bind(slug);
  return await selectOne(statement, projectRowSchema);
}

export async function listProjects(db: VaultDatabase): Promise<ProjectRow[]> {
  const statement = db.prepare(`SELECT ${projectColumns} FROM projects ORDER BY slug`);
  return await selectMany(statement, projectRowSchema);
}

export async function deleteProject(db: VaultDatabase, projectId: string): Promise<void> {
  await execute(db.prepare("DELETE FROM projects WHERE id = ?").bind(projectId));
}

export interface SetCurrentProjectKeyVersionInput {
  projectId: string;
  version: number;
  now: string;
}

export async function setCurrentProjectKeyVersion(
  db: VaultDatabase,
  input: SetCurrentProjectKeyVersionInput,
): Promise<void> {
  await execute(
    db
      .prepare("UPDATE projects SET current_project_key_version = ?, updated_at = ? WHERE id = ?")
      .bind(input.version, input.now, input.projectId),
  );
}
