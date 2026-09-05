import { z } from "zod";

import { nullableTextColumn, timestampColumn } from "../columns.ts";
import type { VaultDatabase } from "../d1.ts";
import { selectMany, selectRequired } from "../sql.ts";

export const auditEventRowSchema = z.object({
  id: z.string(),
  timestamp: timestampColumn,
  actorType: z.string(),
  actorId: nullableTextColumn,
  action: z.string(),
  projectId: nullableTextColumn,
  environmentId: nullableTextColumn,
  bootId: nullableTextColumn,
  metadataJson: z.string(),
});

export type AuditEventRow = z.infer<typeof auditEventRowSchema>;

const auditEventColumns = `
  id AS id,
  timestamp AS timestamp,
  actor_type AS actorType,
  actor_id AS actorId,
  action AS action,
  project_id AS projectId,
  environment_id AS environmentId,
  boot_id AS bootId,
  metadata_json AS metadataJson
`;

export interface AppendAuditEventInput {
  id: string;
  timestamp: string;
  actorType: string;
  actorId: string | null;
  action: string;
  projectId: string | null;
  environmentId: string | null;
  bootId: string | null;
  /** Metadata must never contain decrypted secret material (spec section 35). */
  metadataJson: string;
}

export async function appendAuditEvent(
  db: VaultDatabase,
  input: AppendAuditEventInput,
): Promise<AuditEventRow> {
  const statement = db
    .prepare(
      `INSERT INTO audit_events
         (id, timestamp, actor_type, actor_id, action, project_id, environment_id, boot_id,
          metadata_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       RETURNING ${auditEventColumns}`,
    )
    .bind(
      input.id,
      input.timestamp,
      input.actorType,
      input.actorId,
      input.action,
      input.projectId,
      input.environmentId,
      input.bootId,
      input.metadataJson,
    );
  return await selectRequired(statement, auditEventRowSchema);
}

export interface ListAuditEventsInput {
  id: string;
  limit: number;
  /** Event id to page before. Ids sort by time, newest last. */
  before: string | null;
}

function listByColumn(
  db: VaultDatabase,
  column: string,
  input: ListAuditEventsInput,
): Promise<AuditEventRow[]> {
  const statement = db
    .prepare(
      `SELECT ${auditEventColumns}
       FROM audit_events
       WHERE ${column} = ?1 AND (?2 IS NULL OR id < ?2)
       ORDER BY id DESC
       LIMIT ?3`,
    )
    .bind(input.id, input.before, input.limit);
  return selectMany(statement, auditEventRowSchema);
}

export async function listAuditEventsByProject(
  db: VaultDatabase,
  input: ListAuditEventsInput,
): Promise<AuditEventRow[]> {
  return await listByColumn(db, "project_id", input);
}

export async function listAuditEventsByEnvironment(
  db: VaultDatabase,
  input: ListAuditEventsInput,
): Promise<AuditEventRow[]> {
  return await listByColumn(db, "environment_id", input);
}

export async function listAuditEventsByBoot(
  db: VaultDatabase,
  input: ListAuditEventsInput,
): Promise<AuditEventRow[]> {
  return await listByColumn(db, "boot_id", input);
}

const countRowSchema = z.object({ eventCount: z.number().int() });

export async function countAuditEvents(db: VaultDatabase): Promise<number> {
  const statement = db.prepare("SELECT COUNT(*) AS eventCount FROM audit_events");
  const row = await selectRequired(statement, countRowSchema);
  return row.eventCount;
}
