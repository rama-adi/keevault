/**
 * Reading the audit log for the dashboard.
 *
 * Metadata comes back as the stored JSON string. The dashboard renders it as
 * text; nothing re-interprets it as a typed value, and by construction it holds
 * only identifiers, fingerprints, versions and counts.
 */

import {
  listAuditEventsByEnvironment,
  listAuditEventsByProject,
  type AuditEventRow,
  type VaultDatabase,
} from "@env-vault/vault-store";
import { z } from "zod";

import type { VaultContext } from "./context.ts";

export interface AuditEventView {
  id: string;
  timestamp: string;
  actorType: string;
  actorId: string | null;
  action: string;
  projectId: string | null;
  environmentId: string | null;
  bootId: string | null;
  metadataJson: string;
}

export interface AuditPage {
  events: AuditEventView[];
  /** Pass back as `before` to read the next, older page. */
  nextCursor: string | null;
}

export interface ListAuditEventsInput {
  projectId: string | null;
  environmentId: string | null;
  before: string | null;
  limit: number;
}

const globalPageSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  actorType: z.string(),
  actorId: z.string().nullable(),
  action: z.string(),
  projectId: z.string().nullable(),
  environmentId: z.string().nullable(),
  bootId: z.string().nullable(),
  metadataJson: z.string(),
});

function toView(row: AuditEventRow): AuditEventView {
  return {
    id: row.id,
    timestamp: row.timestamp,
    actorType: row.actorType,
    actorId: row.actorId,
    action: row.action,
    projectId: row.projectId,
    environmentId: row.environmentId,
    bootId: row.bootId,
    metadataJson: row.metadataJson,
  };
}

/** Newest first, cursor paged by event id. */
export async function listAuditEvents(
  context: VaultContext,
  input: ListAuditEventsInput,
): Promise<AuditPage> {
  const events = await readPage(context.db, input);
  const last = events.at(-1);
  return {
    events,
    nextCursor: events.length < input.limit || last === undefined ? null : last.id,
  };
}

async function readPage(db: VaultDatabase, input: ListAuditEventsInput): Promise<AuditEventView[]> {
  if (input.environmentId !== null) {
    const rows = await listAuditEventsByEnvironment(db, {
      id: input.environmentId,
      before: input.before,
      limit: input.limit,
    });
    return rows.map(toView);
  }
  if (input.projectId !== null) {
    const rows = await listAuditEventsByProject(db, {
      id: input.projectId,
      before: input.before,
      limit: input.limit,
    });
    return rows.map(toView);
  }
  const result = await db
    .prepare(
      `SELECT
         id AS id,
         timestamp AS timestamp,
         actor_type AS actorType,
         actor_id AS actorId,
         action AS action,
         project_id AS projectId,
         environment_id AS environmentId,
         boot_id AS bootId,
         metadata_json AS metadataJson
       FROM audit_events
       WHERE (?1 IS NULL OR id < ?1)
       ORDER BY id DESC
       LIMIT ?2`,
    )
    .bind(input.before, input.limit)
    .all<AuditEventView>();
  return result.results.map((row) => globalPageSchema.parse(row));
}
