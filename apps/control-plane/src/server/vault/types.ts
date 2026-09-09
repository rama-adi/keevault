/**
 * Metadata the dashboard is allowed to see.
 *
 * No type in this file carries ciphertext, a nonce, a token, or any key
 * material. The service maps store rows into these before returning.
 */

import type {
  BootstrapTokenRow,
  EnvironmentRow,
  ProjectRow,
  SecretMetadataRow,
  TrustedSignerRow,
} from "@keevault/vault-store";
import { z } from "zod";

export interface ProjectSummary {
  id: string;
  slug: string;
  name: string;
  projectKeyVersion: number;
  createdAt: string;
  updatedAt: string;
}

export function toProjectSummary(row: ProjectRow): ProjectSummary {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    projectKeyVersion: row.currentProjectKeyVersion,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export interface EnvironmentSummary {
  id: string;
  projectId: string;
  slug: string;
  name: string;
  environmentKeyVersion: number;
  provenanceMode: "OFF" | "ADVISORY" | "REQUIRED";
  pendingTtlSeconds: number;
  approvedTtlSeconds: number;
  createdAt: string;
  updatedAt: string;
}

export function toEnvironmentSummary(row: EnvironmentRow): EnvironmentSummary {
  return {
    id: row.id,
    projectId: row.projectId,
    slug: row.slug,
    name: row.name,
    environmentKeyVersion: row.currentEnvKeyVersion,
    provenanceMode: row.provenanceMode,
    pendingTtlSeconds: row.pendingTtlSeconds,
    approvedTtlSeconds: row.approvedTtlSeconds,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export interface SecretSummary {
  id: string;
  name: string;
  secretVersion: number;
  environmentKeyVersion: number;
  createdAt: string;
  updatedAt: string;
}

export function toSecretSummary(row: SecretMetadataRow): SecretSummary {
  return {
    id: row.id,
    name: row.name,
    secretVersion: row.secretVersion,
    environmentKeyVersion: row.envKeyVersion,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export interface BootstrapTokenSummary {
  id: string;
  environmentId: string;
  label: string;
  allowedCidrs: string[];
  maxPendingBoots: number;
  expiresAt: string | null;
  revokedAt: string | null;
  lastSeenAt: string | null;
  createdAt: string;
}

const storedCidrsSchema = z.array(z.string()).catch([]);

export function toBootstrapTokenSummary(row: BootstrapTokenRow): BootstrapTokenSummary {
  return {
    id: row.id,
    environmentId: row.environmentId,
    label: row.label,
    allowedCidrs: storedCidrsSchema.parse(parseJsonArray(row.allowedCidrsJson)),
    maxPendingBoots: row.maxPendingBoots,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    lastSeenAt: row.lastSeenAt,
    createdAt: row.createdAt,
  };
}

function parseJsonArray(text: string): string[] {
  try {
    return storedCidrsSchema.parse(JSON.parse(text));
  } catch {
    return [];
  }
}

export interface TrustedSignerSummary {
  id: string;
  projectId: string | null;
  environmentId: string | null;
  type: string;
  label: string;
  fingerprint: string;
  enabled: boolean;
  createdAt: string;
  revokedAt: string | null;
}

export function toTrustedSignerSummary(row: TrustedSignerRow): TrustedSignerSummary {
  return {
    id: row.id,
    projectId: row.projectId,
    environmentId: row.environmentId,
    type: row.type,
    label: row.label,
    fingerprint: row.fingerprint,
    enabled: row.enabled,
    createdAt: row.createdAt,
    revokedAt: row.revokedAt,
  };
}
