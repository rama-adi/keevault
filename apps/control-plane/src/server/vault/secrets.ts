/**
 * Secret writes (spec section 23).
 *
 * Values arrive in the clear, are encrypted under the environment DEK with the
 * AAD from the engineering brief, and are never read back. There is no reveal
 * path anywhere in the service, and no function here logs or audits a value.
 */

import { b64uEncode, encryptSecret, utf8Encode } from "@env-vault/crypto";
import {
  deleteSecret as deleteSecretRow,
  getSecretForDelivery,
  listSecretMetadata,
  upsertSecretReplace,
} from "@env-vault/vault-store";

import { writeAuditEvent, type AuditMetadataValue } from "./audit.ts";
import type { VaultContext } from "./context.ts";
import { parseDotenv, type DotenvProblem } from "./dotenv.ts";
import { generatePrefixedUlidId } from "./ids.ts";
import { unwrapEnvironmentDek } from "./keys.ts";
import { requireEnvironment } from "./projects.ts";
import { toSecretSummary, type SecretSummary } from "./types.ts";
import { SECRET_NAME_PATTERN, SECRET_VALUE_MAX_BYTES, VaultInputError } from "./validation.ts";

export async function listSecretsMetadata(
  context: VaultContext,
  environmentId: string,
): Promise<SecretSummary[]> {
  return (await listSecretMetadata(context.db, environmentId)).map(toSecretSummary);
}

export interface PutSecretInput {
  environmentId: string;
  name: string;
  value: string;
}

/** Whether a write created a new secret or replaced an existing one. */
export interface PutSecretResult {
  secret: SecretSummary;
  created: boolean;
}

function assertSecretName(name: string): void {
  if (!SECRET_NAME_PATTERN.test(name)) {
    throw new VaultInputError("name", `${name} is not a valid environment variable name.`);
  }
}

function assertSecretValue(value: string): void {
  if (utf8Encode(value).length > SECRET_VALUE_MAX_BYTES) {
    throw new VaultInputError("value", "A secret value may be at most 64 KiB.");
  }
}

/**
 * Write one secret value. A name that already exists keeps its row id and gets
 * the next `secret_version`; a new name gets a fresh `sec_` id at version 1.
 */
export async function putSecret(
  context: VaultContext,
  input: PutSecretInput,
): Promise<PutSecretResult> {
  assertSecretName(input.name);
  assertSecretValue(input.value);
  const environment = await requireEnvironment(context, input.environmentId);
  const dek = await unwrapEnvironmentDek(context.db, context.keyring, input.environmentId);
  const now = context.now();
  const result = await writeSecret(context, {
    environment: { id: environment.id, projectId: environment.projectId },
    dek,
    name: input.name,
    value: input.value,
    now,
  });

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: result.created ? "secret.created" : "secret.updated",
      projectId: environment.projectId,
      environmentId: environment.id,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["secretId", result.secret.id],
        ["name", result.secret.name],
        ["secretVersion", result.secret.secretVersion],
        ["environmentKeyVersion", result.secret.environmentKeyVersion],
        ["valueBytes", utf8Encode(input.value).length],
      ]),
    },
  );
  return result;
}

interface WriteSecretInput {
  environment: { id: string; projectId: string };
  dek: { dek: Uint8Array<ArrayBuffer>; version: number };
  name: string;
  value: string;
  now: string;
}

/** Encrypt and store one value. Shared by `putSecret` and the dotenv import. */
async function writeSecret(
  context: VaultContext,
  input: WriteSecretInput,
): Promise<PutSecretResult> {
  const existing = await getSecretForDelivery(context.db, {
    environmentId: input.environment.id,
    name: input.name,
  });
  const created = existing === null;
  const secretId = existing?.id ?? generatePrefixedUlidId("sec");
  const secretVersion = existing === null ? 1 : existing.secretVersion + 1;

  const sealed = await encryptSecret({
    environmentKey: input.dek.dek,
    value: input.value,
    projectId: input.environment.projectId,
    environmentId: input.environment.id,
    secretId,
    secretName: input.name,
    secretVersion,
    environmentKeyVersion: input.dek.version,
  });

  const row = await upsertSecretReplace(context.db, {
    id: secretId,
    environmentId: input.environment.id,
    name: input.name,
    ciphertext: b64uEncode(sealed.ciphertext),
    nonce: b64uEncode(sealed.nonce),
    envKeyVersion: input.dek.version,
    now: input.now,
  });
  return { secret: toSecretSummary(row), created };
}

export interface DeleteSecretInput {
  environmentId: string;
  name: string;
}

export async function deleteSecret(context: VaultContext, input: DeleteSecretInput): Promise<void> {
  const environment = await requireEnvironment(context, input.environmentId);
  const existing = await getSecretForDelivery(context.db, input);
  if (existing === null) {
    throw new VaultInputError("name", `${input.name} is not set in this environment.`);
  }
  const now = context.now();
  await deleteSecretRow(context.db, input);
  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "secret.deleted",
      projectId: environment.projectId,
      environmentId: environment.id,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["secretId", existing.id],
        ["name", existing.name],
        ["secretVersion", existing.secretVersion],
      ]),
    },
  );
}

export interface ImportDotenvInput {
  environmentId: string;
  content: string;
}

/** Counts only. The imported values never leave the encrypt call (spec section 23). */
export interface ImportDotenvResult {
  created: number;
  replaced: number;
  /** Names present more than once in the file collapse to the last assignment. */
  parsed: number;
}

/**
 * Parse and store a pasted .env file.
 *
 * Any unusable line rejects the whole import, so an operator never ends up with
 * a half-applied file. The error names the offending variable names, which are
 * already shown in the dashboard, and never a value.
 */
export async function importDotenv(
  context: VaultContext,
  input: ImportDotenvInput,
): Promise<ImportDotenvResult> {
  const environment = await requireEnvironment(context, input.environmentId);
  const parsed = parseDotenv(input.content);
  if (parsed.problems.length > 0) {
    throw new VaultInputError("content", describeProblems(parsed.problems));
  }
  if (parsed.entries.length === 0) {
    throw new VaultInputError("content", "The file has no assignments to import.");
  }
  for (const entry of parsed.entries) {
    assertSecretValue(entry.value);
  }

  const dek = await unwrapEnvironmentDek(context.db, context.keyring, input.environmentId);
  const now = context.now();
  let created = 0;
  let replaced = 0;
  for (const entry of parsed.entries) {
    const result = await writeSecret(context, {
      environment: { id: environment.id, projectId: environment.projectId },
      dek,
      name: entry.name,
      value: entry.value,
      now,
    });
    if (result.created) created += 1;
    else replaced += 1;
  }

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "secret.updated",
      projectId: environment.projectId,
      environmentId: environment.id,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["source", "dotenv-import"],
        ["created", created],
        ["replaced", replaced],
        ["environmentKeyVersion", dek.version],
      ]),
    },
  );
  return { created, replaced, parsed: parsed.entries.length };
}

function describeProblems(problems: readonly DotenvProblem[]): string {
  const first = problems[0];
  if (first === undefined) return "The file could not be parsed.";
  const detail =
    first.reason === "invalid_name"
      ? `${first.name ?? "that name"} is not a valid environment variable name`
      : first.reason === "unterminated_quote"
        ? "the quoted value is not closed on the same line"
        : "the line is not a NAME=value assignment";
  const rest = problems.length - 1;
  const suffix = rest > 0 ? ` (${rest} more line${rest === 1 ? "" : "s"} also failed)` : "";
  return `Line ${first.lineNumber}: ${detail}${suffix}.`;
}
