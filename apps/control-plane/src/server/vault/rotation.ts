/**
 * Key rotation (spec section 39).
 *
 * Environment rotation is the only operation in the vault that holds secret
 * plaintext, and it holds it for the length of one call: every value is
 * decrypted under the retiring key and re-encrypted under the new one before
 * anything is written. The rewrites and the version switch go into one store
 * batch, so a reader sees either the old key with the old ciphertext or the new
 * key with the new ciphertext, never a mixture.
 *
 * Project rotation touches no secret value. It rewraps every environment key,
 * including retired ones, so historical keys stay readable.
 */

import {
  b64uEncode,
  b64uDecode,
  decryptSecret,
  encryptSecret,
  generateKey32,
  unwrapEnvironmentKey,
  wrapEnvironmentKey,
  wrapProjectKey,
  type Bytes,
} from "@env-vault/crypto";
import {
  buildReencryptSecretStatement,
  buildRetireProjectKeyStatement,
  buildRewrapEnvironmentKeyStatement,
  buildSetCurrentProjectKeyVersionStatement,
  buildSwitchCurrentEnvironmentKeyStatements,
  getCurrentEnvironmentKey,
  insertEnvironmentKey,
  insertProjectKey,
  listEnvironmentKeysByProject,
  listSecretsForDelivery,
  type EnvironmentKeyRow,
  type VaultPreparedStatement,
} from "@env-vault/vault-store";

import { writeAuditEvent, type AuditMetadataValue } from "./audit.ts";
import type { VaultContext } from "./context.ts";
import {
  unwrapEnvironmentDek,
  unwrapProjectKey,
  unwrapProjectKeyVersion,
  VaultKeyError,
} from "./keys.ts";
import { requireEnvironment, requireProject } from "./projects.ts";

export interface RotateEnvironmentKeyResult {
  environmentId: string;
  previousVersion: number;
  version: number;
  secretsReencrypted: number;
}

/**
 * Generate a new environment DEK, re-encrypt every secret under it and switch
 * the environment over. The retiring key row is marked retired but kept, so an
 * in-flight boot holding the old DEK can still be reasoned about.
 */
export async function rotateEnvironmentKey(
  context: VaultContext,
  environmentId: string,
): Promise<RotateEnvironmentKeyResult> {
  const environment = await requireEnvironment(context, environmentId);
  const currentKeyRow = await getCurrentEnvironmentKey(context.db, environmentId);
  if (currentKeyRow === null) {
    throw new VaultKeyError(
      "environment_key_missing",
      `Environment ${environmentId} has no current key.`,
    );
  }
  const previous = await unwrapEnvironmentDek(context.db, context.keyring, environmentId);
  const projectKey = await unwrapProjectKey(context.db, context.keyring, environment.projectId);

  const nextVersion = previous.version + 1;
  const nextDek = generateKey32();
  const sealedKey = await wrapEnvironmentKey({
    projectKey: projectKey.key,
    environmentKey: nextDek,
    projectId: environment.projectId,
    environmentId,
    environmentKeyVersion: nextVersion,
    projectKeyVersion: projectKey.version,
  });

  const now = context.now();
  const secrets = await listSecretsForDelivery(context.db, environmentId);
  const rewrites: VaultPreparedStatement[] = [];
  for (const secret of secrets) {
    const value = await decryptSecret({
      environmentKey: previous.dek,
      nonce: b64uDecode(secret.nonce),
      ciphertext: b64uDecode(secret.ciphertext),
      projectId: environment.projectId,
      environmentId,
      secretId: secret.id,
      secretName: secret.name,
      secretVersion: secret.secretVersion,
      environmentKeyVersion: secret.envKeyVersion,
    });
    const sealed = await encryptSecret({
      environmentKey: nextDek,
      value,
      projectId: environment.projectId,
      environmentId,
      secretId: secret.id,
      secretName: secret.name,
      secretVersion: secret.secretVersion,
      environmentKeyVersion: nextVersion,
    });
    rewrites.push(
      buildReencryptSecretStatement(context.db, {
        id: secret.id,
        ciphertext: b64uEncode(sealed.ciphertext),
        nonce: b64uEncode(sealed.nonce),
        envKeyVersion: nextVersion,
        now,
      }),
    );
  }

  await insertEnvironmentKey(context.db, {
    environmentId,
    version: nextVersion,
    projectKeyVersion: projectKey.version,
    wrappedKey: b64uEncode(sealedKey.ciphertext),
    nonce: b64uEncode(sealedKey.nonce),
    now,
  });
  await context.db.batch([
    ...rewrites,
    ...buildSwitchCurrentEnvironmentKeyStatements(context.db, {
      environmentId,
      previousVersion: previous.version,
      nextVersion,
      now,
    }),
  ]);

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "environment-key.rotated",
      projectId: environment.projectId,
      environmentId,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["previousVersion", previous.version],
        ["version", nextVersion],
        ["projectKeyVersion", projectKey.version],
        ["secretsReencrypted", secrets.length],
      ]),
    },
  );

  return {
    environmentId,
    previousVersion: previous.version,
    version: nextVersion,
    secretsReencrypted: secrets.length,
  };
}

export interface RotateProjectKeyResult {
  projectId: string;
  previousVersion: number;
  version: number;
  environmentKeysRewrapped: number;
}

/**
 * Generate a new project key, rewrap every environment key under it and switch
 * the project over. No secret value is touched.
 */
export async function rotateProjectKey(
  context: VaultContext,
  projectId: string,
): Promise<RotateProjectKeyResult> {
  await requireProject(context, projectId);
  const current = await unwrapProjectKey(context.db, context.keyring, projectId);
  const nextVersion = current.version + 1;
  const masterKeyVersion = context.keyring.activeVersion;
  const nextKey = generateKey32();
  const sealedKey = await wrapProjectKey({
    masterKey: context.keyring.key(masterKeyVersion),
    projectKey: nextKey,
    projectId,
    projectKeyVersion: nextVersion,
    masterKeyVersion,
  });

  const now = context.now();
  const environmentKeys = await listEnvironmentKeysByProject(context.db, projectId);
  const rewraps: VaultPreparedStatement[] = [];
  for (const keyRow of environmentKeys) {
    const wrappingKey = await unwrapProjectKeyVersion(
      context.db,
      context.keyring,
      projectId,
      keyRow.projectKeyVersion,
    );
    const dek = await unwrapEnvironmentKeyRow(wrappingKey, projectId, keyRow);
    const sealed = await wrapEnvironmentKey({
      projectKey: nextKey,
      environmentKey: dek,
      projectId,
      environmentId: keyRow.environmentId,
      environmentKeyVersion: keyRow.version,
      projectKeyVersion: nextVersion,
    });
    rewraps.push(
      buildRewrapEnvironmentKeyStatement(context.db, {
        environmentId: keyRow.environmentId,
        version: keyRow.version,
        projectKeyVersion: nextVersion,
        wrappedKey: b64uEncode(sealed.ciphertext),
        nonce: b64uEncode(sealed.nonce),
      }),
    );
  }

  await insertProjectKey(context.db, {
    projectId,
    version: nextVersion,
    masterKeyVersion,
    wrappedKey: b64uEncode(sealedKey.ciphertext),
    nonce: b64uEncode(sealedKey.nonce),
    now,
  });
  await context.db.batch([
    ...rewraps,
    buildRetireProjectKeyStatement(context.db, { projectId, version: current.version, now }),
    buildSetCurrentProjectKeyVersionStatement(context.db, { projectId, version: nextVersion, now }),
  ]);

  await writeAuditEvent(
    { db: context.db, actor: context.actor, timestamp: now },
    {
      action: "project-key.rotated",
      projectId,
      environmentId: null,
      bootId: null,
      metadata: new Map<string, AuditMetadataValue>([
        ["previousVersion", current.version],
        ["version", nextVersion],
        ["masterKeyVersion", masterKeyVersion],
        ["environmentKeysRewrapped", environmentKeys.length],
      ]),
    },
  );

  return {
    projectId,
    previousVersion: current.version,
    version: nextVersion,
    environmentKeysRewrapped: environmentKeys.length,
  };
}

/** Unwrap one stored environment key row under the project key it was wrapped with. */
async function unwrapEnvironmentKeyRow(
  projectKey: Bytes,
  projectId: string,
  row: EnvironmentKeyRow,
): Promise<Bytes> {
  try {
    return await unwrapEnvironmentKey({
      projectKey,
      nonce: b64uDecode(row.nonce),
      ciphertext: b64uDecode(row.wrappedKey),
      projectId,
      environmentId: row.environmentId,
      environmentKeyVersion: row.version,
      projectKeyVersion: row.projectKeyVersion,
    });
  } catch {
    throw new VaultKeyError(
      "unwrap_failed",
      `Environment key ${row.environmentId} v${row.version} did not authenticate.`,
    );
  }
}
