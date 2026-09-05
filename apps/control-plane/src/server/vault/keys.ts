/**
 * Master key access and the unwrap path down to an environment DEK.
 *
 * The master keys are Worker secrets named `VAULT_MASTER_KEY_V<n>`, each holding
 * 32 random bytes as base64url without padding.
 * `VAULT_MASTER_KEY_ACTIVE_VERSION` names the version that wraps new project
 * keys; older versions stay readable so a rotation can proceed in steps
 * (spec section 39).
 *
 * Nothing in this file logs, returns or stores key material outside the values
 * a caller explicitly asks for.
 */

import {
  b64uDecode,
  unwrapEnvironmentKey,
  unwrapProjectKey as unwrapProjectKeyBytes,
  AES_KEY_LENGTH,
  type Bytes,
} from "@env-vault/crypto";
import {
  getCurrentEnvironmentKey,
  getCurrentProjectKey,
  getEnvironment,
  listProjectKeys,
  type ProjectKeyRow,
  type VaultDatabase,
} from "@env-vault/vault-store";
import { z } from "zod";

/** Machine-readable reason a key operation failed. Never carries key material. */
export const VAULT_KEY_ERROR_CODES = [
  "master_key_missing",
  "master_key_invalid",
  "active_version_invalid",
  "project_missing",
  "project_key_missing",
  "environment_missing",
  "environment_key_missing",
  "unwrap_failed",
] as const;

export type VaultKeyErrorCode = (typeof VAULT_KEY_ERROR_CODES)[number];

/** Thrown by every function in this file. The message never contains key bytes. */
export class VaultKeyError extends Error {
  readonly code: VaultKeyErrorCode;

  constructor(code: VaultKeyErrorCode, message: string) {
    super(message);
    this.name = "VaultKeyError";
    this.code = code;
  }
}

export function isVaultKeyError(error: Error): error is VaultKeyError {
  return error instanceof VaultKeyError;
}

/**
 * The Worker bindings the keyring reads. The generated `Env` satisfies this, and
 * so does a plain object in a test.
 */
export interface MasterKeyEnv {
  readonly VAULT_MASTER_KEY_ACTIVE_VERSION: string;
}

/** Every master key the Worker can read, plus the version that wraps new keys. */
export interface MasterKeyring {
  /** Version used to wrap newly generated project keys. */
  readonly activeVersion: number;
  /** Every version present in the environment, ascending. */
  readonly versions: readonly number[];
  /** The 32-byte key for one version. Throws `VaultKeyError` when absent. */
  key(version: number): Bytes;
}

const MASTER_KEY_BINDING = /^VAULT_MASTER_KEY_V([1-9][0-9]{0,8})$/;

const bindingValueSchema = z.string();
const activeVersionSchema = z.coerce.number().int().min(1);

function decodeMasterKey(name: string, encoded: string): Bytes {
  let bytes: Bytes;
  try {
    bytes = b64uDecode(encoded);
  } catch {
    throw new VaultKeyError("master_key_invalid", `${name} is not valid base64url.`);
  }
  if (bytes.length !== AES_KEY_LENGTH) {
    throw new VaultKeyError("master_key_invalid", `${name} must decode to 32 bytes.`);
  }
  return bytes;
}

class Keyring implements MasterKeyring {
  readonly activeVersion: number;
  readonly versions: readonly number[];
  readonly #keys: ReadonlyMap<number, Bytes>;

  constructor(keys: ReadonlyMap<number, Bytes>, activeVersion: number) {
    this.#keys = keys;
    this.activeVersion = activeVersion;
    this.versions = [...keys.keys()].sort((left, right) => left - right);
  }

  key(version: number): Bytes {
    const key = this.#keys.get(version);
    if (key === undefined) {
      throw new VaultKeyError(
        "master_key_missing",
        `No VAULT_MASTER_KEY_V${version} is configured on this Worker.`,
      );
    }
    return key;
  }
}

/**
 * Read every master key present on the Worker.
 *
 * Throws when no key is configured, when a key is malformed, or when the active
 * version names a key that is not present.
 */
export function loadMasterKeys(env: MasterKeyEnv): MasterKeyring {
  const keys = new Map<number, Bytes>();
  for (const [name, value] of Object.entries(env)) {
    const match = MASTER_KEY_BINDING.exec(name);
    if (match === null) continue;
    const versionText = match[1];
    if (versionText === undefined) continue;
    const parsed = bindingValueSchema.safeParse(value);
    if (!parsed.success) {
      throw new VaultKeyError("master_key_invalid", `${name} must be a string.`);
    }
    keys.set(Number(versionText), decodeMasterKey(name, parsed.data));
  }
  if (keys.size === 0) {
    throw new VaultKeyError(
      "master_key_missing",
      "No VAULT_MASTER_KEY_V<n> secret is configured on this Worker.",
    );
  }
  const activeVersion = activeVersionSchema.safeParse(env.VAULT_MASTER_KEY_ACTIVE_VERSION);
  if (!activeVersion.success) {
    throw new VaultKeyError(
      "active_version_invalid",
      "VAULT_MASTER_KEY_ACTIVE_VERSION must be a positive integer.",
    );
  }
  if (!keys.has(activeVersion.data)) {
    throw new VaultKeyError(
      "master_key_missing",
      `VAULT_MASTER_KEY_ACTIVE_VERSION is ${activeVersion.data} but that key is not configured.`,
    );
  }
  return new Keyring(keys, activeVersion.data);
}

/** A project key in the clear, with the version it was stored under. */
export interface UnwrappedProjectKey {
  readonly projectId: string;
  readonly key: Bytes;
  readonly version: number;
}

/** Unwrap the project key the project currently wraps environment keys with. */
export async function unwrapProjectKey(
  db: VaultDatabase,
  keyring: MasterKeyring,
  projectId: string,
): Promise<UnwrappedProjectKey> {
  const row = await getCurrentProjectKey(db, projectId);
  if (row === null) {
    throw new VaultKeyError("project_key_missing", `Project ${projectId} has no current key.`);
  }
  try {
    const key = await unwrapProjectKeyBytes({
      masterKey: keyring.key(row.masterKeyVersion),
      nonce: b64uDecode(row.nonce),
      ciphertext: b64uDecode(row.wrappedKey),
      projectId,
      projectKeyVersion: row.version,
      masterKeyVersion: row.masterKeyVersion,
    });
    return { projectId, key, version: row.version };
  } catch (error) {
    if (error instanceof VaultKeyError) throw error;
    throw new VaultKeyError(
      "unwrap_failed",
      `Project key ${projectId} v${row.version} did not authenticate.`,
    );
  }
}

/** An environment DEK in the clear, with the versions it was stored under. */
export interface UnwrappedEnvironmentDek {
  readonly projectId: string;
  readonly dek: Bytes;
  readonly version: number;
}

/**
 * Unwrap master -> project -> environment for the current versions of each.
 *
 * Throws `VaultKeyError` when a row is missing or a wrapped key does not
 * authenticate under the identity recorded in its AAD.
 */
export async function unwrapEnvironmentDek(
  db: VaultDatabase,
  keyring: MasterKeyring,
  environmentId: string,
): Promise<UnwrappedEnvironmentDek> {
  const environment = await getEnvironment(db, environmentId);
  if (environment === null) {
    throw new VaultKeyError("environment_missing", `Environment ${environmentId} does not exist.`);
  }
  const keyRow = await getCurrentEnvironmentKey(db, environmentId);
  if (keyRow === null) {
    throw new VaultKeyError(
      "environment_key_missing",
      `Environment ${environmentId} has no current key.`,
    );
  }
  const projectKey = await unwrapProjectKeyVersion(
    db,
    keyring,
    environment.projectId,
    keyRow.projectKeyVersion,
  );
  try {
    const dek = await unwrapEnvironmentKey({
      projectKey,
      nonce: b64uDecode(keyRow.nonce),
      ciphertext: b64uDecode(keyRow.wrappedKey),
      projectId: environment.projectId,
      environmentId,
      environmentKeyVersion: keyRow.version,
      projectKeyVersion: keyRow.projectKeyVersion,
    });
    return { projectId: environment.projectId, dek, version: keyRow.version };
  } catch (error) {
    if (error instanceof VaultKeyError) throw error;
    throw new VaultKeyError(
      "unwrap_failed",
      `Environment key ${environmentId} v${keyRow.version} did not authenticate.`,
    );
  }
}

/**
 * Unwrap one specific project key version.
 *
 * Rotation and any environment key still wrapped under a retired project key
 * need a version other than the project's current one.
 */
export async function unwrapProjectKeyVersion(
  db: VaultDatabase,
  keyring: MasterKeyring,
  projectId: string,
  version: number,
): Promise<Bytes> {
  const current = await getCurrentProjectKey(db, projectId);
  if (current !== null && current.version === version) {
    return (await unwrapProjectKey(db, keyring, projectId)).key;
  }
  const row = await findProjectKeyVersion(db, projectId, version);
  try {
    return await unwrapProjectKeyBytes({
      masterKey: keyring.key(row.masterKeyVersion),
      nonce: b64uDecode(row.nonce),
      ciphertext: b64uDecode(row.wrappedKey),
      projectId,
      projectKeyVersion: row.version,
      masterKeyVersion: row.masterKeyVersion,
    });
  } catch (error) {
    if (error instanceof VaultKeyError) throw error;
    throw new VaultKeyError(
      "unwrap_failed",
      `Project key ${projectId} v${version} did not authenticate.`,
    );
  }
}

async function findProjectKeyVersion(
  db: VaultDatabase,
  projectId: string,
  version: number,
): Promise<ProjectKeyRow> {
  const rows = await listProjectKeys(db, projectId);
  const row = rows.find((candidate) => candidate.version === version);
  if (row === undefined) {
    throw new VaultKeyError(
      "project_key_missing",
      `Project ${projectId} has no key version ${version}.`,
    );
  }
  return row;
}
