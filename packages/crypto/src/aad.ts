/**
 * Canonical additional-authenticated-data and HKDF info strings.
 *
 * Every string here is UTF-8, lines joined with "\n", no trailing newline and no CR.
 * Integers are decimal without leading zeros.
 */

/** Render an integer for a canonical string. Rejects anything that is not a non-negative safe integer. */
export function canonicalInteger(value: number): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("canonical integer must be a non-negative safe integer");
  }
  return String(value);
}

export interface ProjectKeyAadInput {
  readonly projectId: string;
  readonly projectKeyVersion: number;
  readonly masterKeyVersion: number;
}

/** AAD for wrapping a project key under a master key. */
export function projectKeyAad(input: ProjectKeyAadInput): string {
  return [
    "vault:project-key:v1",
    `project=${input.projectId}`,
    `version=${canonicalInteger(input.projectKeyVersion)}`,
    `master=${canonicalInteger(input.masterKeyVersion)}`,
  ].join("\n");
}

export interface EnvironmentKeyAadInput {
  readonly projectId: string;
  readonly environmentId: string;
  readonly environmentKeyVersion: number;
  readonly projectKeyVersion: number;
}

/** AAD for wrapping an environment key under a project key. */
export function environmentKeyAad(input: EnvironmentKeyAadInput): string {
  return [
    "vault:environment-key:v1",
    `project=${input.projectId}`,
    `environment=${input.environmentId}`,
    `version=${canonicalInteger(input.environmentKeyVersion)}`,
    `project_key_version=${canonicalInteger(input.projectKeyVersion)}`,
  ].join("\n");
}

export interface SecretValueAadInput {
  readonly projectId: string;
  readonly environmentId: string;
  readonly secretId: string;
  readonly secretName: string;
  readonly secretVersion: number;
  readonly environmentKeyVersion: number;
}

/** AAD for a single secret value encrypted under an environment key. */
export function secretValueAad(input: SecretValueAadInput): string {
  return [
    "vault:secret:v1",
    `project=${input.projectId}`,
    `environment=${input.environmentId}`,
    `secret=${input.secretId}`,
    `name=${input.secretName}`,
    `version=${canonicalInteger(input.secretVersion)}`,
    `env_key_version=${canonicalInteger(input.environmentKeyVersion)}`,
  ].join("\n");
}

export interface BootEnvelopeInfoInput {
  readonly bootId: string;
  readonly environmentId: string;
  readonly environmentKeyVersion: number;
  readonly clientPublicKeyFingerprint: string;
  readonly serverPublicKeyFingerprint: string;
}

/** HKDF info, and AES-GCM AAD, for one boot key envelope. */
export function bootEnvelopeInfo(input: BootEnvelopeInfoInput): string {
  return [
    "vault:boot-envelope:v1",
    `boot=${input.bootId}`,
    `environment=${input.environmentId}`,
    `env_key_version=${canonicalInteger(input.environmentKeyVersion)}`,
    `client=${input.clientPublicKeyFingerprint}`,
    `server=${input.serverPublicKeyFingerprint}`,
  ].join("\n");
}
