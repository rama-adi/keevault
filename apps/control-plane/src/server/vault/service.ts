/**
 * The vault service surface.
 *
 * Every dashboard mutation goes through one of these functions, so the audit
 * event and the key handling for an operation live next to the write itself.
 * Callers pass a `VaultContext` built from the Worker bindings and the signed-in
 * operator.
 */

export { systemClock, type BootSessionControl, type VaultContext } from "./context.ts";
export {
  auditMetadataJson,
  AUDIT_ACTIONS,
  type AuditAction,
  type AuditActor,
  type AuditMetadata,
  type AuditMetadataValue,
} from "./audit.ts";
export { listAuditEvents, type AuditEventView, type AuditPage } from "./audit-log.ts";
export { parseDotenv, type DotenvEntry, type DotenvParseResult } from "./dotenv.ts";
export {
  isVaultKeyError,
  loadMasterKeys,
  unwrapEnvironmentDek,
  unwrapProjectKey,
  unwrapProjectKeyVersion,
  VaultKeyError,
  type MasterKeyring,
  type VaultKeyErrorCode,
} from "./keys.ts";
export {
  createEnvironment,
  createProject,
  deleteEnvironment,
  deleteProject,
  getEnvironmentSummary,
  getProject,
  listEnvironments,
  listProjects,
  setEnvironmentPolicy,
  DEFAULT_APPROVED_TTL_SECONDS,
  DEFAULT_PENDING_TTL_SECONDS,
  ENVIRONMENT_DELETED_REASON,
  PROJECT_DELETED_REASON,
} from "./projects.ts";
export { rotateEnvironmentKey, rotateProjectKey } from "./rotation.ts";
export {
  deleteSecret,
  importDotenv,
  listSecretsMetadata,
  putSecret,
  type ImportDotenvResult,
  type PutSecretResult,
} from "./secrets.ts";
export {
  addTrustedSigner,
  listTrustedSigners,
  revokeTrustedSigner,
  SIGNER_TYPE_ED25519,
} from "./signers.ts";
export {
  createBootstrapToken,
  listBootstrapTokens,
  revokeBootstrapToken,
  updateTokenCidrs,
  DEFAULT_MAX_PENDING_BOOTS,
  TOKEN_REVOKED_REASON,
  type CreatedBootstrapToken,
} from "./tokens.ts";
export {
  toBootstrapTokenSummary,
  toEnvironmentSummary,
  toProjectSummary,
  toSecretSummary,
  toTrustedSignerSummary,
  type BootstrapTokenSummary,
  type EnvironmentSummary,
  type ProjectSummary,
  type SecretSummary,
  type TrustedSignerSummary,
} from "./types.ts";
export { isVaultInputError, VaultInputError } from "./validation.ts";
