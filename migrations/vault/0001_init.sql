-- keevault D1 vault schema, initial migration (spec section 19).
-- Conventions:
--   ids            TEXT, prefixed ULID (proj_, env_, sec_, tok_, boot_, aud_, pol_, sig_)
--   timestamps     TEXT, RFC 3339 UTC with millisecond precision
--   versions       INTEGER
--   binary values  TEXT, base64url without padding (b64u), same encoding as the wire format
--   booleans       INTEGER 0 or 1
-- No plaintext secret material is stored anywhere in this schema.

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  current_project_key_version INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE project_keys (
  project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  master_key_version INTEGER NOT NULL,
  wrapped_key TEXT NOT NULL,
  nonce TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at TEXT NOT NULL,
  retired_at TEXT,
  PRIMARY KEY (project_id, version)
);

CREATE INDEX project_keys_by_project_status ON project_keys (project_id, status);

CREATE TABLE environments (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  current_env_key_version INTEGER NOT NULL DEFAULT 0,
  provenance_mode TEXT NOT NULL DEFAULT 'ADVISORY'
    CHECK (provenance_mode IN ('OFF', 'ADVISORY', 'REQUIRED')),
  pending_ttl_seconds INTEGER NOT NULL DEFAULT 1800,
  approved_ttl_seconds INTEGER NOT NULL DEFAULT 300,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (project_id, slug)
);

CREATE INDEX environments_by_project ON environments (project_id);

CREATE TABLE environment_keys (
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  project_key_version INTEGER NOT NULL,
  wrapped_key TEXT NOT NULL,
  nonce TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at TEXT NOT NULL,
  retired_at TEXT,
  PRIMARY KEY (environment_id, version)
);

CREATE INDEX environment_keys_by_environment_status ON environment_keys (environment_id, status);

CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  env_key_version INTEGER NOT NULL,
  secret_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (environment_id, name)
);

CREATE INDEX secrets_by_environment ON secrets (environment_id, name);

CREATE TABLE bootstrap_tokens (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  allowed_cidrs_json TEXT NOT NULL DEFAULT '[]',
  max_pending_boots INTEGER NOT NULL DEFAULT 3,
  expires_at TEXT,
  revoked_at TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX bootstrap_tokens_by_environment ON bootstrap_tokens (environment_id);

CREATE TABLE provenance_policies (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  verifier_type TEXT NOT NULL,
  configuration_json TEXT NOT NULL DEFAULT '{}',
  required INTEGER NOT NULL DEFAULT 0 CHECK (required IN (0, 1)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (environment_id, verifier_type)
);

CREATE INDEX provenance_policies_by_environment ON provenance_policies (environment_id, enabled);

CREATE TABLE trusted_signers (
  id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects (id) ON DELETE CASCADE,
  environment_id TEXT REFERENCES environments (id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  label TEXT NOT NULL,
  public_key TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  CHECK (project_id IS NOT NULL OR environment_id IS NOT NULL)
);

CREATE INDEX trusted_signers_by_fingerprint ON trusted_signers (fingerprint);
CREATE INDEX trusted_signers_by_project ON trusted_signers (project_id);
CREATE INDEX trusted_signers_by_environment ON trusted_signers (environment_id);

CREATE TABLE boot_requests (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
  bootstrap_token_id TEXT NOT NULL REFERENCES bootstrap_tokens (id) ON DELETE CASCADE,
  status TEXT NOT NULL
    CHECK (status IN (
      'PENDING',
      'APPROVED',
      'DELIVERED',
      'CONSUMED',
      'DECLINED',
      'EXPIRED',
      'CANCELED'
    )),
  source_ip TEXT,
  signing_public_key TEXT NOT NULL,
  encryption_public_key TEXT NOT NULL,
  claimed_git_repository TEXT,
  claimed_git_commit TEXT,
  claimed_oci_repository TEXT,
  claimed_oci_digest TEXT,
  provenance_summary_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approved_at TEXT,
  approved_by TEXT,
  declined_at TEXT,
  delivered_at TEXT,
  consumed_at TEXT,
  expired_at TEXT,
  canceled_at TEXT
);

CREATE INDEX boot_requests_by_environment_status ON boot_requests (environment_id, status, created_at);
CREATE INDEX boot_requests_by_environment_recent ON boot_requests (environment_id, created_at);
CREATE INDEX boot_requests_by_token_status ON boot_requests (bootstrap_token_id, status);

CREATE TABLE boot_approvals (
  boot_id TEXT PRIMARY KEY REFERENCES boot_requests (id) ON DELETE CASCADE,
  approver_user_id TEXT NOT NULL,
  approver_credential_id TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  client_signing_fingerprint TEXT NOT NULL,
  client_encryption_fingerprint TEXT NOT NULL,
  evidence_digest TEXT NOT NULL
);

CREATE INDEX boot_approvals_by_approver ON boot_approvals (approver_user_id, approved_at);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  project_id TEXT REFERENCES projects (id) ON DELETE SET NULL,
  environment_id TEXT REFERENCES environments (id) ON DELETE SET NULL,
  boot_id TEXT REFERENCES boot_requests (id) ON DELETE SET NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_events_by_project ON audit_events (project_id, id);
CREATE INDEX audit_events_by_environment ON audit_events (environment_id, id);
CREATE INDEX audit_events_by_boot ON audit_events (boot_id, id);
CREATE INDEX audit_events_by_timestamp ON audit_events (timestamp);
