CREATE TABLE binary_releases (
  id TEXT PRIMARY KEY NOT NULL,
  version TEXT NOT NULL,
  arch TEXT NOT NULL CHECK (arch IN ('amd64', 'arm64')),
  hash TEXT NOT NULL CHECK (length(hash) = 64),
  createdat TEXT NOT NULL,
  url TEXT NOT NULL,
  UNIQUE (version, arch)
);
