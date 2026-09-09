#!/usr/bin/env bash
# Produce static Linux binaries and a checksum manifest without publishing.
set -euo pipefail
cd "$(dirname "$0")/../apps/env-client"
bash build.sh
cd dist
if command -v sha256sum >/dev/null; then
  sha256sum keevault-linux-amd64 keevault-linux-arm64 > SHA256SUMS
else
  shasum -a 256 keevault-linux-amd64 keevault-linux-arm64 > SHA256SUMS
fi
