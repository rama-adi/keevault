#!/usr/bin/env bash
# Build static keevault binaries for linux/amd64 and linux/arm64.
set -euo pipefail

cd "$(dirname "$0")"

DIST="dist"
MAX_BYTES=$((15 * 1024 * 1024))
CLIENT_VERSION="${RELEASE_VERSION:-dev}"
if [[ "$CLIENT_VERSION" != dev && ! "$CLIENT_VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
  echo 'error: RELEASE_VERSION must be dev or a version such as v1.0.0' >&2
  exit 1
fi
if [ "${#CLIENT_VERSION}" -gt 64 ]; then
  echo 'error: RELEASE_VERSION must be at most 64 characters' >&2
  exit 1
fi

rm -rf "$DIST"
mkdir -p "$DIST"

for target in linux/amd64 linux/arm64; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  out="$DIST/keevault-$goos-$goarch"
  echo "building $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w -X github.com/ramaadi/keevault/apps/env-client/internal/client.Version=$CLIENT_VERSION" -o "$out" .
done

status=0
for binary in "$DIST"/*; do
  size=$(wc -c <"$binary" | tr -d ' ')
  printf '%s %s bytes\n' "$binary" "$size"
  if [ "$size" -gt "$MAX_BYTES" ]; then
    echo "error: $binary is larger than 15 MiB" >&2
    status=1
  fi
done
exit "$status"
