#!/usr/bin/env bash
# Build static keevault binaries for linux/amd64 and linux/arm64.
set -euo pipefail

cd "$(dirname "$0")"

DIST="dist"
MAX_BYTES=$((15 * 1024 * 1024))

rm -rf "$DIST"
mkdir -p "$DIST"

for target in linux/amd64 linux/arm64; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  out="$DIST/keevault-$goos-$goarch"
  echo "building $out"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w" -o "$out" .
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
