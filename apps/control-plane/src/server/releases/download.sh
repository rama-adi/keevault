#!/bin/sh
set -eu

# Keep execution inside a function so a truncated piped response cannot install a binary.
keevault_download() {
  case "$(uname -s)" in
    Linux) ;;
    *) echo 'keevault currently supports Linux only.' >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo 'Unsupported CPU architecture.' >&2; return 1 ;;
  esac
  command -v curl >/dev/null 2>&1 || { echo 'curl is required.' >&2; return 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    hash_tool=sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    hash_tool=shasum
  else
    echo 'sha256sum or shasum is required.' >&2
    return 1
  fi

  latest=__KEEVAULT_LATEST__
  version=${KEEVAULT_VER:-$latest}
  [ "$version" != latest ] || version=$latest
  case "$version:$arch" in
# __KEEVAULT_RELEASES__
    *) echo "No published keevault binary for version '$version' and architecture '$arch'." >&2; return 1 ;;
  esac

  # Stage in the current directory so the final rename stays on the same filesystem.
  temp_dir=$(mktemp -d './.keevault-download.XXXXXXXX')
  trap 'rm -rf "$temp_dir"' EXIT
  trap 'exit 1' HUP INT TERM
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 300 "$url" -o "$temp_dir/keevault"
  if [ "$hash_tool" = sha256sum ]; then
    actual=$(sha256sum "$temp_dir/keevault")
  else
    actual=$(shasum -a 256 "$temp_dir/keevault")
  fi
  actual=${actual%% *}
  if [ "$actual" != "$hash" ]; then
    echo 'SHA-256 mismatch. Existing ./keevault was left unchanged.' >&2
    return 1
  fi
  # Refuse directories and symlinks so mv cannot place the binary inside another directory.
  if [ -d ./keevault ] || [ -L ./keevault ]; then
    echo 'Refusing to replace a directory or symlink at ./keevault.' >&2
    return 1
  fi
  chmod 755 "$temp_dir/keevault"
  mv -f "$temp_dir/keevault" ./keevault
  echo "Downloaded keevault $version for linux/$arch to ./keevault (SHA-256 verified)."
}

keevault_download
