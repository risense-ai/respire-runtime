#!/usr/bin/env bash
set -euo pipefail
target="${1:?pass target}"
binary="${2:?pass binary}"
case "$target" in
  aarch64-unknown-linux-gnu|aarch64-unknown-linux-musl)
    bash "$(dirname "$0")/require-native-linux-arm64.sh" "$target"
    readelf -h "$binary" | grep -Eq 'Machine: +AArch64'
    if [[ "$target" == *-gnu ]]; then
      readelf -l "$binary" | grep -q INTERP
      dependencies="$(ldd "$binary")"
      printf '%s\n' "$dependencies"
      if grep -q 'not found' <<<"$dependencies"; then exit 1; fi
    else
      if readelf -l "$binary" | grep -q INTERP; then exit 1; fi
      if readelf -d "$binary" | grep -q NEEDED; then exit 1; fi
      # Native ARM Docker/Alpine, without QEMU setup or a platform override.
      docker run --rm -v "$(realpath "$binary"):/rsrs:ro" alpine:3.23 sh -ec 'test "$(uname -m)" = aarch64; /rsrs --version'
    fi
    ;;
esac
