#!/usr/bin/env bash
# Run on a Linux host of the target architecture with Docker installed.
set -euo pipefail

target="${1:?pass the Rust musl target}"
case "$target:$(uname -m)" in
  x86_64-unknown-linux-musl:x86_64|aarch64-unknown-linux-musl:aarch64) ;;
  *) echo "unsupported target/host: $target/$(uname -m)" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/target/musl-cache/$target"
action="${2:-build}"
case "$action" in build|key|pack) ;; *) echo 'invalid release cache action' >&2; exit 1 ;; esac
image=rust:1.95.0-alpine3.23
if ! docker image inspect "$image" >/dev/null 2>&1; then docker pull "$image"; fi
image="$(docker image inspect "$image" --format '{{.Id}}')"
docker run --rm \
  -v "$root:/workspace" -w /workspace \
  -e TARGET="$target" -e RELEASE_CACHE_ACTION="$action" \
  -e RELEASE_DEPENDENCY_CACHE="${RELEASE_DEPENDENCY_CACHE:-}" \
  -e GITHUB_SHA -e GITHUB_RUN_ID -e GITHUB_RUN_ATTEMPT \
  -e RELEASE_CONTAINER_IMAGE="$image" -e GITHUB_OUTPUT=/workspace/.rust-release-output \
  "$image" sh scripts/build-linux-musl-container.sh
if [ "$action" = key ]; then
  cat "$root/.rust-release-output" >> "${GITHUB_OUTPUT:?release key requires GITHUB_OUTPUT}"
fi
if [ "$action" != build ]; then exit 0; fi

binary="$root/target/ci/$target/release/rsrs"
# A static ELF must have neither a dynamic loader nor shared-library imports.
if readelf -l "$binary" | grep -q INTERP; then
  echo 'musl binary unexpectedly requires an ELF interpreter' >&2
  exit 1
fi
if readelf -d "$binary" | grep -q NEEDED; then
  echo 'musl binary unexpectedly requires shared libraries' >&2
  exit 1
fi
"$binary" --version
# Exercise the same artifact on a musl userspace as well as the Ubuntu host.
docker run --rm -v "$binary:/rsrs:ro" alpine:3.23 /rsrs --version
