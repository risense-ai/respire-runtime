#!/usr/bin/env bash
# ARM platform acceptance must execute on real ARM Linux, never emulation.
set -euo pipefail
target="${1:?pass the exact Rust target}"
case "$target" in
  aarch64-unknown-linux-gnu|aarch64-unknown-linux-musl)
    test "$(uname -s)" = Linux
    test "$(uname -m)" = aarch64
    test "${RUNNER_ARCH:-ARM64}" = ARM64
    ;;
esac
