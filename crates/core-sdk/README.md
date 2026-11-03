# crates/core-sdk

Placeholder for the closed-source Core binding crate (`respire-core-sdk`),
migrated from `respire-cli/crates/core-sdk` with history in phase P2.

Contents after migration:

- `build.rs` + `prepare-sdk.mjs`: resolves the pinned SDK from
  `RSRS_CORE_SDK_DIR` (or `sdk/core-sdk.lock.json`), verifies every file hash
  and stages headers/libraries/runtime assets; the native runtime libraries
  distributed in release archives are copied by this mechanism.
- `core-sdk.lock.json`: exact per-target SDK pins (kept equal to the root
  `sdk/core-sdk.lock.json`; both are updated together).
- `private-sdk-download.mjs`: credential-isolated reader for private SDK
  releases (`CORE_SDK_READ_TOKEN`, trusted main-branch job only).

The closed-source Core itself lives in `risense-ai/respire-core`; this crate
only links and stages it. Redistribution of the Core SDK binaries happens only
under [BINARY-LICENSE.txt](../../BINARY-LICENSE.txt), which must remain bundled
with every distributed runtime artifact.
