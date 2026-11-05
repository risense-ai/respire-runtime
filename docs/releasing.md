# Automatic releases

Push an unused release tag pointing to a reviewed commit on `main`:

```sh
git tag v1.4.0-dev.1 <reviewed-main-commit>
git push origin v1.4.0-dev.1
# Stable uses the same automatic workflow, for example v1.4.0.
```

DEV tags determine the binary version; CI prepares the matching ephemeral
Cargo version. Stable tags require the runtime source version to match first.
DEV releases publish as prereleases; stable releases are the pinned versions
consumed by the CLI.

Manual `workflow_dispatch` remains available: pass `ref` (branch, commit or
tag), `publish`, and for non-tag sources the exact `dev_version`
(`X.Y.Z-dev.N`). A stable tag always publishes.

## What the Release workflow produces

Per platform triple (seven targets: `x86_64`/`aarch64` Linux glibc and musl,
`aarch64-apple-darwin`, `x86_64`/`aarch64` Windows MSVC):

| Asset | Content |
| --- | --- |
| `rsrs-runtime-<triple>` / `.exe` | raw binary |
| `rsrs-runtime-<triple>.tar.gz` | triple-qualified binary + `core-runtime.json` manifest + native Core runtime libraries (onnxruntime / DirectML / metallib, staged from the Core SDK by the `crates/core-sdk` tooling) + notices |
| `runtime-build-<triple>.json` | Schema-2 identity, `archive_sha256`, `binary_sha256`, source commit, protocol range, capabilities, and per-file integrity manifest |

Consumers map legacy schema 1 by reading `sha256` as `archive_sha256` and
`triple` as `target_triple`; conflicting aliases are rejected.

Exactly 21 assets per release (three per platform). The tarball extracts to a
 flat layout: the triple-qualified binary sits at the archive root next to `core-runtime.json`
and the `runtime/` libraries, matching the managed directory layout that
`respire-cli` and `respire-client2` both use (`<installation_root>/runtime/<ver>/`).

## Gate sequence

1. `plan`: tag/version validation (stable tag must match the source version),
   main-ancestry check for published sources.
2. `build` (7-platform matrix): pinned Core SDK from the exact cache,
   release build, SDK staging, archive assembly, SHA-256 computation,
   `runtime-build` metadata generation. Windows ARM64 and Linux ARM64 run on
   native ARM hardware runners only.
3. `native-regression` (7-platform matrix): digest verification of the actual
   artifacts, then a real serve/health/stop smoke of the built binary with the
   `runtime_version` and `runtime_compat` contract checks. After the P2
   migration this job additionally carries the full inference, migration and
   startup-supervision regression suites moved from `respire-cli`.
4. `publish`: inventory and digest re-verification of all 21 assets, draft
   release creation, upload, then publication.

Tag CI runs in its own concurrency group; publication is serialized repo-wide.

## Downstream consumption order

1. This repository publishes `vX.Y.Z` (see docs/version-contract.md for the
   iron rule: runtime first).
2. Generate and merge the CLI pin update PR:
   `node scripts/update-cli-pin.mjs X.Y.Z --from-builds <downloaded assets>`
   produces `runtime-pin.json` and the PR text for `risense-ai/respire-cli`.
3. Cut the CLI release; its pin now points at an existing runtime release.
4. `respire-client2` reads `runtime-build-<triple>.json` (`runtime_version`)
   and downloads `rsrs-runtime-<triple>.tar.gz` from this repository's
   releases, verifying SHA-256 before install.

## Version increments

Every user-visible runtime change set bumps the patch version and ships as a
new tag; dev previews use `vX.Y.Z-dev.N` and never update the CLI pin.
