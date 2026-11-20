# Automatic releases

Push an unused DEV tag that matches `runtime/Cargo.toml` and `Cargo.lock` at a
reviewed commit on `main`:

```sh
git tag v1.4.0-dev.1 <reviewed-main-commit>
git push origin v1.4.0-dev.1
```

CI verifies that the tag matches the Runtime source version. DEV releases
publish as prereleases. The stable publication path requires separate
authorization.

Manual `workflow_dispatch` remains available: pass `ref` (branch, commit or
tag), `publish`, and for non-tag sources the exact `dev_version`
(`X.Y.Z-dev.N`). Use `publish=false` for candidate builds and native validation.

## What the Release workflow produces

Per platform triple (eight targets: `x86_64`/`aarch64` Linux glibc and musl,
`x86_64-apple-darwin`/`aarch64-apple-darwin`, `x86_64`/`aarch64` Windows MSVC):

| Asset | Content |
| --- | --- |
| `rsrs-runtime-<triple>` / `.exe` | raw binary |
| `rsrs-runtime-<triple>.tar.gz` | triple-qualified binary + `core-runtime.json` manifest + native Core runtime libraries (onnxruntime / DirectML / metallib, staged from the Core SDK by the `crates/core-sdk` tooling) + notices |
| `runtime-build-<triple>.json` | Schema-2 identity, `archive_sha256`, `binary_sha256`, source commit, protocol range, capabilities, and per-file integrity manifest |

Consumers map legacy schema 1 by reading `sha256` as `archive_sha256` and
`triple` as `target_triple`; conflicting aliases are rejected.

Exactly 24 assets per release (three per platform). The tarball extracts to a
 flat layout: the triple-qualified binary sits at the archive root next to `core-runtime.json`
and the `runtime/` libraries, matching the managed directory layout that
`respire-cli` and `respire-client2` both use (`<installation_root>/runtime/<ver>/`).

## Gate sequence

1. `plan`: tag and source version validation,
   main-ancestry check for published sources.
2. `build` (8-platform matrix): pinned Core SDK from the exact cache,
   release build, SDK staging, archive assembly, SHA-256 computation,
   `runtime-build` metadata generation. Windows ARM64 and Linux ARM64 run on
   native ARM hardware runners only.
3. `native-regression` (8-platform matrix): digest verification of the actual
   artifacts, then a real serve/health/stop smoke of the built binary with the
   Runtime identity and protocol checks. After the P2
   migration this job additionally carries the full inference, migration and
   startup-supervision regression suites moved from `respire-cli`.
4. `publish`: inventory and digest re-verification of all 24 assets, draft
   release creation, upload, then publication.

Tag CI runs in its own concurrency group; publication is serialized repo-wide.

## Independent consumers

Hosts discover Runtime releases on their selected channel, verify the artifact
digests, and use the published [protocol contract](version-contract.md).
Each product publishes on its own schedule.

## Version increments

Every user-visible runtime change set bumps the patch version and ships as a
new tag. DEV previews use `vX.Y.Z-dev.N`.
