# Repository map

The Respire product spans several repositories. After the CLI/runtime split
this repository is the Core-linked source of truth.

| Repository | Role |
| --- | --- |
| `risense-ai/respire-runtime` (this repo) | `rsrs-runtime` binary, RPC server, closed-source Core link, `respire-protocol` publication, 7-platform native regression and release |
| `risense-ai/respire-cli` | `rsrs` CLI/TUI, asset installation (models, engines), runtime discovery/download/supervision, autostart registration, host account RPC; consumes `respire-protocol` from crates.io and pins a runtime release |
| `risense-ai/respire-core` | Closed-source Core SDK builds; publishes per-target SDK archives (`sdk-v*` tags) that this repository pins and links |
| `risense-ai/respire-client2` | Wails desktop client; shares the managed runtime directory and download/verify rules, downloads runtime assets from this repository's releases |
| `risense-ai/respire-docs` | Product documentation |

Boundaries in one sentence each:

- Repository = build product = authorization surface: only this repository
  links the closed-source Core; `respire-cli` has no Core link, no
  private-sdk-cache and no native regression matrix.
- runtime = core capability + RPC; every install, download, registration and
  configuration entry point lives in the CLI.

## Cross-repository pins

- `respire-core/.github/workflows/sdk-link.yml` validates its GNU SDK through
  a fixed consumer pinned at `risense-ai/respire-cli@406399841208bf865d8f40c72dbbf6450fb3a44b`.
  After the P2 migration lands, replace that pin with a consumer commit from
  this repository (comment also recorded in `release.yml` next to the SDK
  cache restore step).
- `respire-cli` consumes `runtime-build-<triple>.json` and `runtime-pin.json`
  (generated here via `scripts/update-cli-pin.mjs`).
- `respire-client2` consumes the same release assets from this repository
  with `runtime_version` as the version authority.

## Required CI/release configuration (repository settings)

The following must exist before the first real release. The bootstrap
(skeleton) phase ships the workflows but not these settings:

| Item | Where | Purpose |
| --- | --- | --- |
| `CARGO_REGISTRY_TOKEN` secret | Actions secrets | `publish-crates.yml` publishes `respire-protocol` to crates.io |
| `CORE_SDK_READ_TOKEN` secret | Actions secrets | `private-sdk-cache.yml` trusted download job reads private `respire-core` SDK releases (Contents:read on respire-core only; used exclusively in the isolated job) |
| Release signing/publishing credentials | Actions permissions | `release.yml` `publish` job needs `contents: write` (uses the default `GITHUB_TOKEN`; no PAT required unless org policy says otherwise) |
| `ubuntu-24.04-arm` runner access | Org/runner settings | Native Linux ARM64 builds and regression (`aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`) |
| `windows-11-arm` runner access | Org/runner settings | Native Windows ARM64 build and regression (`aarch64-pc-windows-msvc`); emulation is never accepted |
| Approved development server allowlist | Org/network policy | Any runtime regression that later needs the dev environment; the current runtime smoke is local-only, but the migrated CLI-era suites may reference `RESPIRE_DEV_SERVER_ADDR`-style allowlisted hosts after P2 |

Migration note: the dev-server variable names and allowlist entries are
inherited from `respire-cli` repository/organization variables when the
regression suites move in P2; copy, do not share, them.

## Migrated-in P2 (planned)

`runtime/`, `crates/{protocol,core-sdk,app-domain,storage,crypto}`, `sdk/`,
the two SDK lock files (`sdk/core-sdk.lock.json`,
`crates/core-sdk/core-sdk.lock.json`), `docs/model-notices/` and
`docs/dependency-notices/` arrive via `git subtree` with history. The
workflows and scripts in this repository are already written against that
final layout; phase-P2 gates inside the workflows (workspace existence
checks) keep them inert until then.
