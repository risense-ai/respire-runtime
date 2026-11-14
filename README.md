# Respire Runtime

Source of truth for the standalone Respire runtime (`rsrs-runtime`) and the only
repository that links the closed-source Respire Core. The managed runtime released
here is consumed by `respire-cli` (which discovers, downloads and supervises it)
and by `respire-client2` (which shares the same managed layout and download rules).

Boundary in one sentence: **runtime = core capability + RPC; the CLI or Client2
owns downloads, installation, component management and persistent private keys.**

Core capabilities include account authentication, synchronization, database
management, recall and remember. A serving Runtime never accesses the OS
credential store. After restart it reports `credential_state: "required"` and
`store_ready: false`, keeps the library closed, and pauses indexing and sync.
The host reads the existing system credentials and submits them to
`POST /api/runtime/unlock`. This loopback endpoint requires the host bearer
token and binds the request to the exact profile, session revision, Runtime
instance and generation. Keys remain in process memory and are cleared at exit.

The CLI supplies credentials during startup and through `rsrs runtime unlock`.
Client2 requests the same CLI operation when an existing Runtime needs its key.
Other hosts can implement this protocol without adopting either frontend.
Private account-control helpers use the inherited framed channel to request
credential custody from their host; they never load a native credential backend.
These exchanges keep the existing transaction checkpoints and parent lifetime
checks, including confirmation before encrypted account state is committed.

## Status

This repository is a bootstrap skeleton (phase P2 of the CLI/runtime split).
Directories contain placeholder READMEs; the real crates are migrated with
history via `git subtree` in P2. CI and release workflows are already complete
and will start producing artifacts as soon as the workspace lands.

## Layout

| Path | Purpose |
| --- | --- |
| `runtime/` | `rsrs-runtime` binary crate: serve/dispatch/admission, loopback HTTP, MCP endpoints, health, sync worker, snapshot apply |
| `crates/protocol/` | `respire-protocol` RPC contract crate, published to crates.io; the shared contract of this repo and `respire-cli` |
| `crates/core-sdk/` | Closed-source Core bindings (`respire-core-sdk`), SDK locks and the pinned SDK download/prepare tooling |
| `crates/app-domain/` | Domain services: memory engine, sync worker, resident recall, snapshot, diary, review, embedding contracts |
| `crates/storage/` | Encrypted storage layer |
| `crates/crypto/` | Cryptography primitives |
| `sdk/` | Outward-facing binding crate (migrated together with `crates/core-sdk`) |
| `scripts/` | Release, SDK cache and pin tooling (adapted from `respire-cli`) |
| `docs/` | Release process, version/compatibility contract, repository map |

## Release

Push an unused `vX.Y.Z` (stable) or `vX.Y.Z-dev.N` (developer preview) tag on a
reviewed `main` commit. The Release workflow builds all seven platform targets,
runs the full native regression matrix and publishes:

- `rsrs-runtime-<triple>` (raw binary, `.exe` on Windows)
- `rsrs-runtime-<triple>.tar.gz` (binary + `core-runtime.json` manifest + native Core runtime libraries and notices)
- `runtime-build-<triple>.json` (version, tag, triple, SHA-256 digests and CLI compatibility range)

See [docs/releasing.md](docs/releasing.md) for the full process and
[docs/version-contract.md](docs/version-contract.md) for how the CLI consumes
`runtime_version`, `runtime-pin.json` and the health-body compatibility fields.

Release ordering rule: **the runtime repository releases first; the CLI releases
second** and its pin may only point at an existing runtime release.

## Building from source

Use the pinned Rust toolchain and a Core SDK matching your target and
`sdk/core-sdk.lock.json` (the lock files arrive with the P2 migration):

```sh
export RSRS_CORE_SDK_DIR=/path/to/sdk
node scripts/fetch-core-sdk.mjs <rust-target>
cargo build --locked --release -p respire-runtime --bin rsrs-runtime
node scripts/stage-core-runtime.mjs target/release
```

On PowerShell, set `$env:RSRS_CORE_SDK_DIR`. The staged runtime libraries and
notices must ship next to the binary; release packaging does this automatically.
The runtime binary never downloads models or assets on its own; missing assets
are reported through `health` and `assets.status`, and the CLI installs them.
Model verification, switching and background indexing only inspect installed assets.
The business command parser contains no installer, uninstaller, startup
registration, plugin-management, injection or CLI-update commands. Asset
requirements and verification remain read-only RPC capabilities; the host owns
the actual file changes. Host directory migration never runs before business RPC.

## Runtime surface (unchanged from the combined binary)

- Loopback HTTP on `127.0.0.1:15169`, token-free on loopback, `RSRS_RPC_TOKEN` otherwise
- `/mcp` and `/sse` endpoints, `cli.exec` dispatch, health endpoint
- `RSRS_RUNTIME_BOOT_TOKEN` handoff via the CLI-side spawn infrastructure

## License

Repository code follows the license of the runtime sources after migration.
Distributed runtime binaries bundle the closed-source Core SDK under
[BINARY-LICENSE.txt](BINARY-LICENSE.txt); packaging must keep that license and
all third-party notices inside every artifact.
