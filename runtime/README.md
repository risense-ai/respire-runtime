# rsrs-runtime

Standalone loopback runtime binary for respire (runtime split WP-3, milestone
M1 "two runnable binaries"). It hosts the same authenticated loopback HTTP
surface the CLI used to embed (`/api/health`, `/api/rpc`, `/api/runtime/stop`,
`/mcp`), driven by the shared `respire_commands::rpc_serve` module.

## Build

```sh
cargo build -p respire_runtime
```

The binary is `target/debug/rsrs-runtime` (`publish = false`; released builds
are cut from the dedicated runtime repository, not this workspace).

## Run

```sh
rsrs-runtime serve [--host 127.0.0.1] [--port 15169] [--data-dir DIR] [--supervised]
rsrs-runtime --version
```

The CLI or Client2 starts this foreground service and owns sign-in startup,
background execution, supervision and restart. Use the host's `rsrs runtime`
commands for lifecycle operations. Runtime does not detach or launch itself.
It accepts host-provided credentials in memory; an encrypted library remains
locked until the host delivers its key material.

## Identity and health

At startup the binary publishes its `RuntimeIdentity`
(`runtime_version` = this crate's version, compat window `min_cli = 1.0.20`,
`max_cli = *`) through `respire_commands::rpc_serve::set_runtime_identity`.
The `/api/health` body carries the extension under the `runtime` key plus a
flattened `runtime_version`, so older CLI builds keep working additively.

`RSRS_RUNTIME_BOOT_TOKEN` is consumed with `respire_spawn` semantics: read
once, then removed from the environment. Runtime verifies each host launch grant against its profile and process identity.
The CLI owns the registration, maintenance fence and supervisor.

## Status

`assets.status` RPC inspects the required model files with their pinned sizes
and SHA-256 digests. Each asset reports `missing`, `incomplete`, `corrupt`,
`incompatible`, or `complete`; the aggregate `complete` field is true only when
every required asset is complete. Missing assets are installed by the CLI or
Client2; Runtime only reports and uses their verified installed bytes.
