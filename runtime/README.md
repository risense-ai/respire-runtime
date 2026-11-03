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
rsrs-runtime --json runtime start     # same as serve, prints a start envelope
rsrs-runtime [--json] runtime stop    # or --stop: drain + stop the resident runtime
rsrs-runtime --status                 # health probe
rsrs-runtime --version
```

Unknown arguments exit with code 2. `runtime start|stop|status` (with or
without a leading `--json`) is the client2 lifecycle contract; do not change
those shapes without updating the coordinator.

## Identity and health

At startup the binary publishes its `RuntimeIdentity`
(`runtime_version` = this crate's version, compat window `min_cli = 1.0.20`,
`max_cli = *`) through `respire_commands::rpc_serve::set_runtime_identity`.
The `/api/health` body carries the extension under the `runtime` key plus a
flattened `runtime_version`, so older CLI builds keep working additively.

`RSRS_RUNTIME_BOOT_TOKEN` is consumed with `respire_spawn` semantics: read
once, then removed from the environment. Managed-boot verification (the
host-side registration/maintenance fence) remains host-managed through
`host_hooks` until the supervisor moves into this crate (P2).

## Status

`assets.status` RPC reports a stub (`complete: true`, nothing missing) because
the host guarantees asset placement in this train; real inventory lands with
P4. Boot-token/registration verification, the supervisor and the CI release
wiring are P2 work.
