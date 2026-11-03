# runtime/

Placeholder for the `respire-runtime` binary crate (bin target `rsrs-runtime`),
migrated from `respire-cli` with history via `git subtree` in phase P2.

Scope after migration:

- `serve` entry point: loopback HTTP (default `127.0.0.1:15169`), admission,
  job worker threads, dispatch (single source of truth for RPC dispatch)
- `/mcp` and `/sse` endpoints, health endpoint with `runtime_version` and
  `runtime_compat` fields
- Sync worker, snapshot application, resident recall, review service surface
- RPC dispatch for `cli.exec` and related methods

The runtime binary contains no download, installation, registration or
configuration-write logic; assets are consumed read-only and missing assets are
reported to the CLI (see the repository README and AGENTS.md).
