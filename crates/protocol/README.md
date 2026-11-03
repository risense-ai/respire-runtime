# crates/protocol

Placeholder for the `respire-protocol` crate, migrated from
`respire-cli/crates/protocol` with history in phase P2.

This crate is the single RPC contract shared by `respire-runtime` (server) and
`respire-cli` (client), published to crates.io as `respire-protocol`. Its crate
version moves in lockstep with `PROTOCOL_V`, which remains a hard gate on both
sides (`protocol_version_mismatch` on any mismatch).

Rules:

- Contract changes land here first, are published to crates.io, and only then
  do consumer PRs merge (see docs/version-contract.md).
- Keep the crate pure: types and wire contracts, no I/O, no server behavior.
