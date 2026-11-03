# sdk/

Placeholder for the outward-facing binding crate, migrated together with
`crates/core-sdk` in phase P2.

The binding exposes the minimal public surface for embedding consumers; its
native payloads are never bundled in the crate itself. Publication of SDK
binary assets remains owned by `risense-ai/respire-core`; registry publication
of this crate follows the same protocol-first rules as `crates/protocol`.
