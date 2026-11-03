# crates/app-domain

Placeholder for the domain-service crate, migrated from the server-side half of
`respire-cli/crates/app` with history in phase P2.

Scope after migration (per the split plan, section 3.3): service, memory engine
wrappers, sync worker, resident recall, snapshot application, diary, review
server surface, embedding contracts, read heat, feedback contracts.

The client-side half (`app-client`: auth/keystore/prompt/session import/
transport/login transaction) stays in `respire-cli`. Per-file ownership was
fixed in the P0 audit; modules referenced from both sides are cut at the RPC
boundary. Do not reintroduce direct library calls from the CLI into this crate.
