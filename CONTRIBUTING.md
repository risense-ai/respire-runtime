# Contributing

English only. Keep one issue or PR focused on one problem; search existing
issues/PRs and link related work before opening a duplicate.

## Issues

Use the bug or feature form. Give a minimal reproduction with synthetic data,
expected/actual behavior and the relevant versions/platform. For runtime
reports include: exact sanitized commands and exit codes/JSON error reasons,
`runtime_version` and CLI version, install entry, OS/architecture and Linux
libc if known. Performance reports need workload, model/engine, background
activity, concurrent requests and measured memory/latency.

## Pull requests

Use a small branch against `main`. Explain the problem and resulting behavior,
link related issues (use `Fixes #...` only when fully resolved), and include
CI results on the exact head commit. Mark checks N/A with a reason when
irrelevant; say explicitly when CI or platform tests did not run or were
skipped.

Preserve RPC method surfaces, JSON/MCP/HTTP contracts, stored data formats,
`PROTOCOL_V` semantics, the runtime boundary described in
[AGENTS.md](AGENTS.md), and third-party notices. Explain compatibility,
migration and rollback for any affected boundary. Follow the protocol-first
and runtime-first release rules in [docs/version-contract.md](docs/version-contract.md).

## Validation

Heavy Rust builds and native regressions run in CI; do not use local builds as
evidence (see [AGENTS.md](AGENTS.md)). Use isolated test data. Documentation
and template-only changes can use syntax, path/link and diff review; state
explicitly if product tests were not run. Do not dispatch publishing workflows
for contribution-only changes.

## Private data and security

Search existing issues first. Never post passwords, API keys/tokens,
databases/backups, private memories, account identifiers or unredacted
logs/screenshots.

Security vulnerabilities: do not disclose details in a public Issue or PR.
Check this repository's Security tab for a private reporting option; if none
is offered, ask maintainers to establish a private channel without including
vulnerability details.
