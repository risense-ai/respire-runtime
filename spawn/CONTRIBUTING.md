# Contributing

English only. Keep one issue or PR focused on one problem; search existing issues/PRs and link related work before opening a duplicate.

## Issues

Use the bug or feature form. Installation and performance problems fit the bug form; fill conditional fields only when relevant. Blank issues remain available for other topics. Give a minimal reproduction with synthetic data, expected/actual behavior and the relevant versions/platform.

For CLI/runtime reports, include exact sanitized commands, exit codes/JSON error reasons, launcher and runtime versions, install entry, OS/architecture and Linux libc if known. Performance reports need workload, model/engine, background indexing/downloads, concurrent requests and measured memory/latency.

## Pull requests

Use a small branch against `main` and the PR template. Explain the problem and resulting behavior, link related issues (use `Fixes #...` only when fully resolved), and include actual test commands/results. Mark checks N/A with a reason when irrelevant; say explicitly when CI or platform tests did not run or were skipped.

Preserve CLI flags, JSON/MCP/HTTP contracts, stored data/index/config formats, prompt constraints in [AGENTS.md](AGENTS.md), and third-party notices. Explain compatibility, migration and rollback for any affected boundary.

## Validation

Follow [README.md](README.md) and existing [CI](.github/workflows/ci.yml); use isolated test data. Run checks relevant to the changed behavior and record limitations instead of claiming untested platforms passed. No new coverage threshold is introduced.

For Rust behavior changes, the existing baseline is the pinned toolchain, matching Core SDK, and `RSRS_CORE_TEST_MODE=1 cargo test --locked --workspace` (PowerShell: set `$env:RSRS_CORE_TEST_MODE='1'` first). See [SDK setup](crates/core-sdk/README.md) and [command checks](docs/command-regression.md). Runtime/performance changes also need relevant foreground/background and concurrency evidence; report measurement methods and before/after results without relaxing existing acceptance gates.

Documentation/template-only changes can use syntax, path/link and diff review; state explicitly if product tests were not run.

Template and Markdown-only changes are excluded by the current automatic Release workflow's path filters. Do not dispatch publishing workflows for contribution-only changes.

## Private data and security

Search existing issues first. Never post passwords, API keys/tokens, databases/backups, private memories, account identifiers or unredacted logs/screenshots.

Security vulnerabilities: do not disclose details in a public Issue or PR. Check this repository's Security tab for a private reporting option; if none is offered, ask maintainers to establish a private channel without including vulnerability details. No security email or private channel is currently documented.
