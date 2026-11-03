# Repository instructions

## Language and style

- Code, comments, commit messages, documentation and PR descriptions are English only.
- Keep comments for contracts, safety boundaries and non-obvious invariants, not narration.

## Rust safety rules

- Do not add new `.unwrap()` or `.expect()` calls. Handle errors with typed results and
  context, or use `panic!`/`unreachable!` with a message when the invariant genuinely
  cannot hold. Pre-existing call sites may be refactored away but never re-introduced.

## Validation happens in CI

- Do not run `cargo build`, `cargo test` or any heavy native build on developer laptops
  as a substitute for CI. Validation convention: open the PR, let the CI workflows run,
  and iterate on their output. Local `cargo check` on the host target is acceptable for
  fast typing feedback only; it is never evidence of correctness.
- Any claim that behavior changed must point at a green CI run on the exact commit.
- Windows ARM64 and Linux ARM64 acceptance run on native ARM hardware runners only;
  never replace them with emulation.

## Runtime boundary (do not move it)

- This repository never downloads models, engines or any host asset at runtime.
  Missing assets are reported (`health.inference.state`, `assets.status`); the CLI owns
  installation. Do not add download/installer/self-update/self-registration code here.
- The RPC contract lives only in `crates/protocol` (published as `respire-protocol`).
  Never fork protocol types in another crate; bump and publish the crate instead.
- `PROTOCOL_V` stays a hard gate: a mismatch fails fast with `protocol_version_mismatch`.

## Process

- Work on short-lived branches and open a PR into `main`. After review, merge the PR;
  direct pushes to `main` are reserved for release housekeeping (version bumps, pin
  file updates, tag administration) and the initial repository bootstrap.
- Protocol changes: publish the new `respire-protocol` version to crates.io first,
  then merge the consumer PRs in this repository and in `respire-cli`. CI refuses
  locks that point at unpublished versions.
- Release order: runtime repository first, CLI repository second. The CLI pin may only
  reference an existing runtime release. See [docs/version-contract.md](docs/version-contract.md).
- Version increments: every user-visible change set bumps the patch version of this
  repository's own `runtime_version`; developer previews use `vX.Y.Z-dev.N` tags.

## Secrets and private SDK

- `CORE_SDK_READ_TOKEN` is used only inside the isolated trusted download job of
  `private-sdk-cache.yml`. Never forward it to build scripts, PR contexts, caches or logs.
- SDK lock files pin exact bytes; update both `sdk/core-sdk.lock.json` and
  `crates/core-sdk/core-sdk.lock.json` together, for all seven release targets.
