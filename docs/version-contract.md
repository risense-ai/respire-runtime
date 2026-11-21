# Version and compatibility contract

This document defines how `respire-runtime` and `respire-cli` stay compatible
while releasing independently. The contract's machine-readable pieces are the
`runtime-build-<triple>.json` release metadata (produced by the Release
workflow) and the
`respire-protocol` crate published from `crates/protocol` in this repository.

## Frozen host boundary

The frozen host split uses published `respire-protocol` **2.0.0-dev.16** and wire
protocol **1**. Complete the Runtime implementation against these existing
types before accepting CLI and Client2 implementations. Do not add mandatory
fields or change operation semantics during host integration. A later
incompatible change requires a separately reviewed protocol version.

Runtime dev.24 adds the independent [core configuration contract](core-config.md)
in `respire_protocol` **2.0.0-dev.17**, retaining wire protocol **1** and the old
host-control DTOs. Publish dev.17 before merging host consumers of the new DTOs.

- Runtime owns authentication transactions, synchronization, encrypted database
  management, remember/recall, inference and the RPC/MCP interfaces.
- CLI and Client2 independently own downloads, installation, component selection,
  system credential storage, private-key custody, sign-in startup and Runtime
  process supervision. A third-party host can implement the same contract.
- A Runtime started without host-provided keys stays locked. The host supplies
  account-bound factors over the private control channel. Public business RPC
  and MCP do not gain permission to read system credentials or install assets.
- Login, key operations, migration and snapshot restore receive explicit host
  material. Runtime validates candidate digests, transaction scope and custody
  acknowledgements before committing database or account changes. Private
  handoffs go to the host; missing material is an explicit error or a defined
  intermediate state, never an implicit credential lookup.
- Operation identities and unknown outcomes retain their existing result-query
  semantics. Hosts query the original operation instead of silently replaying a
  write. Host plugin events use the published request/ack frames.
- Historical compatibility covers database keys, decryptable records, integrity
  and pending synchronization. Old host binaries, credential locations and
  interrupted host credential-cleanup journals are not a compatibility promise;
  unsupported journals are retained and explicitly rejected.

Runtime, CLI and Client2 release independently. Protocol versions and the
capabilities used by a request determine interoperability.

## runtime_version

- The version in `runtime/Cargo.toml` of this repository is `runtime_version`.
  It increments **independently** of the CLI version: every user-visible
  runtime change set bumps the patch version; developer previews use
  `X.Y.Z-dev.N`.
- Every Runtime release tag must match the source `runtime_version`.
  DEV publication uses a reviewed `main` commit and a `vX.Y.Z-dev.N` tag.
- The CLI has its own version train and never derives its version from the
  runtime or vice versa.

## Release metadata and health

Runtime release metadata describes the Runtime artifact, its digests, the
supported protocol range and capabilities. Each host can discover and verify
an artifact from the requested release channel. A test run may record an exact
artifact version and digest for reproducibility.

Health reports the actual `runtime_version` for diagnosis. Clients check the
wire protocol and capabilities before calling a method. A host delivering
credentials also verifies the receiving Runtime and account scope.

## PROTOCOL_V hard gate

- `PROTOCOL_V` remains a hard gate on both sides: any mismatch fails fast
  with `protocol_version_mismatch`; there is no negotiation or fallback.
- The gate semantics are inherited unchanged from the combined binary.

## respire-protocol is the shared contract

- `crates/protocol` in **this** repository is the source of truth; it is
  published to crates.io as `respire-protocol` by `publish-crates.yml`.
- The crate version identifies the shared types. Compatible schema additions may
  publish a new crate without changing `PROTOCOL_V`; an incompatible wire change
  requires an explicit protocol-version change. Neither version requires equal
  CLI, Runtime, Client2 or Core product versions.
- Both repositories consume only **published** versions of the crate; neither
  may vendor or path-dependency across the repository boundary.

## Protocol-first PR rule

When a change touches the RPC contract:

1. Land and **publish the new `respire-protocol` version** from this
   repository first (stable tag push or explicit manual publish).
2. Only then merge consumer PRs (runtime server code here, CLI client code in
   `respire-cli`) that require the new version.
3. CI on both sides verifies that lockfiles reference versions that exist on
   crates.io; a consumer PR referencing an unpublished version must not merge.


## Current stage-one DEV scope

The coordinated DEV update validates the new CLI, Runtime and Client2 together.
Compatibility is determined by the shared protocol and required capabilities,
not matching component version numbers, source commits or workflow runs. Exact
candidate source and artifact identities are regression provenance only.

Historical releases provide databases for upgrade testing: prepare data with the
historical stack, upgrade the hosts and Runtime, then validate that data with the
new stack. Latest applicable stable and historical stable database upgrades
remain required. DEV-to-DEV upgrades are required for persistent-format changes;
DEV revisions without such changes do not add a separate migration baseline.
Old-client/new-Runtime and new-client/old-Runtime compatibility are not release
requirements. See [Client2 upgrades](client2-split-compatibility.md).

Runtime 2.0.0-dev.18 removes the embedded host command entry points. Both
Client2 0.2.56 and 2.0.0-dev.5 still select their installed Runtime image for
host operations and require the removed model catalog/progress RPCs. Upgrade
those clients before selecting this Runtime; their historical compatibility
checks do not establish compatibility with the pure Runtime.

The G1 freeze workflow authenticates the selected new Client2 candidate from its
successful Desktop client workflow. Each frozen run records the actual source,
build identity, workflow, run, artifact ID, ZIP digest, archive digest and
executable digest. Confirm these identities against the selected candidate
before acceptance. An unpublished input is not a released-client or passing G1
claim, and a recorded source hash is not a production compatibility requirement.
All seven lifecycle cases and process identity, RPC boundary and cleanup
assertions remain required. Each ready-library case first runs public CLI
keygen in the existing hosted private Secret Service fixture, stops the setup
owner, then tests automatic host key delivery without inherited key variables.
The fixture verifies credential ownership and removal. Credential-free restart
locking remains a separate required native check. Current Windows checks and published
upgrade acceptance remain separate. Interactive Keychain authorization is not
established by this evidence.

Runtime 1.0.21-dev.3 and later provide a standalone doctor that
executes Runtime-owned store, asset/backend, index and optional bounded remote
health diagnostics. Asset readiness uses the existing supervised fresh-session
probe; diagnostics do not download, install, access host keyring, inspect host
injection targets or check CLI updates. Repair and CLI-update flags remain
host-owned; callers must coordinate them through the CLI and request Runtime
verification afterwards. Request-scoped progress stays observable during work.

The Runtime 2.0.0-dev.17 candidate restores Intel macOS to the eight-target release
matrix. Intel builds cross-compile on Apple silicon; native smoke runs on
`macos-15-intel` with the existing hardware guard that rejects ARM64 and Rosetta.
All targets retain their native release gates and complete payload/digest checks.
Source changes and native lifecycle/MCP smoke do not establish model inference or
full G1. Stable release planning stays closed until full G1 evidence is verified
and promotion is separately authorized.
