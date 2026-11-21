# Version and compatibility contract

This document defines how `respire-runtime` and `respire-cli` stay compatible
while releasing independently. The contract's machine-readable pieces are the
`runtime-build-<triple>.json` release metadata (produced by the Release
workflow) and the
`respire-protocol` crate published from `crates/protocol` in this repository.

## Host boundary

The current wire protocol is **1**. Check the required methods and capabilities
for each request. Mandatory field or operation-semantics changes that break
compatibility require a separately reviewed protocol version.

The [core configuration contract](core-config.md) was added in Runtime dev.24
with `respire-protocol` **2.0.0-dev.17**. It retained wire protocol **1** and the
existing host-control DTOs.

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


## Upgrade and online interoperability

Each component can be updated independently. Verify the selected components
against the shared wire protocol, required methods and capabilities. Use exact
candidate source and artifact identities to reproduce each regression.

Historical releases provide databases for upgrade testing: prepare data with the
historical stack, upgrade the hosts and Runtime, then validate that data with the
new stack. Latest applicable stable and historical stable database upgrades
remain required. DEV-to-DEV upgrades are required for persistent-format changes;
DEV revisions without such changes do not add a separate migration baseline.
Exercise the older host with a new Runtime and the new host with an older
Runtime by changing one component at a time. Verify operations and receipts when
the required contract is available. Verify explicit errors when a required
contract or authorization is missing. See [Client2 upgrades](client2-split-compatibility.md).

## Historical DEV observations

Runtime 2.0.0-dev.18 removes the embedded host command entry points. Both
Client2 0.2.56 and 2.0.0-dev.5 still select their installed Runtime image for
host operations and require the removed model catalog/progress RPCs. Upgrade
those clients before selecting this Runtime; their historical compatibility
checks do not establish compatibility with the pure Runtime.

The retired cross-repository G1 freeze workflow authenticated the selected
Client2 candidate from its successful Desktop client workflow. Its receipts
recorded source, build, workflow, run, artifact ID and package digests. The
ready-library cases used public CLI keygen to seed a private Secret Service
fixture. They then stopped the setup owner and verified automatic host key
delivery without inherited key variables. Credential-free restart locking was a
separate native check. Interactive Keychain authorization was outside the scope.

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
