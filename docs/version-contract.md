# Version and compatibility contract

This document defines how `respire-runtime` and `respire-cli` stay compatible
while releasing independently. The contract's machine-readable pieces are the
`runtime-build-<triple>.json` release metadata (produced by the Release
workflow), the `runtime-pin.json` file in the CLI repository, and the
`respire-protocol` crate published from `crates/protocol` in this repository.

## runtime_version

- The version in `runtime/Cargo.toml` of this repository is `runtime_version`.
  It increments **independently** of the CLI version: every user-visible
  runtime change set bumps the patch version; developer previews use
  `X.Y.Z-dev.N`.
- A stable release tag `vX.Y.Z` must exactly match the source
  `runtime_version`; dev tags `vX.Y.Z-dev.N` may point at any reviewed `main`
  commit.
- The CLI has its own version train and never derives its version from the
  runtime or vice versa.

## runtime-pin.json consumption rules (CLI side)

The CLI repository carries a pin file:

```json
{ "schema_version": 1, "required": "x.y.z", "accept": ">=x.y.z,<2.0.0" }
```

- **Automatic download uses `required`** as an exact pin (build-time
  determinism, decision #5 of the split plan). It never resolves "latest".
- **`accept` is a reuse range**: an already-installed managed runtime whose
  `runtime_version` falls inside `accept` is reused without forced
  replacement; outside the range the CLI replaces it (draining in-flight
  requests first, semantics unchanged from the combined binary).
- After this repository publishes a new release, a follow-up PR in the CLI
  repository updates the pin (`scripts/update-cli-pin.mjs` in this repository
  generates the content). Merge that PR before cutting the CLI release.

## Release ordering iron rule

**The runtime repository releases first; the CLI repository releases second.**

- A CLI pin may only reference an existing runtime release. Because the pin is
  exact, a pin pointing at a non-existent release is a release blocker; CI on
  the CLI side refuses such pins (pin existence gate).
- client2 switches its asset source last, after both repositories ship.

## health body extension fields

The runtime `/health` body carries, in addition to the existing fields:

```json
{
  "runtime_version": "1.4.0",
  "runtime_compat": { "min_cli": "1.0.21-dev.5", "max_cli": "*" }
}
```

- `runtime_version` equals the releasing `Cargo.toml` version.
- `runtime_compat.min_cli` / `max_cli` declare the CLI versions this runtime
  accepts; `max_cli: "*"` means no upper bound. The Release workflow embeds
  the same window into every `runtime-build-<triple>.json`; the values are
  defined once as workflow-level environment variables (`RUNTIME_MIN_CLI`,
  `RUNTIME_MAX_CLI`).
- The scoped request and lifecycle identity contract requires CLI
  `1.0.21-dev.5` or later. Released CLI `1.0.20` sends unscoped business requests
  and an empty stop body, so it is not compatible with this Runtime train.
- The CLI installer validates the metadata's CLI window before installation.
  Its `runtime_acceptable(health)` check additionally requires the Runtime's
  version to be in the CLI's accept window, the expected managed path, and no
  stalled inference.

## PROTOCOL_V hard gate

- `PROTOCOL_V` remains a hard gate on both sides: any mismatch fails fast
  with `protocol_version_mismatch`; there is no negotiation or fallback.
- The gate semantics are inherited unchanged from the combined binary.

## respire-protocol is the shared contract

- `crates/protocol` in **this** repository is the source of truth; it is
  published to crates.io as `respire-protocol` by `publish-crates.yml`.
- The crate version moves in lockstep with `PROTOCOL_V`.
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

On macOS, background serving and private RPC/control processes disable Keychain
interaction before reading credentials. An inaccessible credential fails startup
without discarding the session or recovery journal. The CLI owns the bounded
foreground `runtime authorize-keychain` flow: it invokes the verified installed
Runtime with `--keychain-authorize-internal`. That read-only process permits the
system prompt and verifies the existing credential without starting a listener.
Users must review the new Runtime path and grant persistent access for subsequent
background reads. Denial, a locked Keychain, and an unanswered prompt are failures,
not successful upgrades. The native startup workflow separately checks a denied
read against an official dev.3/dev.14 home; it does not establish successful
interactive authorization or complete in-place upgrade acceptance.

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
