# Runtime compatibility contract

## Version selection

Components interoperate through the wire protocol and required capabilities.
Each host obtains Runtime through its selected Runtime channel or explicit
Runtime selection. Verify its target, assets and integrity before installation.
The host checks actual protocol and method support before using it. Record
candidate versions and hashes as evidence for the combinations tested.

Upgrade regression prepares data with each supported historical stack, upgrades
the components, then verifies database migration, integrity and memory operations
with the new compatible stack. Include database-changing DEV checkpoints; omit
redundant DEV combinations with unchanged persistent formats. Run a separate
online interoperability check using the original client executable against
the running Runtime, with the required protocol, method and authorization.
Record success for the exact tested operations or the explicit reason for
rejection. Database migration evidence does not imply online interoperability.

## Wire protocol

`PROTOCOL_V` remains a hard gate. A mismatch fails with
`protocol_version_mismatch`. Consumers do not downgrade silently or fall back to
a CLI shim. Capability negotiation is allowed only inside the frozen range and
only for keys declared by both sides.

Stage 1 business callers must send top-level `scope` with the verified health
`account_id`, `instance_id`, and wire `generation`, including result queries.
A caller missing this contract is not a compatible business client. It must not
retry an unconfirmed write with a refreshed scope or fall back to a CLI shim.
`scope_required` and `scope_mismatch` preserve an explicit failure; neither
proves that a previously admitted operation did not commit.

## Channels

| Component | Setting | Stable rule |
| --- | --- | --- |
| Runtime | `runtimeChannel` | Reject prereleases. |
| CLI | `cliChannel` | Reject prereleases and use CLI releases. |
| Client2 | `clientChannel` | Controls only Client2. |

Changing one channel never changes another component implicitly. Dev to stable
occurs only when an exact compatible stable exists. Otherwise the active dev
combination remains active and is reported as dev.

## Legacy consumers

The following describes historical installers and preservation checks. Old
Runtime interfaces require a method and authorization supported by the running
Runtime. Preserve the original artifacts needed to construct upgrade fixtures.

The old CLI consumers that treat `sha256` and `binary_sha256` as the same value
cannot install canonical schema 2 archives whose hashes differ. They keep only
their previously verified combinations until repaired. New consumers may support
schema 1 by mapping `sha256` to `archive_sha256` and `triple` to
`target_triple`.

Client2's legacy installer requires a naked
`rsrs-runtime-<triple>[.exe]` in addition to the archive and metadata. That
asset remains mandatory during the compatibility window. Removing it requires a
separate versioned compatibility decision.

## Platform matrix

All eight targets in `runtime-control-contract.md` are supported. Every target
requires the archive, metadata, naked legacy binary where applicable, and
integrity evidence. Missing platform evidence blocks candidate promotion.
