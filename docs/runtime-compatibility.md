# Runtime compatibility contract

## Version selection

Consumers resolve one exact Runtime version from a pinned compatibility
manifest. `latest` is never a compatibility source. A release is installable
only when runtime version, CLI version, Client2 version, protocol range,
required capabilities, target, asset names, and source binding all match.

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
