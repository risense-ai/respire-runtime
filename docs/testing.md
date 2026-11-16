# Runtime test ownership and execution

PR, main/release pushes and manual source CI run the control-contract checks,
protocol tests and a locked check of the current Runtime libraries and binaries.
The source CI does not download CLI products, install models, freeze candidates,
or require cross-repository execution reports.

## Release acceptance

The release workflow keeps the current eight native platform builds, exact SDK
locks, payload manifests and public asset digests. After publication, each native
runner downloads the actual public release assets and verifies complete payloads,
Runtime identity and normal drain. Build success is not native acceptance.

Linux GNU x64, Windows x64 and macOS ARM64 additionally run the complete workspace
source tests once per OS. This includes database migrations, snapshots, recovery,
crypto, admission replay and ownership checks. Existing source-unit fixtures use
`RSRS_CORE_TEST_MODE=1`; this mode never enters the public product smoke. Source
fixture success is reported separately from execution of the published binaries.

## Latest-component integration

CLI and Client2 own keychain access, installation, startup and Runtime process
management. Their final release acceptance supplies the latest published Runtime
through the protocol. Runtime retains the business assertions and core/RPC source
unit tests. Native HTTP integration fixtures remain distinct from source checks.

Historical compatibility concerns databases: stable releases and DEV checkpoints
that changed the database upgrade to the current DEV. Preserve the original keys,
existing decrypted records, pending sync data and continued remember/recall/sync.
Do not create a compatibility matrix for older hosts calling a new Runtime, or add
DEV upgrade pairs when no database migration occurred.

The historical frozen G1 chain and prebuilt cross-repository test bundles have
been removed. Missing acceptance evidence remains unverified; source checks,
compilation, test-name inventories and a successful download cannot substitute
for final published-product or database upgrade results.
