//! Component maintenance belongs to the host. Runtime only verifies core backends.
use anyhow::Result;
use respire_commands::output::ResultEnvelope;
use respire_protocol::{HostControlLaunchGrant, RpcRequest};

/// Retain an explicit rejection until the shared dispatcher retires this method.
/// No legacy request may recover component planning or filesystem authority here.
pub(crate) fn execute(
    _grant: HostControlLaunchGrant,
    _request: &RpcRequest,
) -> Result<ResultEnvelope> {
    anyhow::bail!("host_owned_model_maintenance: component planning, installation and file verification require the CLI host; use model preparation verify for core backend evidence")
}
