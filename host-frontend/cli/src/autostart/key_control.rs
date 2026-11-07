//! CLI key adapter. The shared coordinator owns journals, grants and transport.

use anyhow::Result;
use respire_commands::output::ResultEnvelope;
use respire_protocol::key_control::{HostKeyInput, HostKeyOperation, HostKeyResult};

pub(crate) use respire_host_control::KeyRecoveryRequired;

pub(crate) fn control_super_reset(super_pass: Option<&str>) -> Result<ResultEnvelope> {
    super::shared_host::keys().super_reset(super_pass)
}

pub(crate) fn control_super_reset_step(
    addr: Option<&str>,
    input: HostKeyInput,
    resume: Option<&HostKeyResult>,
) -> Result<ResultEnvelope> {
    super::shared_host::keys().super_reset_step(addr, input, resume)
}

pub(crate) fn control_key_result(operation_id: &str) -> Result<ResultEnvelope> {
    super::shared_host::keys().result(operation_id)
}

pub(crate) fn control_key_rollback(operation_id: &str) -> Result<ResultEnvelope> {
    super::shared_host::keys().rollback(operation_id)
}

pub(crate) fn control_fivekeys(
    operation: HostKeyOperation,
    input: HostKeyInput,
    resume: Option<&HostKeyResult>,
) -> Result<ResultEnvelope> {
    super::shared_host::keys().fivekeys(operation, input, resume)
}
