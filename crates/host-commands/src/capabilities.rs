//! Static CLI support; no account, store, model or Runtime is inspected.

use anyhow::Result;
use crate::output::{ResultEnvelope, Status as OutputStatus};
use crate::output_emit::emit_result;

pub fn run_capabilities() -> Result<()> {
    emit_result(ResultEnvelope::new(
        "capabilities",
        OutputStatus::Ok,
        serde_json::json!({
            "schema_version": 1,
            "cli_version": crate::app_version::embedded(),
            "capabilities": {
                "host_rpc": {"version":1,"transport":"stdio","flag":"--host-rpc-stdio","methods":["auth.register","auth.login","auth.recover","auth.reset"]},
                "memory_list_metadata": true,
                "memory_metadata_flags": true,
                "memory_metadata_gate_default": false,
                "rerank": false,
                "model": {"install": true, "install_rerank": false, "profile_contract":1, "transport_contract":1, "methods":["model.catalog","model.configure","model.switch","model.resume","model.progress"], "selection_scope":"library"}
            }
        }),
        Vec::new(),
    ))
}
