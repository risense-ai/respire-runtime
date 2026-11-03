//! Single-source output pipeline state: JSON mode, exit code, emission
//! tracking, deferred-output flags and the captured-envelope slot.
//!
//! The thread-locals live only here. The CLI binary re-binds the module so
//! its direct `CAPTURED.with(...)`, `HOST_RPC_OUTPUT.get()` etc. call sites
//! keep compiling against this single source; the runtime engine shares the
//! same state through the same accessors.

use std::cell::Cell;

use crate::output::{ResultEnvelope, Status as OutputStatus};

thread_local! {
    pub static JSON_MODE: Cell<bool> = const { Cell::new(false) };
    pub static OUTPUT_EMITTED: Cell<bool> = const { Cell::new(false) };
    pub static OUTPUT_EXIT_CODE: Cell<u8> = const { Cell::new(0) };
    pub static DEFER_PROFILE_OUTPUT: Cell<bool> = const { Cell::new(false) };
    pub static HOST_RPC_OUTPUT: Cell<bool> = const { Cell::new(false) };
}

pub fn status_exit_code(status: OutputStatus) -> i32 {
    match status {
        OutputStatus::Ok | OutputStatus::Skip => 0,
        OutputStatus::Warn | OutputStatus::Pending => 2,
        OutputStatus::Fail => 1,
    }
}

pub fn json_mode() -> bool {
    JSON_MODE.with(|flag| flag.get())
}
/// Whether to print progress lines on stderr. The web bridge sets RSRS_PROGRESS=1
/// for long async jobs: stdout stays JSON (for the bridge), stderr streams progress
/// (so the UI can "scroll"). Without that env var, a TTY decides - same as before.
pub fn progress_enabled() -> bool {
    if json_mode() { return false; }
    if respire_app::env::var("RSRS_PROGRESS")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    !json_mode() && std::io::IsTerminal::is_terminal(&std::io::stderr())
}

thread_local! {
    pub static CAPTURED: std::cell::RefCell<Option<ResultEnvelope>> = const { std::cell::RefCell::new(None) };
}

pub struct Captured {
    pub exit: i32,
    pub envelope: ResultEnvelope,
}

pub fn set_json_mode(on: bool) {
    JSON_MODE.with(|flag| flag.set(on));
}

pub fn mark_emitted() {
    OUTPUT_EMITTED.with(|flag| flag.set(true));
}

pub fn set_exit_code(code: i32) {
    OUTPUT_EXIT_CODE.with(|flag| flag.set(code.clamp(0, 255) as u8));
}

pub fn exit_code() -> i32 {
    OUTPUT_EXIT_CODE.with(|flag| flag.get() as i32)
}

pub fn output_emitted() -> bool {
    OUTPUT_EMITTED.with(|flag| flag.get())
}

/// Keep the complete parser diagnostic separately from its concise UI message.
pub fn parse_failure(error: &clap::Error) -> ResultEnvelope {
    let usage = error.to_string();
    let mut envelope = ResultEnvelope::new("cli", OutputStatus::Fail,
        serde_json::json!({"reason":"invalid_input"}), Vec::new());
    envelope.errors.push(usage.lines().find(|line| !line.trim().is_empty())
        .unwrap_or("invalid command input").to_owned());
    envelope.details = serde_json::json!({"error_type":"user", "usage":usage});
    envelope
}
