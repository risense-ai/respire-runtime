//! Shared parsing and envelope capture for host UI and Runtime execution.
//! Only the server feature includes business execution and source-change retries.

use anyhow::Result;
use clap::Parser;

use crate::cli_def::Cli;
#[cfg(feature = "server")]
use crate::cli_def::Command;
#[cfg(feature = "server")]
use crate::engine::run_local;
use crate::output::{ResultEnvelope, Status as OutputStatus};
use crate::output_emit::command_failure;
use crate::output_state::{
    exit_code, mark_emitted, output_emitted, parse_failure, set_exit_code, Captured, CAPTURED,
    OUTPUT_EMITTED, OUTPUT_EXIT_CODE,
};
#[cfg(any(feature = "server", test))]
use crate::output_state::HOST_RPC_OUTPUT;

/// Parse and execute one argv vector through the shared engine, capturing the
/// emitted envelope for the RPC reply. This is the executor of the standalone
/// `rsrs-runtime` host; the CLI binary delegates here with [`crate::engine::run_local`]
/// swapped for its own `run()`.
#[cfg(feature = "server")]
pub fn capture_run(args: Vec<String>) -> Captured {
    capture_exec(args, run_local)
}

/// The capture contract shared by both hosts: parse, run, and collect the
/// envelope that `emit_result` parked in the thread-local slot.
///
/// Only the server defers indexing and retries a changed memory source.
/// Frontend capture runs once and never initializes Core or replays a request.
pub fn capture_exec(args: Vec<String>, mut run: impl FnMut(Cli) -> Result<()>) -> Captured {
    CAPTURED.with(|slot| *slot.borrow_mut() = None);
    OUTPUT_EMITTED.with(|flag| flag.set(false));
    OUTPUT_EXIT_CODE.with(|flag| flag.set(0));
    let parsed = Cli::try_parse_from(
        std::iter::once(std::ffi::OsString::from("rsrs"))
            .chain(args.iter().cloned().map(std::ffi::OsString::from)),
    );
    #[cfg(feature = "server")]
    let defer_index = parsed.as_ref().is_ok_and(|cli| {
        matches!(
            cli.command.as_ref(),
            Some(
                Command::Remember { .. }
                    | Command::Update { .. }
                    | Command::Import { .. }
                    | Command::Attach { .. }
                    | Command::Restore { .. }
            )
        )
    });
    #[cfg(feature = "server")]
    let _deferred = defer_index.then(respire_app::core_sdk::defer_indexing);
    let ran = match parsed {
        Ok(cli) => match run(cli) {
            #[cfg(feature = "server")]
            Err(error)
                if !HOST_RPC_OUTPUT.get()
                    && error
                        .downcast_ref::<respire_app::transport::local::MemorySourceChanged>()
                        .is_some() =>
            {
                Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(args.iter().cloned()))
                    .map_err(anyhow::Error::from)
                    .and_then(&mut run)
            }
            result => result,
        },
        Err(error) => {
            let code = error.exit_code();
            let mut envelope = ResultEnvelope::new(
                "cli",
                if code == 0 {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Fail
                },
                serde_json::json!({"reason": "parse"}),
                Vec::new(),
            );
            if code != 0 {
                envelope = parse_failure(&error);
            }
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            mark_emitted();
            set_exit_code(code);
            Ok(())
        }
    };
    if let Err(error) = ran {
        if !output_emitted() {
            let (envelope, code) = command_failure(&error);
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            set_exit_code(code);
        }
    }
    let mut envelope = CAPTURED
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| {
            ResultEnvelope::new("cli", OutputStatus::Ok, serde_json::json!({}), Vec::new())
        });
    envelope.ensure_failure_diagnostics();
    Captured {
        exit: exit_code(),
        envelope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_failure_is_a_user_error_without_running() {
        let captured = capture_exec(vec!["--definitely-not-a-real-flag".to_owned()], |_cli| {
            unreachable!("a parse failure must not reach the runner")
        });
        assert_eq!(captured.exit, 2);
        assert!(matches!(captured.envelope.status, OutputStatus::Fail));
        assert_eq!(captured.envelope.summary["reason"], "invalid_input");
        assert!(!captured.envelope.errors.is_empty());
    }

    #[test]
    fn runner_failure_becomes_a_runtime_error_envelope() {
        let mut calls = 0;
        let captured = capture_exec(vec!["status".to_owned()], |_cli| {
            calls += 1;
            Err(anyhow::anyhow!("boom"))
        });
        assert_eq!(calls, 1);
        assert_eq!(captured.exit, 1);
        assert!(matches!(captured.envelope.status, OutputStatus::Fail));
        assert_eq!(captured.envelope.summary["reason"], "runtime_error");
        assert!(captured.envelope.errors.iter().any(|error| error == "boom"));
    }

    #[test]
    fn emitted_envelope_is_captured_for_host_reply() {
        let previous = HOST_RPC_OUTPUT.replace(true);
        let captured = capture_exec(vec!["status".to_owned()], |_cli| {
            crate::output_emit::emit_result(ResultEnvelope::new(
                "probe",
                OutputStatus::Ok,
                serde_json::json!({"ok": true}),
                Vec::new(),
            ))
        });
        HOST_RPC_OUTPUT.set(previous);
        assert_eq!(captured.exit, 0);
        assert!(matches!(captured.envelope.status, OutputStatus::Ok));
        assert_eq!(captured.envelope.command, "probe");
        assert_eq!(captured.envelope.summary["ok"], true);
    }
}
