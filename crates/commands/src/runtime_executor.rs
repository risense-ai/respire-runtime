//! In-process business executor for the standalone Runtime.
//!
//! It admits only the non-host command surface that supports memory reads,
//! writes and MCP. Identity, lifecycle, update and installation commands remain
//! host-owned and fail closed.

use std::sync::atomic::Ordering;

use anyhow::Context;
use clap::Parser;

use crate::cli_def::{Cli, Command, ModelAction};
use crate::engine::{run_local, DIRECT_MODE};
use crate::output::{ResultEnvelope, Status as OutputStatus};
use crate::output_state::{
    exit_code, mark_emitted, parse_failure, set_exit_code, set_json_mode, Captured, CAPTURED,
    OUTPUT_EMITTED, OUTPUT_EXIT_CODE,
};

fn is_allowed(command: Option<&Command>) -> bool {
    matches!(
        command,
        Some(
            Command::Model {
                action: ModelAction::Engine { .. }
                    | ModelAction::Load { .. }
                    | ModelAction::Probe { .. },
            } | Command::Sync
                | Command::SyncConflicts { .. }
                | Command::SyncResolve { .. }
                | Command::SyncHistory { .. }
                | Command::SyncRestore { .. }
                | Command::Classify { .. }
                | Command::Reembed
                | Command::Status
                | Command::Doctor {
                    check_update: false,
                    fix: false,
                    ..
                }
                | Command::MemoryRevision
                | Command::Capabilities
                | Command::List { .. }
                | Command::Recall { .. }
                | Command::Remember { .. }
                | Command::Update { .. }
                | Command::Forget { .. }
                | Command::Purge { .. }
                | Command::Restore { .. }
                | Command::Promote { .. }
                | Command::Demote { .. }
                | Command::Show { .. }
                | Command::QueryLog { .. }
                | Command::Chain { .. }
                | Command::Attach { .. }
                | Command::Tree { .. }
                | Command::History { .. }
                | Command::Diary { .. }
                | Command::DiarySearch { .. }
                | Command::DiaryFragment { .. }
                | Command::Taxonomy {
                    list: true,
                    ensure: None
                }
                | Command::Extract { .. }
        )
    )
}

fn failure(command: &str, reason: &str) -> Captured {
    let mut envelope = ResultEnvelope::new(
        command,
        OutputStatus::Fail,
        serde_json::json!({"reason": reason}),
        Vec::new(),
    );
    envelope.details = serde_json::json!({"error_type": "host_boundary"});
    Captured { exit: 2, envelope }
}

fn execute(args: Vec<String>) -> anyhow::Result<Captured> {
    // The command pipeline must run in runtime-worker mode; otherwise a nested
    // LocalStore open waits on the listener thread's installation lock.
    crate::rpc_worker::mark_worker();
    CAPTURED.with(|slot| *slot.borrow_mut() = None);
    OUTPUT_EMITTED.with(|flag| flag.set(false));
    OUTPUT_EXIT_CODE.with(|flag| flag.set(0));
    set_json_mode(true);
    DIRECT_MODE.store(false, Ordering::Relaxed);

    let parsed = Cli::try_parse_from(
        std::iter::once(std::ffi::OsString::from("rsrs"))
            .chain(args.iter().cloned().map(std::ffi::OsString::from)),
    );
    let cli = match parsed {
        Ok(cli) => cli,
        Err(error) => {
            let code = i32::from(error.exit_code()).max(1);
            let envelope = parse_failure(&error);
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            mark_emitted();
            set_exit_code(code);
            let envelope = CAPTURED
                .with(|slot| slot.borrow_mut().take())
                .unwrap_or_else(|| {
                    ResultEnvelope::new(
                        "cli",
                        OutputStatus::Fail,
                        serde_json::json!({"reason":"parse"}),
                        Vec::new(),
                    )
                });
            return Ok(Captured {
                exit: exit_code(),
                envelope,
            });
        }
    };

    if !is_allowed(cli.command.as_ref()) {
        return Ok(failure(
            cli.command.as_ref().map_or("cli", |_| "host-command"),
            "command is host-managed and cannot execute in Runtime",
        ));
    }
    if !crate::runtime_policy::client_only() {
        respire_app::migration::ensure_default_home()
            .context("default profile migration failed")?;
    }

    let args_for_retry = args.clone();
    let _progress = crate::progress::Scope::start(cli.progress_id.clone(), false, false);
    let _model_task = crate::model_progress::TaskScope::new(cli.model_task_id.clone());
    let run_result = run_local(cli);
    let run_result = if run_result.as_ref().is_err_and(|error| {
        error
            .downcast_ref::<respire_app::transport::local::MemorySourceChanged>()
            .is_some()
    }) {
        Cli::try_parse_from(
            std::iter::once(std::ffi::OsString::from("rsrs"))
                .chain(args_for_retry.iter().cloned().map(std::ffi::OsString::from)),
        )
        .map_err(anyhow::Error::from)
        .and_then(run_local)
    } else {
        run_result
    };
    Ok(finish_execution(run_result))
}

fn finish_execution(run_result: anyhow::Result<()>) -> Captured {
    if let Err(error) = run_result {
        let (envelope, code) = crate::output_emit::command_failure(&error);
        CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
        set_exit_code(code);
    }
    let Some(envelope) = CAPTURED.with(|slot| slot.borrow_mut().take()) else {
        return failure("cli", "business executor returned no result envelope");
    };
    Captured {
        exit: exit_code(),
        envelope,
    }
}

pub fn capture_run(args: Vec<String>) -> Captured {
    // Keep the scheduler's generation and sync boundary on this worker thread.
    match std::panic::catch_unwind(|| execute(args)) {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => failure("cli", &format!("{error:#}")),
        Err(_) => failure("cli", "executor panicked"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_for(args: &[&str]) -> ResultEnvelope {
        capture_run(args.iter().map(|arg| (*arg).to_owned()).collect()).envelope
    }

    #[test]
    fn pure_memory_commands_are_allowed_by_the_executor() -> anyhow::Result<()> {
        let command = |args: &[&str]| -> anyhow::Result<Option<Command>> {
            Ok(Cli::try_parse_from(std::iter::once("rsrs").chain(args.iter().copied()))?.command)
        };
        for args in [
            vec!["status"],
            vec!["doctor"],
            vec!["doctor", "--remote"],
            vec!["model", "engine"],
            vec!["model", "engine", "--model=quantized", "--", "cpu"],
            vec!["model", "load", "cpu", "--model=quantized"],
            vec!["model", "probe"],
            vec!["sync"],
            vec!["reembed"],
            vec!["list"],
            vec!["show", "abcd1234"],
            vec!["recall", "context"],
            vec!["remember", "context"],
            vec!["update", "abcd1234", "--title", "new"],
            vec!["forget", "abcd1234"],
            vec!["purge", "abcd1234"],
            vec!["restore", "abcd1234"],
            vec!["promote", "abcd1234"],
            vec!["demote", "abcd1234", "--parent", "parent"],
            vec!["attach", "child", "--parent", "parent"],
            vec!["tree"],
            vec!["history"],
            vec!["diary"],
            vec!["diary-search", "context"],
            vec!["diary-fragment", "source", "fragment"],
            vec!["chain", "abcd1234"],
            vec!["taxonomy", "--list"],
            vec!["extract", "--dry-run"],
            vec!["query-log", "mark", "abcd1234", "--good"],
        ] {
            let parsed = command(&args)?;
            if !is_allowed(parsed.as_ref()) {
                return Err(anyhow::anyhow!("executor rejected pure command {args:?}"));
            }
        }
        Ok(())
    }

    #[test]
    fn installers_and_lifecycle_commands_are_not_business_execution() -> anyhow::Result<()> {
        for args in [
            vec!["model", "install"],
            vec!["model", "install-engines"],
            vec!["model", "uninstall"],
            vec!["model", "reset-cpu"],
            vec!["doctor", "--fix"],
            vec!["doctor", "--check-update"],
            vec!["runtime", "stop"],
            vec!["login"],
            vec!["logout"],
        ] {
            let parsed = Cli::try_parse_from(std::iter::once("rsrs").chain(args.iter().copied()))?;
            assert!(
                !is_allowed(parsed.command.as_ref()),
                "host command was admitted: {args:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn host_identity_commands_fail_closed() -> anyhow::Result<()> {
        let envelope = envelope_for(&["login"]);
        assert!(matches!(envelope.status, OutputStatus::Fail));
        assert_eq!(
            envelope.summary["reason"],
            "command is host-managed and cannot execute in Runtime"
        );
        Ok(())
    }

    #[test]
    fn parse_failures_remain_structured() -> anyhow::Result<()> {
        let envelope = envelope_for(&["--not-a-command"]);
        assert!(matches!(envelope.status, OutputStatus::Fail));
        assert_eq!(envelope.summary["reason"], "invalid_input");
        Ok(())
    }

    #[test]
    fn help_is_not_a_successful_business_operation() {
        let captured = capture_run(vec!["remember".to_owned(), "--help".to_owned()]);
        assert_ne!(captured.exit, 0);
        assert!(matches!(captured.envelope.status, OutputStatus::Fail));
    }

    #[test]
    fn executor_preserves_the_scheduler_thread() {
        let was_worker = crate::rpc_worker::worker_active();
        crate::rpc_worker::set_worker_active(false);
        let captured = capture_run(vec!["--not-a-command".to_owned()]);
        let executed_here = crate::rpc_worker::worker_active();
        crate::rpc_worker::set_worker_active(was_worker);
        assert_ne!(captured.exit, 0);
        assert!(
            executed_here,
            "executor must keep scheduler thread-local context"
        );
    }

    #[test]
    fn partial_output_and_missing_output_cannot_hide_failure() {
        CAPTURED.with(|slot| {
            *slot.borrow_mut() = Some(ResultEnvelope::new(
                "remember",
                OutputStatus::Ok,
                serde_json::json!({"progress": "started"}),
                Vec::new(),
            ));
        });
        mark_emitted();
        set_exit_code(0);
        let failed = finish_execution(Err(anyhow::anyhow!("write failed after progress")));
        assert_ne!(failed.exit, 0);
        assert!(matches!(failed.envelope.status, OutputStatus::Fail));

        CAPTURED.with(|slot| *slot.borrow_mut() = None);
        set_exit_code(0);
        let missing = finish_execution(Ok(()));
        assert_ne!(missing.exit, 0);
        assert!(matches!(missing.envelope.status, OutputStatus::Fail));
    }
}
