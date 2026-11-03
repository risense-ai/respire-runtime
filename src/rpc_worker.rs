//! Runtime worker infrastructure shared by the CLI binary and the resident
//! runtime engine.
//!
//! The command-execution engine and its worker plumbing migrate here from the
//! CLI binary in steps of the runtime split. This module currently hosts the
//! argv classification rules shared by client timeout budgets and server
//! routing, plus the loopback endpoint record that both sides read and write.
//!
//! Boundaries:
//! - depends on `respire_app` (app-core) and `cli_def`, never on the `respire`
//!   CLI package;
//! - the CLI binary re-imports these items so `crate::rpc::...` paths and bare
//!   call sites keep resolving.

use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use serde_json::{json, Value};

use crate::app_version;
use crate::cli_def::{Cli, Command, SessionCommand};

pub const PROTOCOL_V: u32 = 1;

pub static WEB_URL: Mutex<String> = Mutex::new(String::new());

pub fn is_status(args: &[String]) -> bool {
    command_name(args) == Some("status")
}

/// Viewing account/configuration state must not invalidate ongoing sync or indexing.
pub fn is_context_query(args: &[String]) -> bool {
    if !matches!(command_name(args), Some("account" | "space" | "config" | "agent-config" | "session")) {
        return false;
    }
    let Ok(cli) = Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(args.iter().cloned())) else {
        return false;
    };
    match cli.command {
        Some(Command::Account { action, .. }) => action == "list",
        Some(Command::Space { action, .. }) => matches!(action.as_str(), "list" | "members"),
        Some(Command::Config { data_dir: None, addr: None, autosync: None, cure_auto: None, rpc_parallelism: None })
        | Some(Command::AgentConfig { set: None })
        | Some(Command::Session { command: SessionCommand::List }) => true,
        _ => false,
    }
}

pub const GLOBAL_VALUE_FLAGS: [&str; 2] = ["--progress-id", "--model-task-id"];

// Keep client timeout classification and server routing on the same argv rules.
// A tracked request ID is a value even when it spells a command such as sync.
pub fn command_words(args: &[String]) -> impl Iterator<Item = &str> + '_ {
    let mut values = args.iter();
    std::iter::from_fn(move || {
        while let Some(arg) = values.next() {
            if GLOBAL_VALUE_FLAGS.contains(&arg.as_str()) {
                let _ = values.next();
            } else if !arg.starts_with('-') {
                return Some(arg.as_str());
            }
        }
        None
    })
}

pub fn command_name(args: &[String]) -> Option<&str> {
    command_words(args).next()
}

pub fn diary_lexical_mode(args: &[String]) -> bool {
    // Values after -- are literal queries, never runtime routing flags.
    let options=&args[..args.iter().position(|arg|arg=="--").unwrap_or(args.len())];
    let modes:Vec<&str>=options.iter().enumerate().filter_map(|(index,arg)| {
        if arg=="--mode" {Some(options.get(index+1).map(String::as_str).unwrap_or(""))}
        else {arg.strip_prefix("--mode=")}
    }).collect();
    modes==["lexical"]
}

pub fn needs_inference(args: &[String]) -> bool {
    matches!(command_name(args), Some("remember" | "recall" | "related" | "reembed" | "classify" | "update"))
        || (command_name(args) == Some("diary-search") && !diary_lexical_mode(args))
        || (command_name(args) == Some("model") && args.iter().any(|arg| matches!(arg.as_str(), "probe" | "load")))
}

pub fn current_url() -> String {
    WEB_URL
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clone()
}

pub fn runtime_dir_path() -> PathBuf {
    runtime_dir()
}

pub fn runtime_dir() -> PathBuf {
    respire_app::service::main_data_dir().join("runtime")
}

pub fn endpoint_path() -> PathBuf {
    runtime_dir().join("endpoint.json")
}

pub fn write_endpoint(url: &str) -> Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let body = json!({
        "v": PROTOCOL_V,
        "pid": std::process::id(),
        "bin": app_version::embedded(),
        "url": url,
    });
    std::fs::write(endpoint_path(), serde_json::to_vec_pretty(&body)?)?;
    Ok(())
}

pub fn endpoint_pid() -> Option<u32> {
    let text = std::fs::read_to_string(endpoint_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    data.get("pid")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
}
