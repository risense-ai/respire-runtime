//! Pure RPC version and argv classification shared by client and server.

use clap::Parser;

use crate::cli_def::{Cli, Command, SessionCommand};

pub const PROTOCOL_V: u32 = 1;

pub fn is_status(args: &[String]) -> bool {
    command_name(args) == Some("status")
}

/// Viewing account/configuration state must not invalidate ongoing sync or indexing.
pub fn is_context_query(args: &[String]) -> bool {
    if !matches!(
        command_name(args),
        Some("account" | "space" | "config" | "agent-config" | "session")
    ) {
        return false;
    }
    let Ok(cli) =
        Cli::try_parse_from(std::iter::once("rsrs".to_owned()).chain(args.iter().cloned()))
    else {
        return false;
    };
    match cli.command {
        Some(Command::Account { action, .. }) => action == "list",
        Some(Command::Space { action, .. }) => matches!(action.as_str(), "list" | "members"),
        Some(Command::Config {
            data_dir: None,
            addr: None,
            autosync: None,
            cure_auto: None,
            rpc_parallelism: None,
        })
        | Some(Command::AgentConfig { set: None })
        | Some(Command::Session {
            command: SessionCommand::List,
        }) => true,
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
    let options = &args[..args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len())];
    let modes: Vec<&str> = options
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| {
            if arg == "--mode" {
                Some(options.get(index + 1).map(String::as_str).unwrap_or(""))
            } else {
                arg.strip_prefix("--mode=")
            }
        })
        .collect();
    modes == ["lexical"]
}

pub fn needs_inference(args: &[String]) -> bool {
    matches!(
        command_name(args),
        Some("remember" | "recall" | "related" | "reembed" | "classify" | "update")
    ) || (command_name(args) == Some("diary-search") && !diary_lexical_mode(args))
        || (command_name(args) == Some("model")
            && args
                .iter()
                .any(|arg| matches!(arg.as_str(), "probe" | "load")))
}
