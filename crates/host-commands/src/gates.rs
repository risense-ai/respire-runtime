//! Write/read gates over the shared clap command surface.
//!
//! Used by the CLI binary to decide what a read-only member, a switched-off
//! memory or a runtime RPC may execute; the runtime engine reuses the same
//! classification so both entry points cannot drift.

use crate::cli_def::{Command, QueryLogCmd, SessionCommand, SnapshotCmd};
use crate::metadata;

/// Rule: commands that change local store data. **The sync family is not a write** - it only moves existing data;
/// a read-only member must still pull memories others just stored (pull rewrite is the sync engine, not this gate).
/// Also not a write: recall/list/show/chain/diary/tree/status/audit/export/backup/
/// doctor/bench/query-log/taxonomy/agent-config/config/space(switch profile)/inject(writes external files).
pub fn is_write_command(c: &Command) -> bool {
    matches!(
        c,
        Command::Remember { .. }
            | Command::Update { .. }
            | Command::Metadata { command: metadata::Command::Enable { .. } | metadata::Command::Disable }
            | Command::Forget { .. }
            | Command::Restore { .. }
            | Command::Purge { .. }
            | Command::Attach { .. }
            | Command::Promote { .. }
            | Command::Demote { .. }
            | Command::Resort { .. }
            | Command::Split { .. }
            | Command::Import { .. }
            | Command::Extract { targets: false, .. }
            | Command::Repack
            | Command::RootCreate { .. }
            | Command::TreeCure { .. }
            | Command::TreeDeepen { .. }
            | Command::TreeFloat { .. }
            | Command::Defrag { .. }
            // Audit add (2026-09-20): these change the store or credentials; they were missing so read-only could bypass.
            // Grant writes access_grants (a read-only grant is itself a write);
            // Taxonomy --ensure creates roots; Keygen rotates key material (--force can wreck the store);
            // Model installs to disk; Account switch writes client.json; Login/Register/
            // Fivekeys/SuperReset/KeysExport change session and credentials; Session/Logout change session;
            // Space creates/deletes profiles and issues sessions.
            | Command::Grant { .. }
            | Command::Taxonomy { list: false, .. }
            | Command::Taxonomy { ensure: Some(_), .. }
            | Command::Keygen { .. }
            | Command::Model { .. }
            | Command::Login { .. }
            | Command::Register { .. }
            | Command::Fivekeys { .. }
            | Command::SuperReset { .. }
            | Command::KeysExport { .. }
            | Command::Logout { .. }
            | Command::Space { .. }
            | Command::Reembed { .. }
            | Command::Retitle { .. }
            | Command::RetitleMany { .. }
            | Command::Snapshot { cmd: SnapshotCmd::Restore { .. } | SnapshotCmd::ResumeSync { .. } | SnapshotCmd::Recover { .. } }
            | Command::SyncReset
            | Command::Doctor { fix: true, .. }
            | Command::SyncResolve { .. }
            | Command::SyncRestore { .. }
    )
}

/// Whether this command **changes the read-only switch itself** (agent.json `readonly` key).
///
/// Why (2026-09-20 audit): the read-only gate reads agent.json; if the command that edits it is not gated,
/// a read-only member can `agent-config --set readonly=false` and unlock themselves (reproduced).
/// So identify it separately, and in read-only **only allow keeping/enabling read-only, never turning it off**.
pub fn is_readonly_switch_off(c: &Command) -> bool {
    match c {
        Command::AgentConfig { set: Some(kv) } => {
            let (k, v) = kv.split_once('=').unwrap_or(("", ""));
            k.trim() == "readonly"
                && matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no")
        }
        _ => false,
    }
}

/// Fine-grained write check: these commands are **part write, part read**, so they cannot go wholesale into `is_write_command`.
///
/// Why (2026-09-20 audit): putting all of `Account`/`Session` on the list would block read-only members -
/// they should still `account list` and `session list`.
/// `Account`: list/use read, remove deletes a profile (write); `Session`: list read, revoke changes session (write).
/// Temporarily-off **allowlist**: memory is fully stopped, but admin/identity/inject infrastructure must still work.
///
/// Use an **allowlist** not a blocklist - a new command is refused by default, which matches "off";
/// missing an admin command is only a hassle (turn memory back on); missing a memory command is an accident.
pub fn is_off_allowed(c: &Command) -> bool {
    matches!(
        c,
        // Self-restore and inject (the only way out of off)
        Command::AgentConfig { .. } | Command::Inject { .. }
        // Status and doctor
        | Command::Status | Command::MemoryRevision | Command::Capabilities | Command::UpdateCheck { .. }
        | Command::Extract { targets: true, .. }
        // Infrastructure (web server, MCP shell, models, plugins, config)
        | Command::Web { .. } | Command::Mcp { .. } | Command::V | Command::ClassifyConfig { .. }
        | Command::Plugin { .. } | Command::Config { .. }
        // Sync reads and writes memory, so it is paused while disabled.
        // Identity / account / credentials / space admin
        | Command::Login { .. } | Command::Logout { .. } | Command::Register { .. }
        | Command::Account { .. } | Command::Session { .. }
        | Command::KeysExport { .. } | Command::SuperReset { .. } | Command::Fivekeys { .. }
        | Command::Secret { .. } | Command::Space { .. }
    )
}

pub fn is_write_command_fine(c: &Command) -> bool {
    match c {
        Command::Review { args } => args.writes(),
        Command::Account { action, .. } => {
            let a = action.trim().to_ascii_lowercase();
            a == "remove"
        }
        Command::Session { command } => matches!(command, SessionCommand::Revoke { .. }),
        Command::QueryLog {
            cmd: Some(QueryLogCmd::Mark { .. }),
            ..
        } => true,
        // share-import without --go only prints the candidate bill (read); --go writes
        Command::ShareImport { go, .. } => *go,
        _ => false,
    }
}
