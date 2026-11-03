//! Clap surface of the runtime lifecycle commands, shared with the runtime
//! engine. The lifecycle logic itself stays in the CLI's autostart module,
//! which re-exports these types so `crate::autostart::RuntimeCommand`
//! paths keep resolving.

use std::path::PathBuf;

use clap::Subcommand;


#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Serve in the foreground; service managers supervise this process.
    Run {
        #[arg(long, hide = true)]
        managed: Option<String>,
        #[arg(long, hide = true)]
        installation_root: Option<PathBuf>,
        #[arg(long, hide = true)]
        supervised_child: bool,
    },
    /// Start the host through its configured lifecycle owner.
    Start,
    /// Stop the owned host without automatic resurrection.
    Stop,
    /// Drain and restart the owned host through its configured lifecycle owner.
    Restart,
    /// Inspect the existing host without creating a profile or starting it.
    Status,
    /// Manage opt-in current-user sign-in startup; never installs a system service.
    Autostart {
        #[command(subcommand)]
        command: AutostartCommand,
    },
    /// Install the managed runtime release; the pinned version downloads by default.
    Install {
        /// Install from a local release archive instead of downloading.
        #[arg(long, value_name = "ARCHIVE")]
        file: Option<PathBuf>,
        /// Runtime version to record for a --file install (required with --file).
        #[arg(long)]
        version: Option<String>,
        /// Override the download mirror origin (http/https, no path or credentials).
        #[arg(long, value_name = "ORIGIN")]
        mirror: Option<String>,
    },
    /// List the managed runtime versions available on disk.
    List,
    /// Remove old managed runtime versions, keeping the current and one rollback.
    Clean,
    /// Fetch and install the runtime release pinned by runtime-pin.json.
    Update,
    /// Supervise the managed runtime child process (startup registration entry point).
    Supervise {
        /// Installation root that owns the supervised runtime registration.
        #[arg(long, value_name = "DIR")]
        data_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum AutostartCommand {
    /// Register current-user sign-in startup; start now only with --now.
    Enable {
        #[arg(long)]
        now: bool,
    },
    /// Disable future sign-in startup; stop the existing host only with --stop.
    Disable {
        #[arg(long)]
        stop: bool,
    },
    /// Remove only this installation's startup registration; preserve data and keys.
    Remove {
        #[arg(long)]
        stop: bool,
    },
    /// Read registration and runtime status without changing either.
    Status,
}
