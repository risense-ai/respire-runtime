//! Open the hosted user dashboard without starting the local runtime.
use std::process::Command;

pub(crate) const DASHBOARD_URL: &str = "https://dash.rsrs.rs";

pub(crate) fn open_browser(url: &str) -> anyhow::Result<()> {
    let mut command = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", "start", ""]);
        command
    } else {
        Command::new("xdg-open")
    };
    command.arg(url).spawn().map_err(|error| {
        anyhow::anyhow!("could not open a browser ({error}); visit {url} manually")
    })?;
    Ok(())
}
