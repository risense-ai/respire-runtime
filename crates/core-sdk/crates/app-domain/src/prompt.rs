//! prompt — first-run interactive prompts (register/login when args are omitted).
//!
//! TTY only. Non-interactive missing-arg errors stay unchanged (script/thin-shell contract).
//! `--json` exclusion is the caller's job (the json branch emits its own contract).

use std::io::{IsTerminal, Write};

use anyhow::{anyhow, Result};

pub fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

fn flush() {
    let _ = std::io::stdout().flush();
}

/// Plain one-line prompt (username and similar).
pub fn ask(prompt: &str) -> Result<String> {
    print!("  {prompt}");
    flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let v = line.trim().to_owned();
    if v.is_empty() {
        return Err(anyhow!("empty input, cancelled"));
    }
    Ok(v)
}

/// Hidden input (passwords).
pub fn ask_secret(prompt: &str) -> Result<String> {
    print!("  {prompt}");
    flush();
    let v = rpassword::read_password()?;
    Ok(v.trim().to_owned())
}

/// Hidden input plus confirmation (super password and other critical material).
pub fn ask_secret_twice(prompt: &str) -> Result<String> {
    let a = ask_secret(prompt)?;
    if a.is_empty() {
        return Err(anyhow!("empty input, cancelled"));
    }
    let b = ask_secret("  re-enter to confirm: ")?;
    if a != b {
        return Err(anyhow!("inputs do not match, cancelled"));
    }
    Ok(a)
}
