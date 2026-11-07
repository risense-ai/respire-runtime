//! Default screen when `rsrs` is started with no command in a terminal.
//!
//! The home page polls the resident runtime. Keys are only arrows, digits,
//! Enter, and Space. Backspace is accepted only while a server address is
//! being typed, because a typo otherwise cannot be corrected.

use std::io::{stdout, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};
use serde_json::Value;

use crate::i18n::{self, Lang};

mod model_task;
mod model_weights;
mod recall_api;
mod recall_fusion;
mod recall_test;
mod text_input;

const FAST: Duration = Duration::from_millis(250);
const SLOW: Duration = Duration::from_secs(5);

enum Page {
    Home,
    Accounts,
    Migration,
    Server,
    Inject,
    Sync,
    Model,
    Workspace,
    Lang,
    Version,
    Web,
}

enum ConfirmKind {
    Switch(String),
    Migrate(String, String),
    Sync,
    InstallM3,
    UninstallM3,
    CancelModel(String),
    RestartM3(String, String),
    Engine(String),
    Weights(String, String),
    InstallVariant(String, String),
    InstallEngines,
    ProbeEngine,
    RecallMode(String),
    Workspace(String),
    Autosync(bool),
    Update(String, String),
}

enum Overlay {
    None,
    RecallApi(recall_api::Form),
    RecallFusion(recall_fusion::Form),
    ModelMirror(text_input::Input),
    ModelWeights(model_weights::Form),
    SavingWeights,
    HostModel,
    RecallTest(recall_test::Form),
    ModelTask(model_task::Task),
    Confirm {
        text: String,
        cursor: usize,
        kind: ConfirmKind,
    },
    Edit {
        buf: String,
        cursor: usize,
    },
}

struct InjectRow {
    id: String,
    name: String,
    state: String,
    seen: bool,
    checked: bool,
}

struct AccountRow {
    name: String,
    user: String,
    current: bool,
}

struct Live {
    inference: Value,
    index: Value,
    model_progress: Value,
    engine: String,
    model_settings: Value,
    connected: bool,
    error: String,
    notice: String,
    user: String,
    addr: String,
    autosync: bool,
    workspace: String,
    local_alive: u64,
    local_total: u64,
    phase: String,
    pulled: u64,
    pushed: u64,
    remote_alive: u64,
    conflicts: i64,
    pending: i64,
    pid: u32,
    url: String,
    runtime_version: String,
    doctor: Vec<(String, String, String)>,
    inject: Vec<InjectRow>,
    accounts: Vec<AccountRow>,
    fresh: usize,
    stale: usize,
    missing: usize,
    ver_line: String,
    update_spec: String,
}

struct App {
    login_requested: bool,
    migration_profiles: Vec<Value>,
    page: Page,
    cursor: usize,
    overlay: Overlay,
    live: Live,
    workspace_draft: usize,
    autosync_draft: bool,
    manager_pick: usize,
    shared: Arc<Mutex<Live>>,
    outcome: Arc<Mutex<Option<String>>>,
    model_outcome: Arc<Mutex<Option<String>>>,
}

// Odd revisions mean a write is in flight; changed revisions invalidate old reads.
static MODEL_REVISION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

static INJECT_REVISION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn run() -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        anyhow::bail!(i18n::text("need_tty"));
    }
    // Finish host startup before terminal rendering. Polling never takes over a
    // runtime, and host actions capture their diagnostics instead of drawing them.
    crate::rpc::ensure_daemon()?;
    enable_raw_mode()?;
    let mut terminal = setup()?;
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Mutex::new(Live::empty()));
    let worker_stop = Arc::clone(&stop);
    let worker_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_loop(worker_stop, worker_shared));
    let worker_stop = Arc::clone(&stop);
    let worker_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_details_loop(worker_stop, worker_shared));
    let worker_stop = stop.clone();
    let worker_shared = shared.clone();
    std::thread::spawn(move || refresh_inference_loop(worker_stop, worker_shared));
    let mut app = App::new(Arc::clone(&shared));
    let result = loop {
        if let Overlay::RecallTest(form) = &mut app.overlay {
            form.poll();
        }
        if let Overlay::RecallFusion(form) = &mut app.overlay {
            form.poll();
        }
        let api_saved = match &mut app.overlay {
            Overlay::RecallApi(form) => form.poll_saved(),
            _ => false,
        };
        if api_saved {
            app.overlay = Overlay::None;
            app.set_notice(t(
                "API \u{914d}\u{7f6e}\u{5df2}\u{4fdd}\u{5b58}\u{ff1b}\u{9009}\u{62e9}\u{9ad8}\u{8d28}\u{91cf}\u{6a21}\u{5f0f}\u{540e}\u{751f}\u{6548}",
                "API saved; select High quality to enable it",
            ));
        }
        if let Ok(mut slot) = app.outcome.lock() {
            if let Some(message) = slot.take() {
                // An older background action must not dismiss an in-flight save.
                if !matches!(app.overlay, Overlay::SavingWeights | Overlay::HostModel) {
                    app.overlay = Overlay::None;
                    app.set_notice(message);
                }
            }
        }
        if let Ok(mut slot) = app.model_outcome.lock() {
            if let Some(message) = slot.take() {
                app.overlay = Overlay::None;
                app.set_notice(message);
            }
        }
        if let Ok(guard) = shared.lock() {
            app.live = guard.clone();
        }
        if let Err(error) = terminal.draw(|frame| draw(frame, &app)) {
            break Err(error);
        }
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let event = event::read()?;
        if let Event::Paste(text) = &event {
            match &mut app.overlay {
                Overlay::RecallApi(form) => form.paste(text),
                Overlay::RecallFusion(form) => form.paste(text),
                Overlay::ModelMirror(input) => input.paste(text),
                Overlay::RecallTest(form) => form.paste(text),
                _ => {}
            }
        }
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Overlay::ModelMirror(input) = &mut app.overlay {
            if key.code == KeyCode::Esc {
                app.overlay = Overlay::None;
            } else if key.code == KeyCode::Enter {
                let value = input.text.trim().to_owned();
                let result = respire_commands::model_download::validate_mirror(&value)
                    .map_err(|e| e.to_string())
                    .and_then(|_| {
                        retrieval_action(&[
                            "agent-config",
                            "--set",
                            &format!("model_mirror={value}"),
                        ])
                        .map(|_| ())
                    });
                match result {
                    Ok(()) => {
                        app.overlay = Overlay::None;
                        app.set_notice(t(
                            "\u{4e0b}\u{8f7d}\u{6e90}\u{5df2}\u{4fdd}\u{5b58}",
                            "Download source saved",
                        ));
                        if let Some(id) = app.live.model_progress["id"]
                            .as_str()
                            .filter(|_| app.live.model_progress["active"] == true)
                        {
                            let id = id.to_owned();
                            ask(&mut app, t("\u{53d6}\u{6d88}\u{5f53}\u{524d}\u{4efb}\u{52a1}\u{ff0c}\u{4f7f}\u{7528}\u{6240}\u{9009}\u{4e0b}\u{8f7d}\u{6e90}\u{91cd}\u{65b0}\u{4e0b}\u{8f7d}\u{ff1f}", "Cancel the current task and restart using the selected source?"), ConfirmKind::RestartM3(id, value));
                        }
                    }
                    Err(error) => app.set_notice(error),
                }
            } else if matches!(key.code, KeyCode::Up | KeyCode::Down) {
                let presets = respire_commands::model_download::MIRRORS;
                let index = presets.iter().position(|v| *v == input.text).unwrap_or(0);
                let next = if key.code == KeyCode::Down {
                    (index + 1) % presets.len()
                } else {
                    (index + presets.len() - 1) % presets.len()
                };
                *input = text_input::Input::new(presets[next].to_owned());
            } else {
                input.key(key);
            }
            continue;
        }
        if let Overlay::RecallFusion(form) = &mut app.overlay {
            if form.key(key) {
                app.overlay = Overlay::None;
            }
            continue;
        }
        if let Overlay::RecallApi(form) = &mut app.overlay {
            if key.code == KeyCode::Esc && !form.saving() {
                app.overlay = Overlay::None;
            } else {
                form.key(key);
            }
            continue;
        }
        if let Overlay::RecallTest(form) = &mut app.overlay {
            if key.code == KeyCode::Esc {
                app.overlay = Overlay::None;
            } else {
                form.key(key);
            }
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            continue;
        }
        if handle(&mut app, key.code) {
            break Ok(());
        }
        if app.login_requested {
            app.login_requested = false;
            // Give secret prompts sole ownership of the normal terminal, then redraw the TUI.
            restore(&mut terminal)?;
            disable_raw_mode()?;
            let login = crate::login::run(None, None, None, None, true, false, None, false, false);
            enable_raw_mode()?;
            terminal = match setup() {
                Ok(terminal) => terminal,
                Err(error) => {
                    stop.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            };
            app.set_notice(match login {
                Ok(()) => t("\u{767b}\u{5f55}\u{6210}\u{529f}\u{ff1b}\u{8d26}\u{6237}\u{5df2}\u{9a8c}\u{8bc1}", "Signed in; account verified"),
                Err(error) => format!("{error:#}"),
            });
        }
    };
    stop.store(true, Ordering::Relaxed);
    restore(&mut terminal)?;
    disable_raw_mode()?;
    result.map_err(anyhow::Error::from)
}

impl Live {
    fn empty() -> Self {
        Self {
            inference: Value::Null,
            index: Value::Null,
            model_progress: Value::Null,
            engine: String::new(),
            model_settings: Value::Null,
            connected: false,
            error: String::new(),
            notice: String::new(),
            user: String::new(),
            addr: String::new(),
            autosync: true,
            workspace: "normal".to_owned(),
            local_alive: 0,
            local_total: 0,
            phase: "idle".to_owned(),
            pulled: 0,
            pushed: 0,
            remote_alive: 0,
            conflicts: 0,
            pending: 0,
            pid: 0,
            url: String::new(),
            runtime_version: String::new(),
            doctor: Vec::new(),
            inject: Vec::new(),
            accounts: Vec::new(),
            fresh: 0,
            stale: 0,
            missing: 0,
            ver_line: String::new(),
            update_spec: String::new(),
        }
    }

    fn clone(&self) -> Self {
        Self {
            inference: self.inference.clone(),
            index: self.index.clone(),
            model_progress: self.model_progress.clone(),
            engine: self.engine.clone(),
            model_settings: self.model_settings.clone(),
            connected: self.connected,
            error: self.error.clone(),
            notice: self.notice.clone(),
            user: self.user.clone(),
            addr: self.addr.clone(),
            autosync: self.autosync,
            workspace: self.workspace.clone(),
            local_alive: self.local_alive,
            local_total: self.local_total,
            phase: self.phase.clone(),
            pulled: self.pulled,
            pushed: self.pushed,
            remote_alive: self.remote_alive,
            conflicts: self.conflicts,
            pending: self.pending,
            pid: self.pid,
            url: self.url.clone(),
            runtime_version: self.runtime_version.clone(),
            doctor: self.doctor.clone(),
            inject: self.inject.iter().map(InjectRow::clone_row).collect(),
            accounts: self.accounts.iter().map(AccountRow::clone_row).collect(),
            fresh: self.fresh,
            stale: self.stale,
            missing: self.missing,
            ver_line: self.ver_line.clone(),
            update_spec: self.update_spec.clone(),
        }
    }
}

impl InjectRow {
    fn clone_row(&self) -> Self {
        Self {
            id: self.id.clone(),
            name: self.name.clone(),
            state: self.state.clone(),
            seen: self.seen,
            checked: self.checked,
        }
    }
}

impl AccountRow {
    fn clone_row(&self) -> Self {
        Self {
            name: self.name.clone(),
            user: self.user.clone(),
            current: self.current,
        }
    }
}

impl App {
    fn new(shared: Arc<Mutex<Live>>) -> Self {
        Self {
            login_requested: false,
            migration_profiles: Vec::new(),
            page: Page::Home,
            cursor: 0,
            overlay: Overlay::None,
            live: Live::empty(),
            workspace_draft: 0,
            autosync_draft: true,
            manager_pick: 0,
            shared,
            outcome: Arc::new(Mutex::new(None)),
            model_outcome: Arc::new(Mutex::new(None)),
        }
    }

    fn set_notice(&self, text: impl Into<String>) {
        if let Ok(mut guard) = self.shared.lock() {
            guard.notice = text.into();
        }
    }
}

fn zh() -> bool {
    i18n::lang() == Lang::Zh
}

fn t(zh_text: &str, en_text: &str) -> String {
    if zh() {
        zh_text.to_owned()
    } else {
        en_text.to_owned()
    }
}

fn rpc(args: &[&str]) -> Result<Value, String> {
    let owned: Vec<String> = args.iter().copied().map(str::to_owned).collect();
    crate::rpc::query_existing_json(owned).map_err(|err| format!("{err:#}"))
}

fn retrieval_action(args: &[&str]) -> Result<Value, String> {
    // Configuration reads and writes are host-owned, including fusion read-back.
    if matches!(args, ["agent-config"] | ["agent-config", "--set", _]) {
        return host_command(args);
    }
    checked_result(rpc(args)?)
}

fn checked_result(result: Value) -> Result<Value, String> {
    if matches!(result["status"].as_str(), Some("ok" | "skip")) {
        return Ok(result);
    }
    let errors = result["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    if errors.contains("model operation cancelled") {
        return Err(t(
            "\u{5df2}\u{53d6}\u{6d88}\u{ff1b}\u{5f53}\u{524d}\u{7d22}\u{5f15}\u{4fdd}\u{6301}\u{4e0d}\u{53d8}",
            "Cancelled; current index unchanged",
        ));
    }
    Err(if errors.is_empty() {
        format!("Command failed: {}", result["status"])
    } else {
        errors
    })
}

fn switch_account(name: &str) -> Result<String, String> {
    let switched = host_command(&["account", "use", name])?;
    let expected_dir = switched["summary"]["dir"]
        .as_str()
        .ok_or_else(|| "Profile switch did not return its directory".to_owned())?;
    let accounts = host_command(&["account", "list"])?;
    let actual = accounts["details"]["accounts"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["current"] == true))
        .ok_or_else(|| "Host did not report its current account".to_owned())?;
    if actual["name"] != name || actual["dir"] != expected_dir {
        return Err("Host account does not match the requested profile".to_owned());
    }
    Ok(t(
        "\u{5df2}\u{5207}\u{6362}\u{8d26}\u{6237}",
        "Account switched",
    ))
}

fn host_command(args: &[&str]) -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = std::process::Command::new(executable);
    command.arg("--json").args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command.output().map_err(|error| error.to_string())?;
    // Diagnostic failures are display rows, not a reason to hide the report.
    if args == ["doctor"] {
        if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
            if value["command"] == "doctor" {
                return Ok(value);
            }
        }
    }
    if !output.status.success() {
        if let Ok(value) = serde_json::from_slice(&output.stdout) {
            if let Err(error) = checked_result(value) {
                return Err(error);
            }
        }
        return Err(format!(
            "Host action failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let envelope = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    checked_result(envelope)
}

fn refresh_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let mut next = Live::empty();
        if let Some((pid, url, version)) = crate::rpc::runtime_brief() {
            next.pid = pid;
            next.url = url;
            next.runtime_version = version;
        }
        match rpc(&["status"]) {
            Ok(envelope) if envelope["status"] == "ok" => {
                let summary = &envelope["summary"];
                next.index = summary["retrieval_index"].clone();
                next.model_progress = summary["model_operation"].clone();
                next.connected = true;
                next.user = summary["session"]["user"].as_str().unwrap_or("").to_owned();
                next.addr = summary["server_addr"].as_str().unwrap_or("").to_owned();
                next.autosync = summary["autosync"].as_bool().unwrap_or(true);
                next.workspace = summary["workspace"].as_str().unwrap_or("normal").to_owned();
                next.local_alive = summary["local_alive"].as_u64().unwrap_or(0);
                next.local_total = summary["local_total"].as_u64().unwrap_or(0);
                let live = &summary["sync_live"];
                next.phase = live["phase"].as_str().unwrap_or("idle").to_owned();
                next.pulled = live["pulled"].as_u64().unwrap_or(0);
                next.pushed = live["pushed"].as_u64().unwrap_or(0);
                next.remote_alive = live["remote_alive"].as_u64().unwrap_or(0);
                next.conflicts = live["conflicts"].as_i64().unwrap_or(0);
                next.pending = live["pending"].as_i64().unwrap_or(0);
                if next.phase == "err" {
                    next.error = live["error"].as_str().unwrap_or("").to_owned();
                }
            }
            Ok(envelope) => next.error = envelope["errors"].to_string(),
            Err(error) => {
                next.connected = false;
                next.error = error;
            }
        }
        if !next.connected {
            next.runtime_version.clear();
        }
        if let Ok(mut guard) = shared.lock() {
            next.inference = guard.inference.clone();
            next.notice = guard.notice.clone();
            next.ver_line = guard.ver_line.clone();
            next.update_spec = guard.update_spec.clone();
            next.inject = guard.inject.iter().map(InjectRow::clone_row).collect();
            next.accounts = guard.accounts.iter().map(AccountRow::clone_row).collect();
            next.doctor = guard.doctor.clone();
            next.engine = guard.engine.clone();
            next.model_settings = guard.model_settings.clone();
            next.fresh = guard.fresh;
            next.stale = guard.stale;
            next.missing = guard.missing;
            *guard = next;
        }
        std::thread::sleep(FAST.saturating_sub(started.elapsed()));
    }
}

fn refresh_inference_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    while !stop.load(Ordering::Relaxed) {
        let inference = match crate::net_rpc::health() {
            Ok(health) => health.inference,
            Err(error) => serde_json::json!({"phase":"unavailable","error":format!("{error:#}")}),
        };
        if let Ok(mut state) = shared.lock() {
            state.inference = inference;
        }
        std::thread::sleep(FAST);
    }
}

fn refresh_details_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    let mut slow_at = Instant::now() - SLOW;
    while !stop.load(Ordering::Relaxed) {
        let ready = shared.lock().map(|live| live.connected).unwrap_or(false);
        if !ready || slow_at.elapsed() < SLOW {
            std::thread::sleep(FAST);
            continue;
        }
        slow_at = Instant::now();
        let mut next = match shared.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return,
        };
        if let Ok(envelope) = host_command(&["account", "list"]) {
            if let Some(rows) = envelope["details"]["accounts"].as_array() {
                next.accounts.clear();
                for row in rows {
                    next.accounts.push(AccountRow {
                        name: row["name"].as_str().unwrap_or("").to_owned(),
                        user: row["user"].as_str().unwrap_or("").to_owned(),
                        current: row["current"].as_bool().unwrap_or(false),
                    });
                }
            }
        }
        let revision = INJECT_REVISION.load(Ordering::Acquire);
        if revision % 2 == 0 {
            if let Ok(rows) = read_inject_rows() {
                if let Ok(mut guard) = shared.lock() {
                    if INJECT_REVISION.load(Ordering::Acquire) == revision {
                        set_inject_rows(&mut guard, rows);
                    }
                }
            }
        }

        if let Ok(envelope) = host_command(&["doctor"]) {
            if let Ok(envelope) = serde_json::from_value::<crate::output::ResultEnvelope>(envelope)
            {
                next.doctor = envelope
                    .items
                    .iter()
                    .map(|item| {
                        (
                            item.name.clone(),
                            item.status.as_str().to_owned(),
                            envelope.human_item_value(item),
                        )
                    })
                    .collect();
            }
        }
        let model_revision = MODEL_REVISION.load(Ordering::Acquire);
        let model_read = retrieval_action(&["model", "engine"]).and_then(checked_result);
        if let Ok(envelope) = &model_read {
            next.engine = envelope["summary"]["engine"]
                .as_str()
                .unwrap_or("")
                .to_owned();
            next.model_settings = envelope["summary"].clone();
        }
        if let Ok(mut guard) = shared.lock() {
            if model_read.is_ok()
                && model_revision % 2 == 0
                && MODEL_REVISION.load(Ordering::Acquire) == model_revision
            {
                guard.engine = next.engine;
                guard.model_settings = next.model_settings;
            }
            guard.accounts = next.accounts;
            guard.doctor = next.doctor;
        }
    }
}

fn handle(app: &mut App, code: KeyCode) -> bool {
    if matches!(app.overlay, Overlay::SavingWeights | Overlay::HostModel) {
        return false;
    }
    if matches!(app.overlay, Overlay::ModelWeights(_)) {
        if code == KeyCode::Char('7') {
            toggle_lang(app);
            return false;
        }
        model_weights_key(app, code);
        return false;
    }
    if let Overlay::ModelTask(task) = &app.overlay {
        if matches!(code, KeyCode::Esc | KeyCode::Char('c' | 'C')) {
            task.cancel.store(true, Ordering::Release);
        }
        return false;
    }
    if code == KeyCode::Esc {
        if !matches!(app.overlay, Overlay::None) {
            app.overlay = Overlay::None;
            return false;
        }
        return go_back(app);
    }
    if code == KeyCode::Char('7') && !matches!(app.overlay, Overlay::Edit { .. }) {
        toggle_lang(app);
        return false;
    }
    if !app.live.connected {
        return code == KeyCode::Char('0');
    }
    if matches!(app.overlay, Overlay::Edit { .. }) {
        return edit_key(app, code);
    }
    if matches!(app.overlay, Overlay::Confirm { .. }) {
        return confirm_key(app, code);
    }
    match app.page {
        Page::Home => home_key(app, code),
        Page::Accounts => list_key(app, code, app.live.accounts.len() + 2, |app, code| {
            account_key(app, code)
        }),
        Page::Migration => list_key(app, code, app.migration_profiles.len(), migration_key),
        Page::Server => server_key(app, code),
        Page::Inject => list_key(app, code, app.live.inject.len() + 2, |app, code| {
            inject_key(app, code)
        }),
        Page::Sync => sync_key(app, code),
        Page::Model => list_key(
            app,
            code,
            15 + model_engines().len() + usize::from(cfg!(windows)),
            |app, code| model_key(app, code),
        ),
        Page::Workspace => workspace_key(app, code),
        Page::Lang => list_key(app, code, 2, |app, code| lang_key(app, code)),
        Page::Version => version_key(app, code),
        Page::Web => web_key(app, code),
    }
}

fn go_back(app: &mut App) -> bool {
    if matches!(app.page, Page::Home) {
        return true;
    }
    app.page = Page::Home;
    false
}

fn toggle_lang(app: &mut App) {
    let next = if zh() { Lang::En } else { Lang::Zh };
    match i18n::set_lang(next) {
        Ok(()) => app.set_notice(t(
            "\u{8bed}\u{8a00}\u{5df2}\u{5207}\u{6362}",
            "Language saved",
        )),
        Err(error) => app.set_notice(error.to_string()),
    }
}

fn home_key(app: &mut App, code: KeyCode) -> bool {
    let n = 10;
    match code {
        KeyCode::Up => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down => app.cursor = (app.cursor + 1).min(n - 1),
        KeyCode::Char('0') => return true,
        KeyCode::Char(ch) if ch.is_ascii_digit() => {
            let number = (ch as u8 - b'0') as usize;
            if (1..=9).contains(&number) {
                open_home(app, number - 1);
            }
        }
        KeyCode::Enter if app.cursor == 9 => return true,
        KeyCode::Enter => open_home(app, app.cursor),
        _ => {}
    }
    false
}

fn open_home(app: &mut App, index: usize) {
    app.cursor = 0;
    app.workspace_draft = match app.live.workspace.as_str() {
        "readonly" => 1,
        "off" => 2,
        _ => 0,
    };
    app.autosync_draft = app.live.autosync;
    app.page = match index {
        0 => Page::Accounts,
        1 => Page::Server,
        2 => Page::Inject,
        3 => Page::Sync,
        4 => Page::Model,
        5 => Page::Workspace,
        6 => Page::Lang,
        7 => Page::Version,
        _ => Page::Web,
    };
}

fn list_key(
    app: &mut App,
    code: KeyCode,
    content: usize,
    mut on_enter: impl FnMut(&mut App, KeyCode),
) -> bool {
    let total = content + 1;
    match code {
        KeyCode::Char('0') => {
            app.page = Page::Home;
            false
        }
        KeyCode::Up => {
            app.cursor = app.cursor.saturating_sub(1);
            false
        }
        KeyCode::Down => {
            if total > 0 {
                app.cursor = (app.cursor + 1).min(total - 1);
            }
            false
        }
        KeyCode::Enter if app.cursor == content => {
            app.page = Page::Home;
            false
        }
        other if app.cursor < content => {
            on_enter(app, other);
            false
        }
        _ => false,
    }
}

fn account_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Enter {
        return;
    }
    if app.cursor == app.live.accounts.len() + 1 {
        app.login_requested = true;
        return;
    }
    if app.cursor == app.live.accounts.len() {
        match crate::profile_discovery::list_legacy_profiles() {
            Ok(value) => {
                app.migration_profiles = value["profiles"]
                    .as_array()
                    .map(|profiles| {
                        profiles
                            .iter()
                            .filter(|profile| profile["migrated_to"].is_null())
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                app.cursor = 0;
                app.page = Page::Migration;
            }
            Err(error) => app.set_notice(format!("{error:#}")),
        }
        return;
    }
    let Some(row) = app.live.accounts.get(app.cursor) else {
        return;
    };
    if row.current {
        app.set_notice(t(
            "\u{5df2}\u{7ecf}\u{662f}\u{5f53}\u{524d}\u{8d26}\u{6237}",
            "Already the active account",
        ));
        return;
    }
    let name = row.name.clone();
    ask(
        app,
        t(
            &format!("\u{5207}\u{6362}\u{5230}\u{8d26}\u{6237} {name}\u{ff1f}",),
            &format!("Switch to account {name}?"),
        ),
        ConfirmKind::Switch(name),
    );
}

fn migration_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Enter {
        return;
    }
    let Some(row) = app.migration_profiles.get(app.cursor) else {
        return;
    };
    if !row["migrated_to"].is_null() {
        app.set_notice(t("\u{8be5}\u{6765}\u{6e90}\u{5df2}\u{8fc1}\u{79fb}\u{ff0c}\u{4e0d}\u{4f1a}\u{91cd}\u{590d}\u{590d}\u{5236}", "Already migrated; no duplicate copy"));
        return;
    }
    let (Some(id), Some(account)) = (row["source_id"].as_str(), row["account"].as_str()) else {
        return;
    };
    let id = id.to_owned();
    let account = account.to_owned();
    ask(app, t(&format!("\u{5c06}\u{6240}\u{9009}\u{65e7}\u{8d26}\u{6237}\u{590d}\u{5236}\u{4e3a} {account}\u{ff1f}\u{5f53}\u{524d}\u{8d26}\u{6237}\u{4fdd}\u{6301}\u{4e0d}\u{53d8}\u{3002}"),
        &format!("Copy the selected legacy account into {account}? Current account stays active.")),
        ConfirmKind::Migrate(id, account));
}

fn server_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = 0,
        KeyCode::Down => app.cursor = 1,
        KeyCode::Enter if app.cursor == 1 => app.page = Page::Home,
        KeyCode::Enter => {
            app.overlay = Overlay::Edit {
                buf: app.live.addr.clone(),
                cursor: app.live.addr.chars().count(),
            };
        }
        _ => {}
    }
    false
}

fn inject_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Char(' ') && code != KeyCode::Enter {
        return;
    }
    if INJECT_REVISION.load(Ordering::Acquire) % 2 != 0 {
        return;
    }
    let batch = app.cursor < 2;
    let remove = app.cursor == 1;
    let selected = if batch {
        app.live
            .inject
            .iter()
            .filter(|row| row.checked)
            .collect::<Vec<_>>()
    } else {
        app.live.inject.get(app.cursor - 2).into_iter().collect()
    };
    let ids: Vec<(String, bool)> = selected
        .iter()
        .map(|row| (row.id.clone(), if batch { remove } else { row.checked }))
        .collect();
    if ids.is_empty() {
        app.set_notice(t(
            "\u{6ca1}\u{6709}\u{5df2}\u{5b89}\u{88c5}\u{7684}\u{63d0}\u{793a}\u{8bcd}",
            "No installed prompts",
        ));
        return;
    }
    INJECT_REVISION.fetch_add(1, Ordering::AcqRel);
    app.set_notice(t(
        "\u{6b63}\u{5728}\u{5904}\u{7406}\u{63d0}\u{793a}\u{8bcd}",
        "Updating prompts",
    ));
    let slot = Arc::clone(&app.outcome);
    let shared = Arc::clone(&app.shared);
    std::thread::spawn(move || {
        let mut succeeded = 0;
        let mut errors = Vec::new();
        for (id, remove) in &ids {
            let result = if *remove {
                host_command(&["inject", "--remove", "--id", id])
            } else {
                host_command(&["inject", "--id", id])
            }
            .and_then(inject_result);
            match result {
                Ok(_) => succeeded += 1,
                Err(error) => errors.push(format!("{id}: {error}")),
            }
        }
        match read_inject_rows() {
            Ok(rows) => {
                if let Ok(mut guard) = shared.lock() {
                    set_inject_rows(&mut guard, rows);
                }
            }
            Err(error) => errors.push(error),
        }
        let mut message = t(
            &format!("\u{63d0}\u{793a}\u{8bcd}\u{5904}\u{7406}\u{5b8c}\u{6210}\u{ff1a}\u{6210}\u{529f} {succeeded}/{}", ids.len()),
            &format!("Prompts finished: {succeeded}/{} succeeded", ids.len()),
        );
        if !errors.is_empty() {
            message.push_str(&format!("; {}", errors.join("; ")));
        }
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(message);
        }
        INJECT_REVISION.fetch_add(1, Ordering::Release);
    });
}

fn inject_result(envelope: Value) -> Result<Value, String> {
    if envelope["status"] != "ok" {
        return Err(envelope["errors"].to_string());
    }
    Ok(envelope)
}

fn read_inject_rows() -> Result<Vec<InjectRow>, String> {
    let envelope = inject_result(host_command(&["inject", "--targets"])?)?;
    let rows = envelope["details"]
        .as_array()
        .ok_or("Missing inject targets")?;
    Ok(rows
        .iter()
        .map(|row| {
            let state = row["state"].as_str().unwrap_or("").to_owned();
            InjectRow {
                checked: state == "fresh" || state == "stale",
                id: row["id"].as_str().unwrap_or("").to_owned(),
                name: row["name"].as_str().unwrap_or("").to_owned(),
                seen: row["likely_installed"].as_bool().unwrap_or(false),
                state,
            }
        })
        .collect())
}

fn set_inject_rows(live: &mut Live, rows: Vec<InjectRow>) {
    live.fresh = rows.iter().filter(|row| row.state == "fresh").count();
    live.stale = rows.iter().filter(|row| row.state == "stale").count();
    live.missing = rows.len() - live.fresh - live.stale;
    live.inject = rows;
}

fn sync_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down => app.cursor = (app.cursor + 1).min(2),
        KeyCode::Left | KeyCode::Right if app.cursor == 1 => {
            app.autosync_draft = !app.autosync_draft
        }
        KeyCode::Enter if app.cursor == 2 => app.page = Page::Home,
        KeyCode::Enter if app.cursor == 0 => ask(
            app,
            t(
                "\u{73b0}\u{5728}\u{540c}\u{6b65}\u{4e00}\u{6b21}\u{ff1f}",
                "Sync once now?",
            ),
            ConfirmKind::Sync,
        ),
        KeyCode::Enter if app.cursor == 1 => {
            let on = app.autosync_draft;
            ask(
                app,
                t(
                    if on {
                        "\u{6253}\u{5f00}\u{81ea}\u{52a8}\u{540c}\u{6b65}\u{ff1f}"
                    } else {
                        "\u{5173}\u{95ed}\u{81ea}\u{52a8}\u{540c}\u{6b65}\u{ff1f}"
                    },
                    if on {
                        "Turn auto-sync on?"
                    } else {
                        "Turn auto-sync off?"
                    },
                ),
                ConfirmKind::Autosync(on),
            );
        }
        _ => {}
    }
    false
}

fn model_engines() -> &'static [&'static str] {
    if cfg!(any(windows, target_os = "macos")) {
        &["cpu", "gpu", "npu"]
    } else {
        &["cpu"]
    }
}

fn selected_model_mirror() -> Result<String> {
    Ok(respire_client_host::settings::mirror_from_env()?.unwrap_or_else(|| "auto".to_owned()))
}

fn cancel_model(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Ok(());
    }
    let started = Instant::now();
    let mut cancellation_accepted = false;
    let mut cancel_sent = false;
    loop {
        let progress = crate::rpc::model_control(id, !cancel_sent)
            .map_err(|error| error.to_string())?;
        cancel_sent = true;
        if progress["stale"] == true {
            // The original task finished after accepting cancellation. A newly
            // scheduled task must not be cancelled or reported as its failure.
            if cancellation_accepted {
                return Ok(());
            }
            return Err(t("\u{6a21}\u{578b}\u{4efb}\u{52a1}\u{5df2}\u{53d8}\u{5316}\u{ff1b}\u{5237}\u{65b0}\u{8fdb}\u{5ea6}\u{540e}\u{91cd}\u{8bd5}", "The model task changed; refresh progress and retry"));
        }
        cancellation_accepted |= progress["cancelled"] == true;
        if progress["active"] != true {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(45) {
            return Err(t("\u{53d6}\u{6d88}\u{5c1a}\u{672a}\u{5b8c}\u{6210}\u{ff1b}\u{7b49}\u{5f85}\u{5f53}\u{524d}\u{7f51}\u{7edc}\u{8bfb}\u{53d6}\u{7ed3}\u{675f}\u{540e}\u{91cd}\u{8bd5}", "Cancellation is still pending; wait for the current network read before retrying"));
        }
        std::thread::sleep(FAST);
    }
}

fn model_key(app: &mut App, code: KeyCode) {
    if let Err(error) = try_model_key(app, code) {
        app.set_notice(format!("{error:#}"));
    }
}

fn try_model_key(app: &mut App, code: KeyCode) -> Result<()> {
    if code != KeyCode::Enter {
        return Ok(());
    }
    match app.cursor {
        0 => ask(
            app,
            t(
                "\u{5b89}\u{88c5}\u{6216}\u{6821}\u{9a8c} BGE-M3 \u{91cf}\u{5316}\u{6a21}\u{578b}\u{ff08}543 MiB\u{ff09}\u{ff1f}\u{6821}\u{9a8c}\u{901a}\u{8fc7}\u{5219}\u{8df3}\u{8fc7}\u{3002}",
                "Install or verify BGE-M3 quantized (543 MiB model)? Verified files are skipped.",
            ),
            ConfirmKind::InstallM3,
        ),
        1 => ask(
            app,
            t(
                "\u{5378}\u{8f7d} BGE-M3 \u{5e76}\u{5220}\u{9664}\u{6a21}\u{578b}\u{6587}\u{4ef6}\u{ff1f}\u{5378}\u{8f7d}\u{540e} recall \u{9700}\u{8981}\u{91cd}\u{65b0}\u{5b89}\u{88c5}\u{3002}",
                "Uninstall BGE-M3 and delete its files? Recall will need a reinstall.",
            ),
            ConfirmKind::UninstallM3,
        ),
        2 => {
            let current = selected_model_mirror()?;
            app.overlay = Overlay::ModelMirror(text_input::Input::new(current));
        }
        cursor => {
            let engines = model_engines();
            if let Some(engine) = cursor.checked_sub(3).and_then(|index| engines.get(index)) {
                run_confirm(app, ConfirmKind::Engine((*engine).to_owned()));
            } else if cfg!(windows) && cursor == 3 + engines.len() {
                ask(
                    app,
                    t(
                        "\u{901a}\u{8fc7} Windows ML \u{4e0b}\u{8f7d}\u{517c}\u{5bb9}\u{7684} NPU \u{63a8}\u{7406}\u{5f15}\u{64ce}\u{ff1f}",
                        "Download compatible NPU providers through Windows ML?",
                    ),
                    ConfirmKind::InstallEngines,
                );
            } else if cursor == 3 + engines.len() + usize::from(cfg!(windows)) {
                run_confirm(app, ConfirmKind::ProbeEngine);
            } else {
                let index = 4 + engines.len() + usize::from(cfg!(windows));
                match cursor.checked_sub(index) {
                    Some(0) => run_confirm(app, ConfirmKind::RecallMode("fast".to_owned())),
                    Some(1) if !recall_api::ready()? => {
                        app.overlay = Overlay::RecallApi(recall_api::Form::new()?);
                        app.set_notice(t("\u{8bf7}\u{5148}\u{914d}\u{7f6e}\u{9ad8}\u{8d28}\u{91cf}\u{53ec}\u{56de} API", "Configure the recall API first"));
                    }
                    Some(1) => ask(
                        app,
                        t(
                            "\u{542f}\u{7528}\u{9ad8}\u{8d28}\u{91cf}\u{53ec}\u{56de}\u{ff1f}\u{67e5}\u{8be2}\u{548c}\u{5019}\u{9009}\u{6807}\u{9898}\u{5c06}\u{53d1}\u{9001}\u{5230}\u{5df2}\u{914d}\u{7f6e}\u{7684}\u{6a21}\u{578b}\u{670d}\u{52a1}\u{ff1b}\u{5931}\u{8d25}\u{65f6}\u{9000}\u{56de}\u{672c}\u{5730}\u{7ed3}\u{679c}\u{3002}",
                            "Enable high-quality recall? Queries and candidate titles go to your configured model service; failures use local results.",
                        ),
                        ConfirmKind::RecallMode("quality".to_owned()),
                    ),
                    Some(2) => app.overlay = Overlay::RecallApi(recall_api::Form::new()?),
                    Some(3) => app.overlay = Overlay::RecallTest(recall_test::Form::new("fast")),
                    Some(4) => app.overlay = Overlay::RecallTest(recall_test::Form::new("quality")),
                    Some(5) => {
                        if let Some(id) = app.live.model_progress["id"].as_str().filter(|_| app.live.model_progress["active"] == true) {
                            let id = id.to_owned();
                            ask(app, t("\u{53d6}\u{6d88}\u{5f53}\u{524d}\u{6a21}\u{578b}\u{4efb}\u{52a1}\u{ff1f}\u{5df2}\u{5b8c}\u{6210}\u{7684}\u{6a21}\u{578b}\u{6587}\u{4ef6}\u{548c}\u{539f}\u{7d22}\u{5f15}\u{4f1a}\u{4fdd}\u{7559}\u{3002}", "Cancel the current model task? Completed files and the original index are kept."), ConfirmKind::CancelModel(id));
                        } else { app.set_notice(t("\u{6ca1}\u{6709}\u{6b63}\u{5728}\u{8fd0}\u{884c}\u{7684}\u{6a21}\u{578b}\u{4efb}\u{52a1}", "No model task is running")); }
                    }
                    Some(6) => {
                        let id = app.live.model_progress["id"].as_str().unwrap_or("").to_owned();
                        ask(app, t("\u{53d6}\u{6d88}\u{5f53}\u{524d}\u{4efb}\u{52a1}\u{5e76}\u{4ece}\u{6240}\u{9009}\u{4e0b}\u{8f7d}\u{6e90}\u{91cd}\u{65b0}\u{4e0b}\u{8f7d}\u{672a}\u{5b8c}\u{6210}\u{6587}\u{4ef6}\u{ff1f}", "Cancel the current task and redownload unfinished files from the selected source?"), ConfirmKind::RestartM3(id, selected_model_mirror()?));
                    }
                    Some(7) => app.overlay = Overlay::RecallTest(recall_test::Form::new("benchmark")),
                    Some(8) => match model_weights::Form::new(&app.live.model_settings) {
                        Ok(form) => app.overlay = Overlay::ModelWeights(form),
                        Err(error) => app.set_notice(format!("{error:#}")),
                    },
                    Some(9) => match recall_fusion::Form::new() {
                        Ok(form) => app.overlay = Overlay::RecallFusion(form),
                        Err(error) => app.set_notice(error),
                    },
                    Some(10) => app.page = Page::Home,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn model_weights_key(app: &mut App, code: KeyCode) {
    let Overlay::ModelWeights(form) = &mut app.overlay else {
        return;
    };
    let action = form.key(code);
    let (engine, variant) = form.selection();
    let variant = variant.to_owned();
    let size = form.selected_size();
    match action {
        Some(model_weights::Action::Back) => app.overlay = Overlay::None,
        Some(model_weights::Action::Save) => {
            if !model_engines().contains(&engine) {
                app.set_notice(t("\u{6b64}\u{7cfb}\u{7edf}\u{4e0d}\u{652f}\u{6301}\u{8be5}\u{5f15}\u{64ce}\u{ff1b}\u{8bf7}\u{9009}\u{62e9} CPU", "This OS does not support that engine; choose CPU"));
            } else if !model_weights::Form::present(&app.live.model_settings, &variant) {
                app.set_notice(t("\u{8bf7}\u{5148}\u{4e0b}\u{8f7d}\u{6240}\u{9009}\u{6743}\u{91cd}\u{ff1b}\u{4e0d}\u{4f1a}\u{81ea}\u{52a8}\u{4e0b}\u{8f7d}\u{6216}\u{4fdd}\u{5b58}", "Download the selected weights first; nothing was downloaded or saved"));
            } else {
                ask(app, t(&format!("\u{6821}\u{9a8c}\u{5e76}\u{52a0}\u{8f7d} {engine} / {variant}\u{ff1f}\u{8bd5}\u{63a8}\u{7406}\u{6210}\u{529f}\u{540e}\u{4fdd}\u{5b58}\u{ff1b}\u{4e0d}\u{4f1a}\u{4e0b}\u{8f7d}\u{3002}"),
                    &format!("Validate and load {engine} / {variant}? Save only after trial inference succeeds; no download.")),
                    ConfirmKind::Weights(engine.to_owned(), variant));
            }
        }
        Some(model_weights::Action::Install) => {
            let mib = size as f64 / 1048576.0;
            ask(app, t(&format!("\u{4e0b}\u{8f7d} {variant}\u{ff08}{mib:.0} MiB\u{ff09}\u{ff1f}\u{57fa}\u{7840}\u{6a21}\u{578b}\u{53ca} CPU \u{5bb9}\u{5668}\u{53ef}\u{80fd}\u{53e6}\u{9700}\u{5404} 543 MiB\u{ff0c}tokenizer \u{7ea6} 17 MiB\u{ff1b}\u{5df2}\u{9a8c}\u{8bc1}\u{6587}\u{4ef6}\u{8df3}\u{8fc7}\u{3002}\u{53ea}\u{4e0b}\u{8f7d}\u{ff0c}\u{4e0d}\u{4fdd}\u{5b58}\u{9009}\u{62e9}\u{3002}"),
                    &format!("Download {variant} ({mib:.0} MiB)? Baseline and CPU container may each need another 543 MiB plus a 17 MiB tokenizer; verified files are skipped. Downloads only; selection is not saved.")),
                    ConfirmKind::InstallVariant(engine.to_owned(), variant));
        }
        None => {}
    }
}

fn save_model_settings_with(
    engine: &str,
    variant: Option<&str>,
    mut action: impl FnMut(&[&str]) -> Result<Value, String>,
) -> Result<Value, String> {
    let current;
    let variant = if let Some(variant) = variant {
        variant
    } else {
        current = checked_result(action(&["model", "engine"])?)?;
        current["summary"]["model"].as_str().ok_or_else(|| {
            t(
                "\u{65e0}\u{6cd5}\u{8bfb}\u{53d6}\u{5f53}\u{524d}\u{6743}\u{91cd}",
                "Cannot read current weights",
            )
        })?
    };
    let args = ["model", "load", engine, "--model", variant];
    let loaded = checked_result(action(&args)?)?;
    if loaded["summary"]["loaded"] != true
        || loaded["summary"]["validated"] != true
        || loaded["summary"]["saved"] != true
    {
        return Err(t("\u{52a0}\u{8f7d}\u{56de}\u{6267}\u{4e0d}\u{5b8c}\u{6574}\u{ff0c}\u{672a}\u{786e}\u{8ba4}\u{52a0}\u{8f7d}\u{6210}\u{529f}", "Incomplete load receipt; loading was not confirmed"));
    }
    let read_back = checked_result(action(&["model", "engine"])?)?;
    let summary = &read_back["summary"];
    if summary["engine"] != engine || summary["model"] != variant {
        return Err(t("runtime \u{56de}\u{8bfb}\u{4e0e}\u{9009}\u{62e9}\u{4e0d}\u{4e00}\u{81f4}\u{ff1b}\u{8bf7}\u{68c0}\u{67e5}\u{73af}\u{5883}\u{53d8}\u{91cf}\u{8986}\u{76d6}\u{5e76}\u{5237}\u{65b0}", "Runtime read-back differs from selection; check environment overrides and refresh"));
    }
    Ok(summary.clone())
}

fn save_model_settings(
    shared: &Arc<Mutex<Live>>,
    engine: &str,
    variant: Option<&str>,
) -> Result<String, String> {
    let settings = save_model_settings_with(engine, variant, retrieval_action)?;
    if let Ok(mut live) = shared.lock() {
        live.engine = settings["engine"].as_str().unwrap_or("").to_owned();
        live.model_settings = settings;
    }
    Ok(t("\u{6743}\u{91cd}\u{5df2}\u{6821}\u{9a8c}\u{3001}\u{52a0}\u{8f7d}\u{3001}\u{8bd5}\u{63a8}\u{7406}\u{5e76}\u{4fdd}\u{5b58}\u{ff1b}\u{5df2}\u{56de}\u{8bfb}\u{8bbe}\u{7f6e}", "Weights validated, loaded, trial inference passed, saved and read back."))
}

fn probe_notice(value: Value) -> Result<String, String> {
    let result = &value["summary"];
    if result["ready"] != true || !result["cosine"].as_f64().is_some_and(|v| v >= 0.99) {
        return Err(t("\u{63a8}\u{7406}\u{9a8c}\u{8bc1}\u{56de}\u{6267}\u{4e0d}\u{5b8c}\u{6574}\u{ff0c}\u{672a}\u{62a5}\u{544a}\u{9a8c}\u{8bc1}\u{6210}\u{529f}", "Incomplete inference receipt; validation was not accepted"));
    }
    Ok(format!("{}: {}  cosine {}  {} ms", t("\u{6570}\u{503c}\u{9a8c}\u{8bc1}\u{901a}\u{8fc7}\u{ff08}\u{4e0d}\u{4ee3}\u{8868}\u{5b9e}\u{6d4b}\u{7b97}\u{5b50}\u{786c}\u{4ef6}\u{5206}\u{914d}\u{ff09}", "Numerical check passed (node placement not measured)"),
        result["selected"].as_str().unwrap_or("unknown"), result["cosine"], result["elapsed_ms"]))
}

fn workspace_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = 0,
        KeyCode::Down => app.cursor = 1,
        KeyCode::Left if app.cursor == 0 => {
            app.workspace_draft = app.workspace_draft.saturating_sub(1)
        }
        KeyCode::Right if app.cursor == 0 => app.workspace_draft = (app.workspace_draft + 1).min(2),
        KeyCode::Enter if app.cursor == 1 => app.page = Page::Home,
        KeyCode::Enter => {
            let mode = ["normal", "readonly", "off"][app.workspace_draft];
            ask(
                app,
                t(
                    &format!("\u{628a}\u{6574}\u{53f0}\u{8bbe}\u{5907}\u{7684}\u{5de5}\u{4f5c}\u{6a21}\u{5f0f}\u{6539}\u{6210} {}\u{ff1f}", workspace_label(mode)),
                    &format!("Change service mode for this device to {}?", workspace_label(mode)),
                ),
                ConfirmKind::Workspace(mode.to_owned()),
            );
        }
        _ => {}
    }
    false
}

fn version_key(app: &mut App, code: KeyCode) -> bool {
    let tools = tools_on_path();
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down => app.cursor = (app.cursor + 1).min(2),
        KeyCode::Left if app.cursor == 1 && !tools.is_empty() => {
            app.manager_pick = app.manager_pick.saturating_sub(1);
        }
        KeyCode::Right if app.cursor == 1 && !tools.is_empty() => {
            app.manager_pick = (app.manager_pick + 1).min(tools.len() - 1);
        }
        KeyCode::Enter if app.cursor == 2 => app.page = Page::Home,
        KeyCode::Enter if app.cursor == 0 => check_versions(app),
        KeyCode::Enter => {
            let Some(manager) = tools.get(app.manager_pick).copied() else {
                app.set_notice(t(
                    "\u{6ca1}\u{6709}\u{627e}\u{5230} npm\u{3001}pnpm\u{3001}yarn \u{6216} bun",
                    "npm, pnpm, yarn, and bun were not found",
                ));
                return false;
            };
            if matches!(manager, Manager::Direct) {
                app.set_notice(t(
                    "\u{5f53}\u{524d}\u{7a97}\u{53e3}\u{662f}\u{76f4}\u{63a5}\u{8fd0}\u{884c}\u{7684}\u{7a0b}\u{5e8f}\u{ff0c}\u{5305}\u{7ba1}\u{7406}\u{5668}\u{66f4}\u{65b0}\u{4e0d}\u{4f1a}\u{6362}\u{6389}\u{8fd9}\u{4e2a}\u{7a97}\u{53e3}",
                    "This window is a direct binary. A package-manager update will not replace it",
                ));
                return false;
            }
            let spec = if app.live.update_spec.is_empty() {
                channel_spec()
            } else {
                app.live.update_spec.clone()
            };
            ask(
                app,
                t(
                    &format!(
                        "\u{7528} {} \u{66f4}\u{65b0}\u{5230} {spec}\u{ff1f}",
                        manager_name(manager)
                    ),
                    &format!("Update to {spec} with {}?", manager_name(manager)),
                ),
                ConfirmKind::Update(manager_name(manager).to_owned(), spec),
            );
        }
        _ => {}
    }
    false
}

fn lang_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('1') => app.cursor = 0,
        KeyCode::Char('2') => app.cursor = 1,
        KeyCode::Enter => {
            let lang = if app.cursor == 0 { Lang::Zh } else { Lang::En };
            match i18n::set_lang(lang) {
                Ok(()) => app.set_notice(t(
                    "\u{8bed}\u{8a00}\u{5df2}\u{5207}\u{6362}",
                    "Language saved",
                )),
                Err(error) => app.set_notice(error.to_string()),
            }
        }
        _ => {}
    }
}

fn ask(app: &mut App, text: String, kind: ConfirmKind) {
    app.overlay = Overlay::Confirm {
        text,
        cursor: 1,
        kind,
    };
}

fn confirm_key(app: &mut App, code: KeyCode) -> bool {
    let Overlay::Confirm { cursor, .. } = &mut app.overlay else {
        return false;
    };
    match code {
        KeyCode::Up | KeyCode::Left | KeyCode::Char('1') => *cursor = 0,
        KeyCode::Down | KeyCode::Right | KeyCode::Char('2') => *cursor = 1,
        KeyCode::Enter if *cursor == 1 => app.overlay = Overlay::None,
        KeyCode::Enter => {
            let kind = match std::mem::replace(&mut app.overlay, Overlay::None) {
                Overlay::Confirm { kind, .. } => kind,
                other => {
                    app.overlay = other;
                    return false;
                }
            };
            run_confirm(app, kind);
        }
        KeyCode::Char('0') => app.overlay = Overlay::None,
        _ => {}
    }
    false
}

fn run_confirm(app: &mut App, kind: ConfirmKind) {
    let host_model = matches!(
        &kind,
        ConfirmKind::InstallM3
            | ConfirmKind::InstallVariant(_, _)
            | ConfirmKind::UninstallM3
            | ConfirmKind::InstallEngines
            | ConfirmKind::RestartM3(_, _)
    );
    if host_model {
        app.overlay = Overlay::HostModel;
    }
    let label = match &kind {
        ConfirmKind::Switch(name) => t(
            &format!("\u{6b63}\u{5728}\u{5207}\u{6362}\u{5230} {name}"),
            &format!("Switching to {name}"),
        ),
        ConfirmKind::Migrate(_, _) => t("\u{6b63}\u{5728}\u{8fc1}\u{79fb}\u{6240}\u{9009}\u{65e7}\u{8d26}\u{6237}", "Migrating selected legacy account"),
        ConfirmKind::Sync => t("\u{6b63}\u{5728}\u{540c}\u{6b65}", "Syncing"),
        ConfirmKind::InstallM3 => t("\u{6b63}\u{5728}\u{5b89}\u{88c5}\u{6216}\u{6821}\u{9a8c} BGE-M3", "Installing or verifying BGE-M3"),
        ConfirmKind::UninstallM3 => t("\u{6b63}\u{5728}\u{5378}\u{8f7d} BGE-M3", "Uninstalling BGE-M3"),
        ConfirmKind::CancelModel(_) => t("\u{6b63}\u{5728}\u{53d6}\u{6d88}\u{6a21}\u{578b}\u{4efb}\u{52a1}\u{ff0c}\u{7b49}\u{5f85}\u{5f53}\u{524d}\u{7f51}\u{7edc}\u{8bfb}\u{53d6}\u{7ed3}\u{675f}", "Cancelling model task; waiting for the current network read"),
        ConfirmKind::RestartM3(_, _) => t("\u{6b63}\u{5728}\u{53d6}\u{6d88}\u{65e7}\u{4efb}\u{52a1}\u{5e76}\u{91cd}\u{65b0}\u{5b89}\u{6392}\u{4e0b}\u{8f7d}", "Cancelling the old task and scheduling a new download"),
        ConfirmKind::Weights(_, _) => t("\u{6b63}\u{5728}\u{6821}\u{9a8c}\u{5e76}\u{52a0}\u{8f7d}\u{ff1b}\u{8bd5}\u{63a8}\u{7406}\u{6210}\u{529f}\u{540e}\u{4fdd}\u{5b58}", "Validating and loading; saving after trial inference"),
        ConfirmKind::InstallVariant(_, _) => t("\u{6b63}\u{5728}\u{4e0b}\u{8f7d}\u{6240}\u{9009}\u{6743}\u{91cd}\u{ff1b}\u{4e0d}\u{5207}\u{6362}\u{6a21}\u{578b}", "Downloading selected weights; current model unchanged"),
        ConfirmKind::Engine(_) => t("\u{6b63}\u{5728}\u{6821}\u{9a8c}\u{5e76}\u{52a0}\u{8f7d}\u{63a8}\u{7406}\u{5f15}\u{64ce}", "Validating and loading inference engine"),
        ConfirmKind::InstallEngines => t("\u{6b63}\u{5728}\u{4e0b}\u{8f7d} NPU \u{63a8}\u{7406}\u{5f15}\u{64ce}", "Downloading NPU providers"),
        ConfirmKind::ProbeEngine => t("\u{6b63}\u{5728}\u{9a8c}\u{8bc1}\u{63a8}\u{7406}\u{5f15}\u{64ce}", "Checking inference engine"),
        ConfirmKind::RecallMode(_) => t("\u{6b63}\u{5728}\u{4fdd}\u{5b58}\u{53ec}\u{56de}\u{6a21}\u{5f0f}", "Saving recall mode"),
        ConfirmKind::Workspace(_) => t("\u{6b63}\u{5728}\u{5207}\u{6362}\u{5de5}\u{4f5c}\u{533a}", "Changing workspace"),
        ConfirmKind::Autosync(_) => t("\u{6b63}\u{5728}\u{4fdd}\u{5b58}\u{81ea}\u{52a8}\u{540c}\u{6b65}", "Saving auto-sync"),
        ConfirmKind::Update(tool, spec) => t(
            &format!("\u{6b63}\u{5728}\u{7528} {tool} \u{66f4}\u{65b0} {spec}"),
            &format!("Updating {spec} with {tool}"),
        ),
    };
    let changing_model = matches!(&kind, ConfirmKind::Engine(_) | ConfirmKind::Weights(_, _));
    if changing_model {
        app.overlay = Overlay::SavingWeights;
        MODEL_REVISION.fetch_add(1, Ordering::AcqRel);
    }
    app.set_notice(label);
    let shared = Arc::clone(&app.shared);
    let slot = Arc::clone(if changing_model || host_model {
        &app.model_outcome
    } else {
        &app.outcome
    });
    std::thread::spawn(move || {
        let result = match kind {
            ConfirmKind::Switch(name) => {
                switch_account(&name)
            }
            ConfirmKind::Migrate(id, account) => host_command(&["migrate", "--source", &id, "--account", &account])
                .map(|_| t("\u{8fc1}\u{79fb}\u{5b8c}\u{6210}\u{ff1b}\u{53ef}\u{5728}\u{8d26}\u{6237}\u{9875}\u{9762}\u{5207}\u{6362}", "Migration complete; select it on the Accounts page")),
            ConfirmKind::Sync => rpc(&["sync"]).map(|value| sync_notice(&value)),
            ConfirmKind::InstallM3 => selected_model_mirror().map_err(|error| format!("{error:#}"))
                .and_then(|mirror| host_command(&["model", "install-m3", "--mirror", &mirror]))
                .map(|_| t("BGE-M3 \u{5904}\u{7406}\u{7ed3}\u{675f}", "BGE-M3 step finished")),
            ConfirmKind::CancelModel(id) => cancel_model(&id)
                .map(|_| t("\u{5df2}\u{53d6}\u{6d88}\u{6a21}\u{578b}\u{4efb}\u{52a1}", "Model task cancelled")),
            ConfirmKind::RestartM3(id, mirror) => cancel_model(&id)
                .and_then(|_| host_command(&["model", "install-m3", "--mirror", &mirror]))
                .map(|_| t("BGE-M3 \u{5b89}\u{88c5}\u{5b8c}\u{6210}", "BGE-M3 installation complete")),
            ConfirmKind::UninstallM3 => {
                host_command(&["model", "uninstall-m3"]).map(|_| t("BGE-M3 \u{5df2}\u{5378}\u{8f7d}", "BGE-M3 uninstalled"))
            }
            ConfirmKind::Engine(engine) => save_model_settings(&shared, &engine, None),
            ConfirmKind::Weights(engine, variant) => save_model_settings(&shared, &engine, Some(&variant)),
            ConfirmKind::InstallVariant(engine, variant) => selected_model_mirror().map_err(|error| format!("{error:#}"))
                .and_then(|mirror| host_command(&["model", "install-m3", "--model", &variant, "--for-engine", &engine,
                "--mirror", &mirror])).map(|_| t(
                    "\u{9884}\u{4e0b}\u{8f7d}\u{5b8c}\u{6210}\u{ff1b}\u{5f53}\u{524d}\u{6a21}\u{578b}\u{672a}\u{5207}\u{6362}\u{ff0c}\u{53ef}\u{7ee7}\u{7eed}\u{4e0b}\u{8f7d}\u{5176}\u{4ed6}\u{6743}\u{91cd}\u{6216}\u{9009}\u{62e9}\u{52a0}\u{8f7d}", "Download complete; current model unchanged. Download more weights or select Load.")),
            ConfirmKind::RecallMode(mode) => {
                retrieval_action(&["agent-config", "--set", &format!("recall_mode={mode}")]).map(
                    |_| {
                        t(
                            "\u{53ec}\u{56de}\u{6a21}\u{5f0f}\u{5df2}\u{4fdd}\u{5b58}\u{ff0c}\u{4e0b}\u{6b21}\u{67e5}\u{8be2}\u{751f}\u{6548}",
                            "Recall mode saved; applies to the next query",
                        )
                    },
                )
            }
            ConfirmKind::InstallEngines => host_command(&["model", "install-engines"]).map(|v| {
                format!(
                    "{}: {}",
                    t("\u{63a8}\u{7406}\u{5f15}\u{64ce}", "Providers"),
                    v["summary"]["providers"].as_array().map(|providers|
                        providers.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default()
                )
            }),
            ConfirmKind::ProbeEngine => retrieval_action(&["model", "probe"]).and_then(probe_notice),
            ConfirmKind::Workspace(mode) => set_workspace(&mode),
            ConfirmKind::Autosync(on) => {
                let flag = if on { "true" } else { "false" };
                host_command(&["config", "--autosync", flag]).map(|_| t("\u{81ea}\u{52a8}\u{540c}\u{6b65}\u{5df2}\u{4fdd}\u{5b58}", "Auto-sync saved"))
            }
            ConfirmKind::Update(tool, spec) => run_package_update(&tool, &spec),
        };
        if changing_model {
            MODEL_REVISION.fetch_add(1, Ordering::AcqRel);
        }
        let message = match result {
            Ok(text) => text,
            Err(error) => error,
        };
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(message);
        }
    });
}

fn set_workspace(mode: &str) -> Result<String, String> {
    host_command(&["agent-config", "--set", &format!("workspace_mode={mode}")])?;
    Ok(t(
        "\u{5de5}\u{4f5c}\u{6a21}\u{5f0f}\u{5df2}\u{4fdd}\u{5b58}",
        "Service mode saved",
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Manager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Direct,
}

fn manager_name(manager: Manager) -> &'static str {
    match manager {
        Manager::Npm => "npm",
        Manager::Pnpm => "pnpm",
        Manager::Yarn => "yarn",
        Manager::Bun => "bun",
        Manager::Direct => "direct",
    }
}

fn tool_on_path(name: &str) -> bool {
    let path = match respire::env::var_os("PATH") {
        Some(path) => path,
        None => return false,
    };
    let file = if cfg!(windows) {
        format!("{name}.cmd")
    } else {
        name.to_owned()
    };
    std::env::split_paths(&path).any(|dir| dir.join(&file).is_file() || dir.join(name).is_file())
}

fn tools_on_path() -> Vec<Manager> {
    let mut tools = Vec::new();
    let agent = respire::env::var("npm_config_user_agent")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let exe = std::env::current_exe()
        .map(|path| path.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let prefer = if agent.starts_with("pnpm") || exe.contains(".pnpm") || exe.contains("pnpm") {
        Some(Manager::Pnpm)
    } else if agent.starts_with("yarn") || exe.contains("yarn") {
        Some(Manager::Yarn)
    } else if agent.starts_with("bun") || exe.contains("\\bun\\") || exe.contains("/bun/") {
        Some(Manager::Bun)
    } else if agent.starts_with("npm")
        || exe.contains("node_modules")
        || exe.contains("\\npm\\")
        || exe.contains("/npm/")
    {
        Some(Manager::Npm)
    } else {
        None
    };
    for manager in [Manager::Npm, Manager::Pnpm, Manager::Yarn, Manager::Bun] {
        if tool_on_path(manager_name(manager)) {
            tools.push(manager);
        }
    }
    if let Some(prefer) = prefer {
        if let Some(index) = tools.iter().position(|item| *item == prefer) {
            tools.swap(0, index);
        }
    }
    if tools.is_empty() {
        tools.push(Manager::Direct);
    }
    tools
}

fn channel_spec() -> String {
    if env!("CARGO_PKG_VERSION").contains("-dev") {
        "rsrs-cli@dev".to_owned()
    } else {
        "rsrs-cli@latest".to_owned()
    }
}

fn check_versions(app: &mut App) {
    app.set_notice(t(
        "\u{6b63}\u{5728}\u{68c0}\u{67e5} npm \u{4e0a}\u{7684}\u{7248}\u{672c}",
        "Checking versions on npm",
    ));
    let slot = Arc::clone(&app.outcome);
    let shared = Arc::clone(&app.shared);
    std::thread::spawn(move || {
        let current = env!("CARGO_PKG_VERSION");
        let message = match respire::update_check::fetch_dist_tags() {
            Some((latest, dev)) => {
                let spec = channel_spec();
                let remote = if current.contains("-dev") {
                    dev.as_str()
                } else {
                    latest.as_str()
                };
                let newer =
                    !remote.is_empty() && respire::update_check::is_newer(remote, current);
                let line = format!(
                    "{} {current}    latest {latest}    dev {dev}{}",
                    if zh() { "\u{5f53}\u{524d}" } else { "current" },
                    if newer {
                        if zh() {
                            format!("    \u{6709}\u{65b0}\u{7248}\u{672c} {remote}")
                        } else {
                            format!("    update available {remote}")
                        }
                    } else if zh() {
                        "    \u{5df2}\u{662f}\u{8fd9}\u{6761}\u{901a}\u{9053}\u{4e0a}\u{7684}\u{6700}\u{65b0}\u{7248}".to_owned()
                    } else {
                        "    already the newest on this channel".to_owned()
                    }
                );
                if let Ok(mut guard) = shared.lock() {
                    guard.ver_line = line.clone();
                    guard.update_spec = spec;
                }
                line
            }
            None => t(
                "\u{6ca1}\u{6709}\u{8bfb}\u{5230} npm \u{7248}\u{672c}\u{ff0c}\u{68c0}\u{67e5}\u{7f51}\u{7edc}\u{540e}\u{518d}\u{8bd5}",
                "Could not read npm versions. Check the network and try again",
            ),
        };
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(message);
        }
    });
}

fn run_package_update(tool: &str, spec: &str) -> Result<String, String> {
    crate::runtime_policy::require_host("package upgrade").map_err(|error| error.to_string())?;
    let line = match tool {
        "npm" => format!("npm i -g {spec}"),
        "pnpm" => format!("pnpm add -g {spec}"),
        "yarn" => format!("yarn global add {spec}"),
        "bun" => format!("bun add -g {spec}"),
        _ => {
            return Err(t(
                "\u{6ca1}\u{6709}\u{53ef}\u{7528}\u{7684}\u{5305}\u{7ba1}\u{7406}\u{5668}",
                "No package manager is available",
            ))
        }
    };
    let mut cmd = if cfg!(windows) {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", &line]);
        cmd
    } else {
        let mut parts = line.split_whitespace();
        let program = parts.next().unwrap_or(tool);
        let mut cmd = std::process::Command::new(program);
        cmd.args(parts);
        cmd
    };
    let output = cmd.output().map_err(|error| format!("{error}"))?;
    if output.status.success() {
        return Ok(t(
            "\u{66f4}\u{65b0}\u{547d}\u{4ee4}\u{5df2}\u{5b8c}\u{6210}\u{3002}\u{91cd}\u{65b0}\u{6253}\u{5f00}\u{7a0b}\u{5e8f}\u{540e}\u{624d}\u{4f1a}\u{6362}\u{6210}\u{65b0}\u{7248}\u{672c}\u{3002}\u{5f53}\u{524d}\u{8fd9}\u{4e2a}\u{7a97}\u{53e3}\u{5982}\u{679c}\u{662f}\u{76f4}\u{63a5}\u{8fd0}\u{884c}\u{7684}\u{ff0c}\u{4e0d}\u{4f1a}\u{88ab}\u{6362}\u{6389}\u{3002}",
            "Update command finished. Reopen the program to use the new version. This window is unchanged if it was started as a direct binary.",
        ));
    }
    let err = String::from_utf8_lossy(&output.stderr);
    let out = String::from_utf8_lossy(&output.stdout);
    let text = if err.trim().is_empty() { out } else { err };
    Err(text.chars().take(400).collect())
}

fn sync_notice(value: &Value) -> String {
    let summary = &value["summary"];
    t(
        &format!(
            "\u{540c}\u{6b65}\u{7ed3}\u{675f}  \u{62c9} {}  \u{63a8} {}  \u{51b2}\u{7a81} {}",
            summary["pulled"].as_u64().unwrap_or(0),
            summary["pushed"].as_u64().unwrap_or(0),
            summary["conflicts"].as_i64().unwrap_or(0)
        ),
        &format!(
            "Sync finished  pulled {}  pushed {}  conflicts {}",
            summary["pulled"].as_u64().unwrap_or(0),
            summary["pushed"].as_u64().unwrap_or(0),
            summary["conflicts"].as_i64().unwrap_or(0)
        ),
    )
}

fn edit_key(app: &mut App, code: KeyCode) -> bool {
    let Overlay::Edit { buf, cursor } = &mut app.overlay else {
        return false;
    };
    match code {
        KeyCode::Char(' ') => app.overlay = Overlay::None,
        KeyCode::Enter => {
            let value = buf.trim().to_owned();
            app.overlay = Overlay::None;
            if value.is_empty() || !(value.starts_with("http://") || value.starts_with("https://"))
            {
                app.set_notice(t(
                    "\u{5730}\u{5740}\u{5fc5}\u{987b}\u{4ee5} http:// \u{6216} https:// \u{5f00}\u{5934}",
                    "Address must start with http:// or https://",
                ));
                return false;
            }
            let slot = Arc::clone(&app.outcome);
            app.set_notice(t(
                "\u{6b63}\u{5728}\u{4fdd}\u{5b58}\u{670d}\u{52a1}\u{5668}\u{5730}\u{5740}",
                "Saving the server address",
            ));
            std::thread::spawn(move || {
                let message = match host_command(&["config", "--addr", &value]) {
                    Ok(_) => t(
                        "\u{670d}\u{52a1}\u{5668}\u{5730}\u{5740}\u{5df2}\u{4fdd}\u{5b58}",
                        "Server address saved",
                    ),
                    Err(error) => error,
                };
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(message);
                }
            });
        }
        KeyCode::Backspace => {
            if *cursor > 0 {
                let remove_at = *cursor - 1;
                let mut next = String::new();
                for (index, ch) in buf.chars().enumerate() {
                    if index != remove_at {
                        next.push(ch);
                    }
                }
                *buf = next;
                *cursor -= 1;
            }
        }
        KeyCode::Left => *cursor = cursor.saturating_sub(1),
        KeyCode::Right => *cursor = (*cursor + 1).min(buf.chars().count()),
        KeyCode::Char(ch) => {
            let mut next = String::new();
            let mut inserted = false;
            for (index, current) in buf.chars().enumerate() {
                if index == *cursor {
                    next.push(ch);
                    inserted = true;
                }
                next.push(current);
            }
            if !inserted {
                next.push(ch);
            }
            *buf = next;
            *cursor += 1;
        }
        _ => {}
    }
    false
}

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let foot_height = if app.live.notice.is_empty() { 3 } else { 4 };
    let chunks =
        Layout::vertical([Constraint::Min(8), Constraint::Length(foot_height)]).split(area);
    let mut body = if !app.live.connected {
        let mut lines = vec![line(t(
            "\u{6b63}\u{5728}\u{8fde}\u{63a5} runtime / \u{521d}\u{59cb}\u{5316}\u{4e2d}\u{2026}",
            "Connecting to runtime / initializing...",
        ))];
        if !app.live.error.is_empty() {
            lines.push(fail_line(app.live.error.clone()));
        }
        lines.push(line(t(
            "\u{63a8}\u{7406}\u{5361}\u{4f4f}\u{53ef}\u{5728}\u{7ec8}\u{7aef}\u{8fd0}\u{884c}\u{ff1a}rsrs model reset-cpu",
            "If inference is stuck: rsrs model reset-cpu",
        )));
        lines
    } else {
        match app.page {
            Page::Home => home_body(app, chunks[0].width.saturating_sub(2) as usize),
            Page::Accounts => accounts_body(app),
            Page::Migration => migration_body(app),
            Page::Server => server_body(app),
            Page::Inject => Vec::new(),
            Page::Sync => sync_body(app),
            Page::Model => model_body(app),
            Page::Workspace => workspace_body(app),
            Page::Lang => lang_body(app),
            Page::Version => version_body(app),
            Page::Web => web_body(app),
        }
    };
    if matches!(app.overlay, Overlay::None) {
        keep_selection_visible(&mut body, chunks[0]);
    }
    let mut lines = vec![banner()];
    if let Some(mut extra) = overlay_lines(app) {
        if matches!(
            app.overlay,
            Overlay::ModelWeights(_) | Overlay::RecallFusion(_)
        ) {
            keep_selection_visible(&mut extra, chunks[0]);
        }
        // Confirmation and edit controls must not be clipped below a long page body.
        lines.extend(extra);
    } else {
        lines.extend(body);
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(crate::app_version::line()),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    match &app.overlay {
        Overlay::RecallApi(form) => form.draw(frame, chunks[0]),
        Overlay::RecallTest(form) => form.draw(frame, chunks[0]),
        _ => {}
    }
    if app.live.connected
        && matches!(app.page, Page::Inject)
        && matches!(app.overlay, Overlay::None)
    {
        draw_inject(frame, app, chunks[0]);
    }
    let foot = if matches!(app.overlay, Overlay::HostModel) {
        t("\u{7b49}\u{5f85}\u{5bbf}\u{4e3b}\u{7ed3}\u{679c}\u{ff1b}\u{4e0d}\u{652f}\u{6301}\u{53d6}\u{6d88}", "Waiting for host result; cancellation unavailable")
    } else if matches!(app.overlay, Overlay::ModelTask(_)) {
        t(
            "Esc / C \u{53d6}\u{6d88}\u{5f53}\u{524d}\u{6a21}\u{578b}\u{4efb}\u{52a1}",
            "Esc / C cancels the model task",
        )
    } else if matches!(
        app.overlay,
        Overlay::RecallApi(_) | Overlay::RecallFusion(_)
    ) {
        t(
            "Tab \u{5207}\u{5b57}\u{6bb5}    Ctrl+A \u{5168}\u{9009}    Ctrl+S \u{4fdd}\u{5b58}    Esc \u{653e}\u{5f03}",
            "Tab changes field    Ctrl+A selects all    Ctrl+S saves    Esc discards",
        )
    } else if matches!(app.overlay, Overlay::RecallTest(_)) {
        t(
            "\u{56de}\u{8f66}\u{6d4b}\u{8bd5}    Ctrl+A \u{5168}\u{9009}    PgUp/PgDn \u{6eda}\u{52a8}    Esc \u{8fd4}\u{56de}",
            "Enter tests    Ctrl+A selects all    PgUp/PgDn scroll    Esc returns",
        )
    } else if matches!(app.overlay, Overlay::Edit { .. }) {
        t(
            "\u{56de}\u{8f66}\u{4fdd}\u{5b58}    \u{7a7a}\u{683c}\u{6216} Esc \u{653e}\u{5f03}    \u{9000}\u{683c}\u{5220}\u{9664}",
            "Enter saves    Space or Esc cancels    Backspace deletes",
        )
    } else if zh() {
        "\u{65b9}\u{5411}\u{952e}\u{79fb}\u{52a8}    \u{6570}\u{5b57}\u{8fdb}\u{5165}    \u{56de}\u{8f66}\u{786e}\u{8ba4}    \u{7a7a}\u{683c}\u{52fe}\u{9009}    0 \u{6216} Esc \u{8fd4}\u{56de}    7 \u{5207}\u{6362}\u{8bed}\u{8a00}".to_owned()
    } else {
        "Arrows move    digits open    Enter confirms    Space checks    0 or Esc back    7 switches language".to_owned()
    };
    let note = if app.live.notice.is_empty() {
        foot
    } else {
        format!("{foot}\n{}", app.live.notice)
    };
    let foot_lines: Vec<Line<'static>> = note.lines().map(|text| line(text.to_owned())).collect();
    frame.render_widget(
        Paragraph::new(foot_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(t("\u{6309}\u{952e}", "Keys")),
        ),
        chunks[1],
    );
}

fn keep_selection_visible(body: &mut Vec<Line<'static>>, area: Rect) {
    let height = area.height.saturating_sub(3) as usize;
    let width = usize::from(area.width.saturating_sub(2)).max(1);
    let rows = |line: &Line<'_>| line.width().max(1).div_ceil(width);
    let selected = body.iter().position(|line| {
        line.spans
            .iter()
            .any(|span| span.style.add_modifier.contains(Modifier::REVERSED))
    });
    if let Some(selected) = selected {
        if body[..selected].iter().map(rows).sum::<usize>() >= height.saturating_sub(2) {
            let mut start = selected;
            let mut visible = rows(&body[selected]);
            while start > 0 && visible + rows(&body[start - 1]) <= height / 2 {
                start -= 1;
                visible += rows(&body[start]);
            }
            body.drain(..start);
        }
    }
}

fn home_body(app: &App, inner: usize) -> Vec<Line<'static>> {
    let live = &app.live;
    let phase = match live.phase.as_str() {
        "running" => t("\u{6b63}\u{5728}\u{540c}\u{6b65}", "syncing"),
        "ok" => t("\u{4e0a}\u{6b21}\u{6210}\u{529f}", "last ok"),
        "err" => t("\u{4e0a}\u{6b21}\u{5931}\u{8d25}", "last failed"),
        _ => t("\u{7a7a}\u{95f2}", "idle"),
    };
    let user = if live.user.is_empty() {
        t("\u{672a}\u{767b}\u{5f55}", "signed out")
    } else {
        live.user.clone()
    };
    let addr = if live.addr.is_empty() {
        crate::client_config::DEFAULT_SERVER_ADDR.to_owned()
    } else {
        live.addr.clone()
    };
    let stamp = chrono::Local::now().format("%H:%M:%S").to_string();
    let mut lines = smi_table(
        &[
            [
                format!("CLI {}", crate::app_version::embedded()),
                runtime_version_label(live),
                stamp.clone(),
            ],
            [
                format!("rsrs  {stamp}"),
                format!("pid {}", live.pid),
                if live.connected {
                    t("runtime \u{5728}\u{8fd0}\u{884c}", "runtime up")
                } else {
                    t("runtime \u{672a}\u{8fde}\u{901a}", "runtime down")
                },
            ],
            [
                live.url.clone(),
                format!("{}  {user}", t("\u{6863}\u{6848}", "Account")),
                format!(
                    "{}  {}",
                    t("\u{5de5}\u{4f5c}\u{6a21}\u{5f0f}", "Service mode"),
                    workspace_label(&live.workspace)
                ),
            ],
            [
                format!("{}  {addr}", t("\u{670d}\u{52a1}\u{5668}", "Server")),
                format!("{}  {phase}", t("\u{540c}\u{6b65}", "Sync")),
                format!(
                    "{} {} / {} {}",
                    t("\u{672c}\u{5730}", "Local"),
                    live.local_alive,
                    t("\u{4e91}\u{7aef}", "Remote"),
                    live.remote_alive
                ),
            ],
            [
                format!(
                    "{} {}  {} {}",
                    t("\u{51b2}\u{7a81}", "Conflicts"),
                    live.conflicts,
                    t("\u{81ea}\u{52a8}", "Auto"),
                    if live.autosync {
                        t("\u{5f00}", "on")
                    } else {
                        t("\u{5173}", "off")
                    }
                ),
                format!(
                    "{} {}",
                    t("\u{5f85}\u{63a8}\u{9001}", "Pending"),
                    live.pending
                ),
                format!(
                    "{} {}  {} {}",
                    t("\u{4e0a}\u{6b21}\u{62c9}", "Pulled"),
                    live.pulled,
                    t("\u{63a8}", "pushed"),
                    live.pushed
                ),
            ],
            [
                format!(
                    "{} {}  {} {}  {} {}",
                    t("\u{6ce8}\u{5165}\u{65b0}", "fresh"),
                    live.fresh,
                    t("\u{8fc7}\u{671f}", "stale"),
                    live.stale,
                    t("\u{672a}\u{6ce8}\u{5165}", "missing"),
                    live.missing
                ),
                String::new(),
                String::new(),
            ],
        ],
        inner,
    );
    if !live.error.is_empty() {
        lines.push(fail_line(live.error.clone()));
    }
    let fails: Vec<_> = live
        .doctor
        .iter()
        .filter(|(_, status, _)| status == "fail" || status == "warn")
        .cloned()
        .collect();
    if fails.is_empty() {
        lines.push(ok_line(format!(
            "doctor  {} {}",
            live.doctor.len(),
            t("\u{9879}\u{5df2}\u{8bfb}\u{53d6}", "checks read")
        )));
    } else {
        for (name, status, value) in fails.iter().take(6) {
            let shown = if status == "fail" {
                fail_line(format!("{name}  {value}"))
            } else {
                warn_line(format!("{name}  {value}"))
            };
            lines.push(shown);
        }
    }
    lines.push(line(String::new()));
    let labels = [
        t("1  \u{8d26}\u{6237}", "1  Accounts"),
        t("2  \u{670d}\u{52a1}\u{5668}", "2  Server"),
        t(
            "3  \u{6ce8}\u{5165}\u{4e0e}\u{63d0}\u{793a}\u{8bcd}",
            "3  Inject and prompts",
        ),
        t("4  \u{540c}\u{6b65}", "4  Sync"),
        t("5  \u{6a21}\u{578b}", "5  Models"),
        t("6  \u{5de5}\u{4f5c}\u{6a21}\u{5f0f}", "6  Service mode"),
        t("7  \u{8bed}\u{8a00}", "7  Language"),
        t("8  \u{7248}\u{672c}", "8  Version"),
        t("9  \u{6253}\u{5f00} Web", "9  Open Web"),
    ];
    for (index, label) in labels.iter().enumerate() {
        lines.push(choice(index == app.cursor, label.clone()));
    }
    lines.push(choice(app.cursor == 9, t("0  \u{9000}\u{51fa}", "0  Quit")));
    lines
}

fn table_metrics(inner: usize) -> (usize, usize, usize) {
    let preferred = 28usize;
    let cols = if inner >= preferred * 3 + 4 {
        3
    } else if inner >= preferred * 2 + 3 {
        2
    } else {
        1
    };
    let gutters = cols + 1;
    let cell = if cols == 3 {
        preferred
    } else {
        inner.saturating_sub(gutters).clamp(12, preferred)
    };
    let width = cols * cell + gutters;
    (cols, cell, width)
}

fn clip_cell(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + w > width {
            break;
        }
        out.push(ch);
        used += w;
    }
    while used < width {
        out.push(' ');
        used += 1;
    }
    out
}

fn smi_table(rows: &[[String; 3]], inner: usize) -> Vec<Line<'static>> {
    let (cols, cell, _) = table_metrics(inner);
    let mut flat = Vec::new();
    for row in rows {
        for item in row {
            flat.push(item.clone());
        }
    }
    let mut out = Vec::new();
    let rule = |fill: char| {
        let mut text = String::from("+");
        for _ in 0..cols {
            text.push_str(&fill.to_string().repeat(cell));
            text.push('+');
        }
        line(text)
    };
    out.push(rule('-'));
    for (index, chunk) in flat.chunks(cols).enumerate() {
        let mut text = String::from("|");
        for item in chunk {
            text.push_str(&clip_cell(item, cell));
            text.push('|');
        }
        for _ in 0..(cols - chunk.len()) {
            text.push_str(&clip_cell("", cell));
            text.push('|');
        }
        out.push(line(text));
        out.push(rule(if index == 0 { '=' } else { '-' }));
    }
    out
}

fn web_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = 0,
        KeyCode::Down => app.cursor = 1,
        KeyCode::Enter if app.cursor == 1 => app.page = Page::Home,
        KeyCode::Enter => {
            let url = crate::web::DASHBOARD_URL;
            if let Err(error) = crate::web::open_browser(url) {
                app.set_notice(error.to_string());
                return false;
            }
            app.set_notice(t(
                &format!("\u{5df2}\u{6253}\u{5f00} {url}"),
                &format!("Opened {url}"),
            ));
        }
        _ => {}
    }
    false
}

fn web_body(app: &App) -> Vec<Line<'static>> {
    let url = crate::web::DASHBOARD_URL;
    vec![
        line(format!("{}: {url}", t("\u{7528}\u{6237}\u{540e}\u{53f0}", "User dashboard"))),
        line(t(
            "\u{56de}\u{8f66}\u{7528}\u{7cfb}\u{7edf}\u{6d4f}\u{89c8}\u{5668}\u{6253}\u{5f00}\u{3002}",
            "Enter opens it in the system browser.",
        )),
        choice(app.cursor == 0, t("\u{6253}\u{5f00} Web", "Open Web")),
        choice(app.cursor == 1, t("0  \u{8fd4}\u{56de}", "0  Back")),
    ]
}

fn banner() -> Line<'static> {
    let zh_on = zh();
    let on = Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let off = Style::default().fg(Color::DarkGray);
    Line::from(vec![
        Span::raw(t("\u{8bed}\u{8a00}  ", "Language  ")),
        Span::styled("\u{4e2d}\u{6587}", if zh_on { on } else { off }),
        Span::raw("  "),
        Span::styled("English", if zh_on { off } else { on }),
        Span::raw(t(
            "      7 \u{7acb}\u{5373}\u{5207}\u{6362}",
            "      7 switches now",
        )),
    ])
}

fn accounts_body(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![line(t(
        "\u{9009}\u{62e9}\u{8d26}\u{6237}\u{540e}\u{56de}\u{8f66}\u{5207}\u{6362}\u{ff1b}\u{65b0}\u{8d26}\u{6237}\u{4f7f}\u{7528}\u{767b}\u{5f55}\u{5165}\u{53e3}\u{3002}",
        "Enter switches account; use Sign in for a new account.",
    ))];
    if app.live.accounts.is_empty() {
        lines.push(line(t(
            "\u{6ca1}\u{6709}\u{8bfb}\u{5230}\u{8d26}\u{6237}",
            "No accounts read",
        )));
    }
    for (index, row) in app.live.accounts.iter().enumerate() {
        let mark = if row.current {
            t("\u{5f53}\u{524d}", "current")
        } else {
            t("    ", "       ")
        };
        let user = if row.user.is_empty() {
            t("\u{672a}\u{767b}\u{5f55}", "signed out")
        } else {
            row.user.clone()
        };
        lines.push(choice(
            index == app.cursor,
            format!("{mark}  {}  {user}", row.name),
        ));
    }
    lines.push(choice(
        app.cursor == app.live.accounts.len(),
        t(
            "\u{8fc1}\u{79fb}\u{65e7}\u{7248}\u{672c}",
            "Migrate old version",
        ),
    ));
    lines.push(choice(
        app.cursor == app.live.accounts.len() + 1,
        t(
            "\u{767b}\u{5f55}\u{ff08}OAuth / \u{5bc6}\u{7801}\u{4e0e} TOTP\u{ff09}",
            "Sign in (OAuth / password and TOTP)",
        ),
    ));
    lines.push(choice(
        app.cursor == app.live.accounts.len() + 2,
        t("0  \u{8fd4}\u{56de}", "0  Back"),
    ));
    lines
}

fn migration_body(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![line(t("\u{9009}\u{62e9}\u{6765}\u{6e90}\u{76ee}\u{5f55}\u{548c}\u{65e7}\u{8d26}\u{6237}\u{ff0c}\u{56de}\u{8f66}\u{786e}\u{8ba4}\u{ff1b}\u{4e0d}\u{4f1a}\u{8986}\u{76d6}\u{5df2}\u{6709}\u{5e93}\u{3002}",
        "Choose the source directory and legacy account. Existing libraries are preserved."))];
    for (index, row) in app.migration_profiles.iter().enumerate() {
        let state = if row["migrated_to"].is_null() {
            ""
        } else {
            " [migrated]"
        };
        lines.push(choice(
            index == app.cursor,
            format!(
                "{} | {} \u{2192} {}{state}",
                row["source"].as_str().unwrap_or(""),
                row["user"].as_str().unwrap_or(""),
                row["account"].as_str().unwrap_or("")
            ),
        ));
    }
    if app.migration_profiles.is_empty() {
        lines.push(line(t(
            "\u{6ca1}\u{6709}\u{53ef}\u{8fc1}\u{79fb}\u{7684}\u{65e7}\u{5e93}",
            "No legacy libraries found",
        )));
    }
    lines.push(line(t("0  \u{8fd4}\u{56de}", "0  Back")));
    lines
}

fn server_body(app: &App) -> Vec<Line<'static>> {
    vec![
        choice(
            app.cursor == 0,
            format!(
                "{}: {}",
                t("\u{4fee}\u{6539}\u{5730}\u{5740}", "Edit address"),
                app.live.addr
            ),
        ),
        choice(app.cursor == 1, t("0  \u{8fd4}\u{56de}", "0  Back")),
    ]
}

fn draw_inject(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered().title(t(
        "\u{6ce8}\u{5165}\u{4e0e}\u{63d0}\u{793a}\u{8bcd}",
        "Inject and prompts",
    ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let sections = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Min(2),
        Constraint::Length(1),
    ])
    .split(inner);
    frame.render_widget(Paragraph::new(banner()), sections[0]);
    frame.render_widget(
        Paragraph::new(vec![
            choice(
                app.cursor == 0,
                t("\u{66f4}\u{65b0}\u{6240}\u{6709}\u{5df2}\u{5b89}\u{88c5}\u{63d0}\u{793a}\u{8bcd}", "Update all installed prompts"),
            ),
            choice(
                app.cursor == 1,
                t("\u{5378}\u{8f7d}\u{6240}\u{6709}\u{5df2}\u{5b89}\u{88c5}\u{63d0}\u{793a}\u{8bcd}", "Uninstall all installed prompts"),
            ),
        ]),
        sections[1],
    );
    let rows = app.live.inject.iter().map(|row| {
        let color = match row.state.as_str() {
            "fresh" => Color::Green,
            "stale" => Color::Yellow,
            _ => Color::DarkGray,
        };
        Row::new(vec![
            Cell::from(if row.checked { "[x]" } else { "[ ]" }),
            Cell::from(row.name.clone()),
            Cell::from(state_label(&row.state)).style(Style::default().fg(color)),
            Cell::from(if row.seen {
                t("\u{5df2}\u{68c0}\u{6d4b}\u{5230}", "detected")
            } else {
                t("\u{672a}\u{68c0}\u{6d4b}\u{5230}", "not detected")
            }),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new([
            t("\u{5b89}\u{88c5}", "On"),
            t("\u{76ee}\u{6807}", "Target"),
            t("\u{63d0}\u{793a}\u{8bcd}\u{72b6}\u{6001}", "Prompt status"),
            t("\u{5e94}\u{7528}\u{68c0}\u{6d4b}", "App detected"),
        ])
        .style(Style::default().bold()),
    )
    .block(Block::bordered())
    .column_spacing(2)
    .row_highlight_style(Style::default().bg(Color::DarkGray).bold())
    .highlight_symbol("> ");
    let selected = app
        .cursor
        .checked_sub(2)
        .filter(|index| *index < app.live.inject.len());
    let mut state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, sections[2], &mut state);
    frame.render_widget(
        Paragraph::new(choice(
            app.cursor == app.live.inject.len() + 2,
            t("0  \u{8fd4}\u{56de}", "0  Back"),
        )),
        sections[3],
    );
}

fn state_label(state: &str) -> String {
    match state {
        "fresh" => t(
            "\u{63d0}\u{793a}\u{8bcd}\u{5df2}\u{66f4}\u{65b0}",
            "prompt fresh",
        ),
        "stale" => t("\u{63d0}\u{793a}\u{8bcd}\u{8fc7}\u{671f}", "prompt stale"),
        "none" | "absent" => t("\u{672a}\u{6ce8}\u{5165}", "not injected"),
        other => other.to_owned(),
    }
}

fn sync_body(app: &App) -> Vec<Line<'static>> {
    let phase = match app.live.phase.as_str() {
        "running" => t("\u{6b63}\u{5728}\u{540c}\u{6b65}", "syncing"),
        "ok" => t("\u{4e0a}\u{6b21}\u{6210}\u{529f}", "last ok"),
        "err" => t("\u{4e0a}\u{6b21}\u{5931}\u{8d25}", "last failed"),
        _ => t("\u{5c1a}\u{672a}\u{540c}\u{6b65}", "not synced yet"),
    };
    vec![
        line(format!(
            "{phase}    {}: {}  {}: {}  {}: {}",
            t("\u{62c9}", "pulled"),
            app.live.pulled,
            t("\u{63a8}", "pushed"),
            app.live.pushed,
            t("\u{51b2}\u{7a81}", "conflicts"),
            app.live.conflicts
        )),
        line(if app.live.error.is_empty() {
            t(
                "\u{51b2}\u{7a81}\u{53ea}\u{5728}\u{8fd9}\u{91cc}\u{67e5}\u{770b}\u{ff0c}\u{5408}\u{5e76}\u{4ecd}\u{7528}\u{547d}\u{4ee4}\u{3002}",
                "Conflicts are listed here. Merging stays a command.",
            )
        } else {
            app.live.error.clone()
        }),
        choice(app.cursor == 0, t("\u{624b}\u{52a8}\u{540c}\u{6b65}\u{4e00}\u{6b21}", "Sync once")),
        choice(
            app.cursor == 1,
            format!(
                "{}  {}",
                t("\u{81ea}\u{52a8}\u{540c}\u{6b65}", "Auto-sync"),
                if app.autosync_draft {
                    t("\u{5f00}", "on")
                } else {
                    t("\u{5173}", "off")
                }
            ),
        ),
        choice(app.cursor == 2, t("0  \u{8fd4}\u{56de}", "0  Back")),
        line(t(
            "\u{5de6}\u{53f3}\u{952e}\u{5207}\u{6362}\u{81ea}\u{52a8}\u{540c}\u{6b65}\u{ff0c}\u{56de}\u{8f66}\u{4fdd}\u{5b58}\u{3002}",
            "Left and right change auto-sync. Enter saves.",
        )),
    ]
}

fn model_body(app: &App) -> Vec<Line<'static>> {
    let mirror = match selected_model_mirror() {
        Ok(value) => value,
        Err(error) => return vec![fail_line(format!("{error:#}"))],
    };
    let config = match respire_client_host::settings::read_agent_config() {
        Ok(value) => value,
        Err(error) => return vec![fail_line(format!("{error:#}"))],
    };
    let bge = doctor_value(&app.live, "embedder");
    let engine = &app.live.engine;
    let mut lines = vec![
        line(format!("BGE-M3  {bge}")),
        choice(
            app.cursor == 0,
            t("\u{5b89}\u{88c5}\u{6216}\u{6821}\u{9a8c} BGE-M3 \u{91cf}\u{5316}\u{6a21}\u{578b}\u{ff08}543 MiB\u{ff09}", "Install or verify BGE-M3 quantized (543 MiB)"),
        ),
        choice(
            app.cursor == 1,
            t("\u{5378}\u{8f7d} BGE-M3\u{ff08}\u{5220}\u{9664}\u{6587}\u{4ef6}\u{ff09}", "Uninstall BGE-M3 (delete files)"),
        ),
        choice(app.cursor == 2, format!("{}: {}", t("\u{4e0b}\u{8f7d}\u{6e90}\u{ff08}\u{56de}\u{8f66}\u{9009}\u{62e9}\u{ff09}", "Download source (Enter to choose)"), mirror)),
        line(format!(
            "{}: {engine} / {}",
            t("\u{5f53}\u{524d}\u{63a8}\u{7406}\u{8bbe}\u{7f6e}", "Inference setting"), app.live.model_settings["model"].as_str().unwrap_or("unknown")
        )),
    ];
    for (index, engine) in model_engines().iter().enumerate() {
        let label = match *engine {
            "npu" if cfg!(target_os = "macos") => "Apple CoreML (ANE / CPU)".to_owned(),
            "npu" => "NPU (Windows ML)".to_owned(),
            "gpu" => "GPU".to_owned(),
            _ => t("CPU\u{ff08}\u{9ed8}\u{8ba4}\u{ff09}", "CPU (default)"),
        };
        lines.push(choice(app.cursor == index + 3, label));
    }
    let mut index = 3 + model_engines().len();
    if cfg!(windows) {
        lines.push(choice(
            app.cursor == index,
            t(
                "\u{5b89}\u{88c5} Windows NPU \u{63a8}\u{7406}\u{5f15}\u{64ce}",
                "Install Windows NPU providers",
            ),
        ));
        index += 1;
    }
    lines.push(choice(
        app.cursor == index,
        t(
            "\u{8fd0}\u{884c}\u{63a8}\u{7406}\u{9a8c}\u{8bc1}",
            "Check inference",
        ),
    ));
    let mode = config["recall_mode"]
        .as_str()
        .unwrap_or("fast")
        .to_owned();
    lines.push(line(format!(
        "{}: {mode}",
        t("\u{53ec}\u{56de}\u{6a21}\u{5f0f}", "Recall mode")
    )));
    lines.push(choice(
        app.cursor == index + 1,
        t("\u{5feb}\u{901f}\u{ff08}\u{672c}\u{5730}\u{53ec}\u{56de}\u{ff0c}\u{9ed8}\u{8ba4}\u{ff09}", "Fast (local retrieval, default)"),
    ));
    lines.push(choice(
        app.cursor == index + 2,
        t(
            "\u{9ad8}\u{8d28}\u{91cf}\u{ff08}\u{6a21}\u{578b}\u{7b5b}\u{9009}\u{6807}\u{9898}\u{ff0c}\u{9700}\u{914d}\u{7f6e} API\u{ff09}",
            "High quality (model selects titles; API required)",
        ),
    ));
    let index_state = app.live.index["state"].as_str().unwrap_or("unknown");
    lines.push(line(format!(
        "{}: {}",
        t("\u{540e}\u{53f0}\u{7d22}\u{5f15}", "Background index"),
        index_state
    )));
    if let Some(error) = app.live.index["error"].as_str() {
        lines.push(fail_line(error.to_owned()));
    }
    if app.live.model_progress["active"] == true {
        lines.push(line(crate::output::model_task_text(
            &app.live.model_progress,
        )));
    }
    if let Some(status) = crate::progress::inference_progress_text(&app.live.inference) {
        if app.live.inference["host_recovery_required"] == true {
            lines.push(fail_line(status));
        } else {
            lines.push(line(status));
        }
    }
    if let Some(error) = app.live.inference["error"].as_str() {
        lines.push(fail_line(error.to_owned()));
    }
    lines.push(line(t(
        "\u{9ed8}\u{8ba4} CPU\u{ff1b}runtime \u{5185}\u{5171}\u{4eab}\u{6a21}\u{578b}\u{4e0e}\u{63a8}\u{7406}\u{ff1b}\u{5931}\u{8d25}\u{62a5}\u{9519}\u{ff0c}\u{4e0d}\u{5207}\u{6362}\u{5f15}\u{64ce}\u{3002}",
        "CPU by default; shared model and inference inside runtime; failures report errors without switching engines.",
    )));
    lines.push(line(t(
        "\u{5361}\u{4f4f}\u{65f6}\u{5728}\u{7ec8}\u{7aef}\u{8fd0}\u{884c}\u{ff1a}rsrs model reset-cpu",
        "If stuck, run in terminal: rsrs model reset-cpu",
    )));
    lines.push(choice(
        app.cursor == index + 3,
        t(
            "\u{914d}\u{7f6e}\u{9ad8}\u{8d28}\u{91cf}\u{53ec}\u{56de} API\u{ff08}\u{5730}\u{5740} / \u{6a21}\u{578b} / \u{5bc6}\u{94a5}\u{ff09}",
            "Configure recall API (URL / model / key)",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 4,
        t(
            "\u{6d4b}\u{8bd5}\u{5feb}\u{901f}\u{53ec}\u{56de}",
            "Test fast recall",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 5,
        t(
            "\u{6d4b}\u{8bd5}\u{9ad8}\u{8d28}\u{91cf}\u{53ec}\u{56de}",
            "Test high-quality recall",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 6,
        t(
            "\u{53d6}\u{6d88}\u{5f53}\u{524d}\u{6a21}\u{578b}\u{4efb}\u{52a1}",
            "Cancel current model task",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 7,
        t(
            "\u{4ece}\u{6240}\u{9009}\u{4e0b}\u{8f7d}\u{6e90}\u{91cd}\u{65b0}\u{4e0b}\u{8f7d}",
            "Restart download from selected source",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 8,
        t(
            "\u{63a8}\u{7406} / Recall Benchmark",
            "Inference / Recall Benchmark",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 9,
        t(
            "\u{9009}\u{62e9}\u{5f15}\u{64ce}\u{4e0e}\u{6a21}\u{578b}\u{6743}\u{91cd}\u{2026}",
            "Choose engine and model weights\u{2026}",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 10,
        t(
            "五轴注意力融合设置…",
            "Five-axis attention fusion settings…",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 11,
        t("0  \u{8fd4}\u{56de}", "0  Back"),
    ));
    lines
}

fn workspace_body(app: &App) -> Vec<Line<'static>> {
    let labels = [
        t("\u{6b63}\u{5e38}\u{670d}\u{52a1}", "Normal service"),
        t("\u{53ea}\u{8bfb}\u{670d}\u{52a1}", "Read-only service"),
        t("\u{7981}\u{7528}\u{670d}\u{52a1}", "Disabled service"),
    ];
    vec![
        line(format!(
            "{}: {}",
            t("\u{5f53}\u{524d}", "Current"),
            workspace_label(&app.live.workspace)
        )),
        choice(
            app.cursor == 0,
            format!("{}  {}", t("\u{9009}\u{62e9}", "Choice"), labels[app.workspace_draft]),
        ),
        choice(app.cursor == 1, t("0  \u{8fd4}\u{56de}", "0  Back")),
        line(t(
            "\u{5de6}\u{53f3}\u{952e}\u{9009}\u{62e9}\u{ff0c}\u{56de}\u{8f66}\u{4fdd}\u{5b58}\u{ff1b}\u{5207}\u{6362}\u{8d26}\u{53f7}\u{540e}\u{4fdd}\u{6301}\u{3002}",
            "Left/right chooses. Enter saves for all accounts on this device.",
        )),
    ]
}

fn lang_body(app: &App) -> Vec<Line<'static>> {
    vec![
        choice(app.cursor == 0, t("1  \u{4e2d}\u{6587}", "1  Chinese")),
        choice(app.cursor == 1, t("2  English", "2  English")),
        choice(app.cursor == 2, t("0  \u{8fd4}\u{56de}", "0  Back")),
        line(t(
            "\u{4efb}\u{610f}\u{754c}\u{9762}\u{6309} 7 \u{4e5f}\u{4f1a}\u{7acb}\u{5373}\u{5207}\u{6362}\u{3002}\u{56de}\u{8f66}\u{5728}\u{8fd9}\u{91cc}\u{9009}\u{5b9a}\u{3002}",
            "7 also switches immediately from any screen. Enter selects here.",
        )),
    ]
}

fn version_body(app: &App) -> Vec<Line<'static>> {
    let tools = tools_on_path();
    let tool = tools
        .get(app.manager_pick)
        .copied()
        .unwrap_or(Manager::Direct);
    let spec = if app.live.update_spec.is_empty() {
        channel_spec()
    } else {
        app.live.update_spec.clone()
    };
    let status = if app.live.ver_line.is_empty() {
        format!(
            "{} {}",
            t("\u{5f53}\u{524d}", "Current"),
            env!("CARGO_PKG_VERSION")
        )
    } else {
        app.live.ver_line.clone()
    };
    vec![
        line(status),
        line(runtime_version_label(&app.live)),
        line(format!("{}: {}", t("\u{542f}\u{52a8}\u{65b9}\u{5f0f}", "Started as"), manager_name(detect_preferred()))),
        choice(app.cursor == 0, t("\u{68c0}\u{67e5}\u{6700}\u{65b0}\u{7248}", "Check the newest version")),
        choice(app.cursor == 1, format!("{} {}  {spec}", t("\u{66f4}\u{65b0}", "Update"), manager_name(tool))),
        choice(app.cursor == 2, t("0  \u{8fd4}\u{56de}", "0  Back")),
        line(t("\u{5de6}\u{53f3}\u{952e}\u{9009}\u{62e9}\u{7528}\u{54ea}\u{4e2a}\u{5305}\u{7ba1}\u{7406}\u{5668}\u{66f4}\u{65b0}\u{3002}\u{76f4}\u{63a5}\u{8fd0}\u{884c}\u{7684}\u{7a0b}\u{5e8f}\u{4e0d}\u{4f1a}\u{88ab}\u{8fd9}\u{6b21}\u{66f4}\u{65b0}\u{66ff}\u{6362}\u{3002}", "Left and right choose the package manager. A direct binary is not replaced by the update.")),
    ]
}

fn runtime_version_label(live: &Live) -> String {
    if live.runtime_version.is_empty() {
        t("Runtime \u{672a}\u{8fde}\u{63a5}", "Runtime not connected")
    } else {
        format!("Runtime {}", live.runtime_version)
    }
}

fn detect_preferred() -> Manager {
    tools_on_path().first().copied().unwrap_or(Manager::Direct)
}

fn doctor_value(live: &Live, name: &str) -> String {
    if name == "embedder" && live.model_progress["active"] == true {
        return t(
            "\u{6b63}\u{5728}\u{540e}\u{53f0}\u{51c6}\u{5907}\u{6a21}\u{578b}",
            "Preparing model in background",
        );
    }
    live.doctor
        .iter()
        .find(|(item, _, _)| item == name)
        .map(|(_, status, value)| {
            let value = if value.starts_with("BGE-M3 preparation/indexing ")
                || value.starts_with("Model operation in progress:")
            {
                t(
                    "\u{5df2}\u{5b89}\u{6392}\u{540e}\u{53f0}\u{51c6}\u{5907}",
                    "Background preparation scheduled",
                )
            } else if value.starts_with("BGE-M3 index pending;") {
                t(
                    "\u{7b49}\u{5f85}\u{540e}\u{53f0}\u{91cd}\u{5efa}",
                    "Waiting for background rebuild",
                )
            } else {
                value.clone()
            };
            format!("{status}  {value}")
        })
        .unwrap_or_else(|| t("\u{8fd8}\u{6ca1}\u{6709}\u{8bfb}\u{5230}", "not read yet"))
}

#[cfg(test)]
mod model_menu_tests {
    use super::*;

    #[test]
    fn small_terminal_keeps_weight_actions_visible() -> Result<()> {
        let shared = Arc::new(Mutex::new(Live::empty()));
        let mut app = App::new(shared);
        app.live.connected = true;
        app.page = Page::Model;
        let variants = (0..12).map(|index| serde_json::json!({
            "name":format!("runtime-{index}"),"size":7340032,"state":"present"
        })).collect::<Vec<_>>();
        let count = variants.len();
        app.live.model_settings = serde_json::json!({"engine":"cpu","model":"runtime-0",
            "variants":variants});
        let mut form = model_weights::Form::new(&app.live.model_settings)?;
        form.cursor = count + 1;
        app.overlay = Overlay::ModelWeights(form);
        let backend = ratatui::backend::TestBackend::new(70, 20);
        let mut terminal = Terminal::new(backend)?;
        terminal.draw(|frame| draw(frame, &app))?;
        let screen = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(
            screen.contains("Validate and load")
                || screen.contains("\u{6821}\u{9a8c}\u{5e76}\u{52a0}\u{8f7d}"),
            "{screen}"
        );
        Ok(())
    }

    #[test]
    fn selection_commands_check_errors_read_back_and_always_retire_the_session() -> Result<()> {
        let mut calls = Vec::new();
        let settings = serde_json::json!({"engine":"cpu","model":"fp16","variants":[]});
        let actual = save_model_settings_with("cpu", Some("fp16"), |args| {
            calls.push(args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
            Ok(
                serde_json::json!({"status":"ok","summary":if args[1] == "load" {
                serde_json::json!({"loaded":true,"validated":true,"saved":true})
            } else { settings.clone() }}),
            )
        })
        .map_err(anyhow::Error::msg)?;
        assert_eq!(actual, settings);
        assert_eq!(
            calls,
            vec![
                vec!["model", "load", "cpu", "--model", "fp16"],
                vec!["model", "engine"]
            ]
        );
        let mut failures = 0;
        assert!(save_model_settings_with("cpu", Some("fp16"), |_| {
            failures += 1;
            Ok(serde_json::json!({"status":"fail","errors":["reset failed"]}))
        })
        .is_err());
        assert_eq!(failures, 1);
        assert!(save_model_settings_with("gpu", Some("fp16"), |_| Ok(
            serde_json::json!({"status":"ok","summary":{"engine":"cpu","model":"quantized"}})
        ))
        .is_err());
        assert!(probe_notice(serde_json::json!({"summary":{"ready":false}})).is_err());
        assert!(probe_notice(serde_json::json!({"summary":{"ready":true}})).is_err());
        Ok(())
    }

    #[test]
    fn picker_cancel_missing_weights_and_download_confirmation_do_not_write() -> Result<()> {
        let shared = Arc::new(Mutex::new(Live::empty()));
        let mut app = App::new(shared);
        app.live.connected = true;
        app.live.model_settings = serde_json::json!({"engine":"cpu","model":"runtime-only",
            "variants":[{"name":"runtime-only","size":7340032,"state":"missing"}]});
        app.overlay = Overlay::ModelWeights(model_weights::Form::new(&app.live.model_settings)?);
        assert!(!handle(&mut app, KeyCode::Esc));
        assert!(matches!(app.overlay, Overlay::None));
        let mut form = model_weights::Form::new(&app.live.model_settings)?;
        form.cursor = 2;
        app.overlay = Overlay::ModelWeights(form);
        model_weights_key(&mut app, KeyCode::Enter);
        assert!(
            matches!(app.overlay, Overlay::ModelWeights(_)),
            "missing weights must not be saved"
        );
        app.live.model_settings["variants"][0]["state"] = serde_json::json!("present");
        model_weights_key(&mut app, KeyCode::Enter);
        assert!(matches!(
            app.overlay,
            Overlay::Confirm {
                cursor: 1,
                kind: ConfirmKind::Weights(_, _),
                ..
            }
        ));
        confirm_key(&mut app, KeyCode::Enter);
        assert!(matches!(app.overlay, Overlay::None));
        let mut form = model_weights::Form::new(&app.live.model_settings)?;
        form.cursor = 3;
        app.overlay = Overlay::ModelWeights(form);
        model_weights_key(&mut app, KeyCode::Enter);
        let Overlay::Confirm {
            text,
            cursor: 1,
            kind: ConfirmKind::InstallVariant(engine, name),
        } = &app.overlay
        else {
            anyhow::bail!("download must require confirmation defaulting to cancel");
        };
        assert_eq!(engine, "cpu");
        assert_eq!(name, "runtime-only");
        assert!(text.contains("7 MiB"));
        assert!(text.contains("543 MiB"));
        confirm_key(&mut app, KeyCode::Enter);
        assert!(app
            .outcome
            .lock()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .is_none());
        assert_eq!(app.live.model_settings["model"], "runtime-only");
        Ok(())
    }

    #[test]
    fn mirror_cancel_restart_keys_and_live_progress_match_the_menu() -> anyhow::Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let previous = respire::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let result = (|| -> anyhow::Result<()> {
            std::fs::write(
                dir.path().join("agent.json"),
                serde_json::to_vec(&serde_json::json!({
                    "model_mirror": "http://127.0.0.1:9999"
                }))?,
            )?;
            let mut app = App::new(Arc::new(Mutex::new(Live::empty())));
            for width in [40, 100] {
                let rows = home_body(&app, width)
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(rows.contains(&runtime_version_label(&app.live)));
            }
            let rows = version_body(&app)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rows.contains(&runtime_version_label(&app.live)));
            app.live.runtime_version = "1.0.9".to_owned();
            let rows = home_body(&app, 100)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rows.contains("CLI "));
            assert!(rows.contains(crate::app_version::embedded()));
            assert!(rows.contains("Runtime 1.0.9"));
            let rows = version_body(&app)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rows.contains("Runtime 1.0.9"));
            app.page = Page::Model;
            app.cursor = 2;
            model_key(&mut app, KeyCode::Enter);
            let Overlay::ModelMirror(input) = &app.overlay else {
                anyhow::bail!("mirror picker did not open");
            };
            assert_eq!(input.text, "http://127.0.0.1:9999");
            let picker =
                overlay_lines(&app).ok_or_else(|| anyhow::anyhow!("mirror picker has no rows"))?;
            assert!(picker
                .iter()
                .any(|line| line.to_string().contains("hf-mirror.com")));
            app.live.model_progress = serde_json::json!({"id":"fixture-task","active":true,"phase":"download","item":"model_quantized.onnx","done":25,"total":100});
            let rows = model_body(&app)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(rows.contains("25.0%"));
            assert!(rows.contains("model_quantized.onnx"));
            app.live.inference = serde_json::json!({"active":true,"queued":3,"phase":"loading"});
            let busy_rows = model_body(&app)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let inference_text = crate::progress::inference_progress_text(&app.live.inference)
                .ok_or_else(|| anyhow::anyhow!("missing inference status"))?;
            assert!(busy_rows.contains(&inference_text));
            app.live.inference = serde_json::json!({"host_recovery_required":true});
            let stalled_rows = model_body(&app)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            let stalled_text = crate::progress::inference_progress_text(&app.live.inference)
                .ok_or_else(|| anyhow::anyhow!("missing stalled status"))?;
            assert!(stalled_rows.contains(&stalled_text));
            app.cursor = 9 + model_engines().len() + usize::from(cfg!(windows));
            model_key(&mut app, KeyCode::Enter);
            assert!(
                matches!(&app.overlay, Overlay::Confirm { kind: ConfirmKind::CancelModel(id), .. } if id == "fixture-task")
            );
            app.cursor += 1;
            model_key(&mut app, KeyCode::Enter);
            assert!(
                matches!(&app.overlay, Overlay::Confirm { kind: ConfirmKind::RestartM3(id, mirror), .. } if id == "fixture-task" && mirror == "http://127.0.0.1:9999")
            );
            app.cursor += 1;
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(&app.overlay, Overlay::RecallTest(_)));
            app.overlay = Overlay::None;
            app.cursor += 1;
            app.live.model_settings = Value::Null;
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(app.overlay, Overlay::None));
            app.live.model_settings = serde_json::json!({"engine":"cpu","model":"runtime-only",
                "variants":[{"name":"runtime-only","size":7340032,"state":"present"}]});
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(app.overlay, Overlay::ModelWeights(_)));
            app.overlay = Overlay::None;
            app.cursor += 2;
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(app.page, Page::Home));
            Ok(())
        })();
        match previous {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        result
    }
}

fn workspace_label(mode: &str) -> String {
    match mode {
        "readonly" => t("\u{53ea}\u{8bfb}\u{670d}\u{52a1}", "Read-only service"),
        "off" => t("\u{7981}\u{7528}\u{670d}\u{52a1}", "Disabled service"),
        _ => t("\u{6b63}\u{5e38}\u{670d}\u{52a1}", "Normal service"),
    }
}

fn overlay_lines(app: &App) -> Option<Vec<Line<'static>>> {
    match &app.overlay {
        Overlay::None => None,
        Overlay::ModelWeights(form) => Some(form.lines(&app.live.model_settings)),
        Overlay::RecallFusion(form) => Some(form.lines()),
        Overlay::HostModel => Some(vec![
            line(t("\u{7b49}\u{5f85}\u{5bbf}\u{4e3b}\u{5b50}\u{8fdb}\u{7a0b}\u{8fd4}\u{56de}\u{7ed3}\u{679c}", "Waiting for the host subprocess result")),
            line(t("\u{5b9e}\u{65f6}\u{8fdb}\u{5ea6}\u{4e0d}\u{53ef}\u{7528}\u{ff1b}\u{6b64}\u{5904}\u{4e0d}\u{652f}\u{6301}\u{53d6}\u{6d88}", "Live progress unavailable; cancellation is not supported here")),
        ]),
        Overlay::SavingWeights => Some(vec![
            line(match app.live.model_progress["phase"].as_str() {
                Some("verify") => t("\u{6b63}\u{5728}\u{6821}\u{9a8c}\u{56fa}\u{5b9a}\u{5927}\u{5c0f}\u{3001}SHA-256 \u{548c}\u{6a21}\u{578b}\u{8eab}\u{4efd}", "Validating pinned size, SHA-256 and model identity"),
                Some("load") => t("\u{6b63}\u{5728}\u{5b9e}\u{9645}\u{52a0}\u{8f7d}\u{548c}\u{8bd5}\u{63a8}\u{7406}\u{ff1b}\u{6210}\u{529f}\u{540e}\u{4fdd}\u{5b58}", "Loading and running trial inference; saving after success"),
                _ => t("\u{7b49}\u{5f85}\u{52a0}\u{8f7d}\u{4e8b}\u{52a1}\u{5b8c}\u{6210}\u{ff1b}\u{4e0d}\u{4f1a}\u{4e0b}\u{8f7d}", "Waiting for model load transaction; no downloads"),
            }),
            line(t("\u{8bf7}\u{7b49}\u{5f85}\u{ff1b}\u{52a0}\u{8f7d}\u{671f}\u{95f4}\u{4e0d}\u{63a5}\u{53d7}\u{53d6}\u{6d88}", "Please wait; loading cannot be cancelled")),
        ]),
        Overlay::ModelMirror(input) => {
            let mut lines = vec![line(t("BGE-M3 \u{4e0b}\u{8f7d}\u{6e90}", "BGE-M3 download source"))];
            lines.extend(respire_commands::model_download::MIRRORS.iter().map(|mirror| choice(input.text == *mirror, (*mirror).to_owned())));
            lines.push(input.line(70, true, false));
            lines.push(line(t("\u{4e0a}\u{4e0b}\u{952e}\u{9009}\u{62e9}\u{ff0c}\u{4e5f}\u{53ef}\u{8f93}\u{5165}\u{81ea}\u{5b9a}\u{4e49}\u{5730}\u{5740}\u{ff1b}\u{56de}\u{8f66}\u{4fdd}\u{5b58}\u{ff0c}Esc \u{8fd4}\u{56de}\u{3002}", "Up/down selects; custom URL supported; Enter saves, Esc returns.")));
            lines.push(line(t("\u{8fd0}\u{884c}\u{4e2d}\u{7684}\u{4e0b}\u{8f7d}\u{4e0d}\u{4f1a}\u{76f4}\u{63a5}\u{6362}\u{6e90}\u{ff1b}\u{4fdd}\u{5b58}\u{540e}\u{53ef}\u{53d6}\u{6d88}\u{5e76}\u{91cd}\u{65b0}\u{4e0b}\u{8f7d}\u{3002}", "An active download keeps its source; cancel and restart after saving.")));
            Some(lines)
        }
        Overlay::RecallApi(_) | Overlay::RecallTest(_) => Some(Vec::new()),
        Overlay::ModelTask(task) => Some(task.lines()),
        Overlay::Edit { buf, cursor } => {
            let mut shown = String::new();
            for (index, ch) in buf.chars().enumerate() {
                if index == *cursor {
                    shown.push('|');
                }
                shown.push(ch);
            }
            if *cursor >= buf.chars().count() {
                shown.push('|');
            }
            Some(vec![
                line(String::new()),
                line(t("\u{670d}\u{52a1}\u{5668}\u{5730}\u{5740}", "Server address")),
                line(shown),
            ])
        }
        Overlay::Confirm { text, cursor, .. } => Some(vec![
            line(String::new()),
            line(text.clone()),
            choice(*cursor == 0, t("1  \u{786e}\u{8ba4}", "1  Confirm")),
            choice(*cursor == 1, t("2  \u{53d6}\u{6d88}", "2  Cancel")),
        ]),
    }
}

fn line(text: String) -> Line<'static> {
    Line::from(text)
}

fn choice(on: bool, text: String) -> Line<'static> {
    let prefix = if on { "> " } else { "  " };
    let style = if on {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    Line::from(Span::styled(format!("{prefix}{text}"), style))
}

fn ok_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Green)))
}

fn warn_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Yellow)))
}

fn fail_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Red)))
}

fn setup() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let result = (|| -> Result<_> {
        execute!(stdout(), EnterAlternateScreen, event::EnableBracketedPaste)?;
        Ok(Terminal::new(CrosstermBackend::new(stdout()))?)
    })();
    match result {
        Ok(terminal) => Ok(terminal),
        Err(mut error) => {
            let restore = execute!(
                stdout(),
                event::DisableBracketedPaste,
                LeaveAlternateScreen,
                crossterm::cursor::Show
            );
            let raw_mode = disable_raw_mode();
            if let Err(cleanup) = restore {
                error = error.context(format!("terminal restoration failed: {cleanup}"));
            }
            if let Err(cleanup) = raw_mode {
                error = error.context(format!("disabling raw mode failed: {cleanup}"));
            }
            Err(error)
        }
    }
}

fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    execute!(
        terminal.backend_mut(),
        event::DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    Ok(terminal.show_cursor()?)
}
