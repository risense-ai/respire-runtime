//! extract --tui - interactive session-import picker (ratatui).
//!
//! Keys: UP/DOWN/jk move, Space toggle, a all, e extract checked, r refresh, q quit.
//! Extraction runs on a worker thread and reports a determinate progress bar.

use std::collections::HashSet;
use std::io::stdout;
use std::sync::mpsc::{self, Receiver, Sender};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, BorderType, Gauge, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::session_import::{self, Source};

const ACCENT: Color = Color::Rgb(86, 156, 214);
const BAR_BG: Color = Color::Rgb(22, 26, 34);

enum Work {
    Progress(String, usize, usize),
    Done(String),
    Failed(String),
}

struct App {
    rows: Vec<Source>,
    checked: HashSet<String>,
    cursor: usize,
    list_state: ListState,
    log: Vec<Line<'static>>,
    receiver: Option<Receiver<Work>>,
    phase: String,
    done: usize,
    total: usize,
    running: bool,
    should_exit: bool,
}

impl App {
    fn new() -> Self {
        let rows = session_import::source_list();
        let checked: HashSet<String> = rows
            .iter()
            .filter(|source| source.installed)
            .map(|source| source.id.clone())
            .collect();
        let mut app = Self {
            rows,
            checked,
            cursor: 0,
            list_state: ListState::default(),
            log: vec![Line::styled(
                "Check sources to import, press e to extract; installed sources are pre-checked.".to_owned(),
                Style::default().fg(Color::DarkGray),
            )],
            receiver: None,
            phase: String::new(),
            done: 0,
            total: 0,
            running: false,
            should_exit: false,
        };
        app.sync_list_state();
        app
    }

    fn sync_list_state(&mut self) {
        self.list_state
            .select(Some(self.cursor.min(self.rows.len().saturating_sub(1))));
    }

    fn log_line(&mut self, text: String, color: Color) {
        let stamp = chrono::Local::now().format("%H:%M:%S").to_string();
        self.log.push(Line::from(vec![
            Span::styled(format!("{stamp} "), Style::default().fg(Color::DarkGray)),
            Span::styled(text, Style::default().fg(color)),
        ]));
        if self.log.len() > 200 {
            self.log.drain(0..self.log.len() - 200);
        }
    }

    fn selected_ids(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|source| self.checked.contains(&source.id))
            .map(|source| source.id.clone())
            .collect()
    }

    fn start_extract(&mut self) {
        if self.running {
            self.log_line("extraction already running".to_owned(), Color::Yellow);
            return;
        }
        let ids = self.selected_ids();
        if ids.is_empty() {
            self.log_line("no source checked - Space to check, then press e".to_owned(), Color::Yellow);
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        self.running = true;
        self.done = 0;
        self.total = 0;
        self.phase = "scanning".to_owned();
        self.log_line(format!("extracting {} source(s)\u{2026}", ids.len()), ACCENT);
        spawn_worker(ids, sender);
    }

    fn drain(&mut self) {
        let Some(receiver) = self.receiver.as_ref() else {
            return;
        };
        let mut messages = Vec::new();
        let mut disconnected = false;
        loop {
            match receiver.try_recv() {
                Ok(message) => messages.push(message),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        for message in messages {
            match message {
                Work::Progress(phase, done, total) => {
                    self.phase = phase;
                    self.done = done;
                    self.total = total;
                }
                Work::Done(summary) => {
                    self.running = false;
                    self.log_line(summary, Color::Green);
                }
                Work::Failed(error) => {
                    self.running = false;
                    self.log_line(error, Color::Red);
                }
            }
        }
        if disconnected && self.running {
            self.running = false;
            self.log_line("extraction worker stopped unexpectedly".to_owned(), Color::Red);
        }
        if !self.running {
            self.receiver = None;
        }
    }

    fn refresh(&mut self) {
        self.rows = session_import::source_list();
        self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
        self.sync_list_state();
        self.log_line("source status refreshed".to_owned(), ACCENT);
    }
}

fn spawn_worker(ids: Vec<String>, sender: Sender<Work>) {
    std::thread::spawn(move || {
        let options = session_import::ScanOptions::default();
        let mut sessions = Vec::new();
        for id in &ids {
            let _ = sender.send(Work::Progress(format!("scanning {id}"), 0, 0));
            if let Some(scanner) = session_import::find_scanner(id) {
                let mut found = scanner.scan(&options);
                found.retain(|session| options.matches(session));
                sessions.extend(found);
            }
        }
        let sessions = session_import::dedupe(sessions);
        let cursor = session_import::Cursor::load();
        let fresh: Vec<_> = sessions
            .into_iter()
            .filter(|session| !cursor.is_imported(session))
            .collect();
        let pending = session_import::cap_per_platform(fresh, options.limit);
        if pending.is_empty() {
            let _ = sender.send(Work::Done("no new sessions to import".to_owned()));
            return;
        }

        let convert = session_import::ConvertOptions {
            kind: crate::Kind::Context,
            importance: "important".to_owned(),
            parent: String::new(),
            user: crate::service::current_user(),
            device: crate::service::device_tag(),
            project: String::new(),
        };
        let mut entries: Vec<_> = pending
            .iter()
            .map(|session| session_import::session_entry(session, &convert))
            .collect();
        let mut cursor = cursor;
        let result = session_import::import_entries(
            &mut entries,
            "",
            |done, total| {
                let _ = sender.send(Work::Progress("storing memories".to_owned(), done, total));
            },
            |start, completed| {
                for (offset, ok) in completed.iter().enumerate() {
                    if *ok {
                        cursor.mark(&pending[start + offset]);
                    }
                }
                cursor.save()?;
                Ok(())
            },
        );
        match result {
            Ok(outcome) => {
                let _ = sender.send(Work::Done(format!("imported {} memory(ies)", outcome.imported)));
            }
            Err(error) => {
                let _ = sender.send(Work::Failed(format!("{error}")));
            }
        }
    });
}

pub fn run() -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        anyhow::bail!("extract --tui needs a real terminal (stdin/stdout must both be tty)");
    }
    enable_raw_mode()?;
    let mut app = App::new();
    let mut terminal = match setup_terminal() {
        Ok(terminal) => terminal,
        Err(error) => {
            disable_raw_mode()?;
            return Err(error);
        }
    };
    let result = event_loop(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    disable_raw_mode()?;
    result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>> {
    execute!(stdout(), EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(terminal.show_cursor()?)
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    while !app.should_exit || app.running {
        app.drain();
        terminal.draw(|frame| ui(frame, app))?;
        if !event::poll(std::time::Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if app.running {
                    app.log_line(
                        "extraction in progress - waiting for it to finish before exit".to_owned(),
                        Color::Yellow,
                    );
                }
                app.should_exit = true;
            }
            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                app.should_exit = true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.cursor = app.cursor.saturating_sub(1);
                app.sync_list_state();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if app.cursor + 1 < app.rows.len() {
                    app.cursor += 1;
                }
                app.sync_list_state();
            }
            KeyCode::Char(' ') => {
                if let Some(source) = app.rows.get(app.cursor) {
                    let id = source.id.clone();
                    if !app.checked.remove(&id) {
                        app.checked.insert(id);
                    }
                }
            }
            KeyCode::Char('a') => {
                if app.checked.len() == app.rows.len() {
                    app.checked.clear();
                } else {
                    for source in &app.rows {
                        app.checked.insert(source.id.clone());
                    }
                }
            }
            KeyCode::Char('e') => app.start_extract(),
            KeyCode::Char('r') => app.refresh(),
            _ => {}
        }
    }
    Ok(())
}

fn ui(frame: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let top = Paragraph::new(Line::from(vec![
        Span::styled(" rsrs ", Style::default().fg(Color::Black).bg(ACCENT).bold()),
        Span::styled(" extract ", Style::default().fg(Color::White).bg(BAR_BG)),
        Span::styled(
            "  Space check   a all   e extract   r refresh   q quit  ",
            Style::default().fg(Color::DarkGray).bg(BAR_BG),
        ),
    ]))
    .style(Style::default().bg(BAR_BG));
    frame.render_widget(top, outer[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(outer[1]);

    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|source| {
            let mark = if app.checked.contains(&source.id) { "[x]" } else { "[ ]" };
            let detect = if source.installed {
                Span::styled(" detected", Style::default().fg(Color::Green))
            } else {
                Span::styled(" missing", Style::default().fg(Color::DarkGray))
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {mark} "), Style::default().fg(ACCENT).bold()),
                Span::styled(
                    format!("{:<14}", source.id),
                    Style::default().fg(Color::White).bold(),
                ),
                detect,
                Span::styled(
                    format!("  {}", source.name),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();
    let checked_n = app.checked.len();
    let list = List::new(items)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(70, 78, 94)))
                .title(Span::styled(
                    format!(" Sources ({checked_n}/{} checked) ", app.rows.len()),
                    Style::default().fg(ACCENT).bold(),
                )),
        )
        .highlight_style(Style::default().bg(Color::Rgb(34, 44, 62)))
        .highlight_symbol(" ");
    frame.render_stateful_widget(list, mid[0], &mut app.list_state);

    let log_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Rgb(70, 78, 94)))
        .title(Span::styled(" log ", Style::default().fg(ACCENT).bold()));
    let log_area = log_block.inner(mid[1]);
    frame.render_widget(log_block, mid[1]);
    let show: Vec<Line> = app
        .log
        .iter()
        .rev()
        .take(log_area.height as usize)
        .rev()
        .cloned()
        .collect();
    frame.render_widget(Paragraph::new(show).wrap(Wrap { trim: true }), log_area);

    let ratio = if app.total == 0 { 0.0 } else { app.done as f64 / app.total as f64 };
    let label = if app.running {
        format!("{} {}/{}", app.phase, app.done, app.total)
    } else {
        "idle - press e to extract checked sources".to_owned()
    };
    let gauge = Gauge::default()
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(70, 78, 94))),
        )
        .gauge_style(if app.running {
            Style::default().fg(ACCENT)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .ratio(ratio.clamp(0.0, 1.0))
        .label(label);
    frame.render_widget(gauge, outer[2]);
}
