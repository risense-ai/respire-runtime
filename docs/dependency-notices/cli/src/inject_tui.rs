//! inject --tui - interactive inject picker (ratatui).
//!
//! Layout: top bar brand + hints | middle: host list (checks + state colors) above,
//! shortcut card left / op log right | bottom bar status.
//! Keys: UPDOWN/jk move   Space toggle   a select-all/clear   i inject checked
//! u remove checked (y to confirm)   r refresh   q/Esc quit.
//! Actions reuse inject.rs `targets()`/`inject_one()`/`remove_one()`, same as the non-interactive path.

use std::collections::HashSet;
use std::io::stdout;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, BorderType, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::inject::{inject_one, remove_one, targets, Target};

/// Selected-row highlight and brand accent.
const ACCENT: Color = Color::Rgb(86, 156, 214);
/// Top/bottom bar background (near-black blue-gray, not flat black).
const BAR_BG: Color = Color::Rgb(22, 26, 34);

struct App {
    rows: Vec<Target>,
    checked: HashSet<String>,
    cursor: usize,
    list_state: ListState,
    log: Vec<Line<'static>>,
    /// Two-step uninstall confirm: when true, the next u/y actually runs it.
    confirm_remove: bool,
    should_exit: bool,
}

impl App {
    fn new() -> Result<Self> {
        let rows = targets()?;
        let checked: HashSet<String> = rows
            .iter()
            .filter(|t| t.likely_installed || t.id == "generic")
            .map(|t| t.id.to_owned())
            .collect();
        let mut app = Self {
            rows,
            checked,
            cursor: 0,
            list_state: ListState::default(),
            log: vec![Line::styled(
                "Check hosts to write, press i to inject; u uninstalls checked targets (y to confirm).".to_owned(),
                Style::default().fg(Color::DarkGray),
            )],
            confirm_remove: false,
            should_exit: false,
        };
        app.sync_list_state();
        Ok(app)
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
            .filter(|t| self.checked.contains(t.id))
            .map(|t| t.id.to_owned())
            .collect()
    }

    /// Inject each checked target; log success/skip counts.
    fn run_inject(&mut self) {
        let ids = self.selected_ids();
        if ids.is_empty() {
            self.log_line(
                "No host checked - Space to check, then press i".to_owned(),
                Color::Yellow,
            );
            return;
        }
        let mut ok = 0;
        let mut skip = 0;
        for id in &ids {
            match inject_one(id) {
                Ok(true) => {
                    ok += 1;
                    if let Some(t) = self.rows.iter_mut().find(|t| t.id == id) {
                        t.state = "fresh";
                    }
                    self.log_line(format!("WRITE injected {id}"), Color::Green);
                }
                Ok(false) => {
                    skip += 1;
                    if let Some(t) = self.rows.iter_mut().find(|t| t.id == id) {
                        t.state = "fresh";
                    }
                    self.log_line(format!("PASS {id} already up to date"), Color::DarkGray);
                }
                Err(e) => self.log_line(format!("FAIL {id} inject failed: {e}"), Color::Red),
            }
        }
        self.log_line(
            format!(
                "inject done: wrote {ok}, unchanged {skip}, {} total",
                ids.len()
            ),
            ACCENT,
        );
    }

    /// Uninstall each checked target (called after two-step confirm).
    fn run_remove(&mut self) {
        let ids = self.selected_ids();
        if ids.is_empty() {
            self.log_line(
                "No host checked - Space to check, then press u".to_owned(),
                Color::Yellow,
            );
            return;
        }
        let mut ok = 0;
        for id in &ids {
            match remove_one(id) {
                Ok(true) => {
                    ok += 1;
                    if let Some(t) = self.rows.iter_mut().find(|t| t.id == id) {
                        t.state = "none";
                    }
                    self.log_line(format!("PURGE uninstalled {id}"), Color::Yellow);
                }
                Ok(false) => {
                    self.log_line(format!("PASS {id} had no inject content"), Color::DarkGray)
                }
                Err(e) => self.log_line(format!("FAIL {id} uninstall failed: {e}"), Color::Red),
            }
        }
        self.log_line(
            format!("uninstall done: wrote {ok} of {} targets", ids.len()),
            ACCENT,
        );
    }

    fn refresh(&mut self) {
        match targets() {
            Ok(rows) => {
                self.rows = rows;
                self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
                self.sync_list_state();
                self.log_line("host status refreshed".to_owned(), ACCENT);
            }
            Err(e) => self.log_line(format!("refresh failed: {e}"), Color::Red),
        }
    }
}

/// State column (text + color).
fn state_span(t: &Target) -> Span<'static> {
    let (status, color) = match t.state {
        "fresh" => ("PASS fresh", Color::Green),
        "stale" => ("WARN stale", Color::Yellow),
        "none" => ("SKIP none", Color::Cyan),
        _ => ("MISSING", Color::DarkGray),
    };
    Span::styled(status, Style::default().fg(color))
}

pub fn run() -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        anyhow::bail!("inject --tui needs a real terminal (stdin/stdout must both be tty)");
    }
    enable_raw_mode()?;
    let mut app = match App::new() {
        Ok(a) => a,
        Err(e) => {
            disable_raw_mode()?;
            return Err(e);
        }
    };
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            disable_raw_mode()?;
            return Err(e);
        }
    };
    let res = event_loop(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    disable_raw_mode()?;
    res
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
    while !app.should_exit {
        terminal.draw(|f| ui(f, app))?;
        if !event::poll(std::time::Duration::from_millis(200))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.should_exit = true,
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
            KeyCode::Home => {
                app.cursor = 0;
                app.sync_list_state();
            }
            KeyCode::End => {
                app.cursor = app.rows.len().saturating_sub(1);
                app.sync_list_state();
            }
            KeyCode::Char(' ') => {
                if let Some(t) = app.rows.get(app.cursor) {
                    let id = t.id.to_owned();
                    if !app.checked.remove(&id) {
                        app.checked.insert(id);
                    }
                }
            }
            KeyCode::Char('a') => {
                if app.checked.len() == app.rows.len() {
                    app.checked.clear();
                    app.log_line("cleared checks".to_owned(), Color::DarkGray);
                } else {
                    for t in &app.rows {
                        app.checked.insert(t.id.to_owned());
                    }
                    app.log_line("selected all".to_owned(), ACCENT);
                }
            }
            KeyCode::Char('i') => app.run_inject(),
            KeyCode::Char('u') | KeyCode::Char('y') if app.confirm_remove => {
                app.confirm_remove = false;
                app.run_remove();
            }
            KeyCode::Char('u') => {
                let n = app.selected_ids().len();
                app.confirm_remove = true;
                app.log_line(
                    format!("will uninstall {n} checked target(s) - press u or y to confirm, any other key to cancel"),
                    Color::Yellow,
                );
            }
            KeyCode::Char('r') => app.refresh(),
            _ => {}
        }
        if !matches!(key.code, KeyCode::Char('u')) {
            app.confirm_remove = false;
        }
    }
    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    // -- Top bar: brand + key hints --
    let top = Paragraph::new(Line::from(vec![
        Span::styled(
            " rsrs ",
            Style::default().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::styled(" inject ", Style::default().fg(Color::White).bg(BAR_BG)),
        Span::styled(
            "  Space check   a all   i inject   u uninstall   r refresh   q quit  ",
            Style::default().fg(Color::DarkGray).bg(BAR_BG),
        ),
    ]))
    .style(Style::default().bg(BAR_BG));
    f.render_widget(top, outer[0]);

    // -- Middle: list on the left, shortcut card + log on the right --
    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(outer[1]);

    // Host list
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mark = if app.checked.contains(t.id) {
                "[x]"
            } else {
                "[ ]"
            };
            let detect = if t.likely_installed {
                Span::styled(" detected", Style::default().fg(Color::Green))
            } else {
                Span::styled(" missing", Style::default().fg(Color::DarkGray))
            };
            let mut line = vec![
                Span::styled(
                    format!(" {mark} "),
                    Style::default()
                        .fg(if mark == "[x]" {
                            ACCENT
                        } else {
                            Color::DarkGray
                        })
                        .bold(),
                ),
                Span::styled(
                    format!("{:<16}", t.name),
                    Style::default().fg(Color::White).bold(),
                ),
                detect,
                Span::raw("  "),
                state_span(t),
                Span::styled(
                    format!("  {}", t.path),
                    Style::default().fg(Color::DarkGray),
                ),
            ];
            if i == app.cursor {
                line.insert(0, Span::styled("ACTION", Style::default().fg(ACCENT)));
            } else {
                line.insert(0, Span::styled(" ", Style::default()));
            }
            ListItem::new(Line::from(line))
        })
        .collect();
    let checked_n = app.checked.len();
    let list = List::new(items)
        .block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::Rgb(70, 78, 94)))
                .title(Span::styled(
                    format!(" Hosts ({checked_n}/{} checked) ", app.rows.len()),
                    Style::default().fg(ACCENT).bold(),
                ))
                .title_bottom(Span::styled(
                    "detected or missing; status is PASS, WARN, SKIP, or MISSING",
                    Style::default().fg(Color::DarkGray),
                )),
        )
        .highlight_style(Style::default().bg(Color::Rgb(34, 44, 62)))
        .highlight_symbol(" ");
    f.render_stateful_widget(list, mid[0], &mut app.list_state);

    // Right: shortcut card + op log
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(mid[1]);

    let keys = Paragraph::new(vec![
        Line::from(vec![Span::styled(
            " Keys",
            Style::default().fg(ACCENT).bold(),
        )]),
        Line::styled("  UP/k DOWN/j   move", Style::default().fg(Color::White)),
        Line::styled(
            "  Space      check/uncheck",
            Style::default().fg(Color::White),
        ),
        Line::styled(
            "  a          select all / clear",
            Style::default().fg(Color::White),
        ),
        Line::styled(
            "  i          inject checked",
            Style::default().fg(Color::Green),
        ),
        Line::styled(
            "  u u/y      uninstall (confirm twice)",
            Style::default().fg(Color::Yellow),
        ),
        Line::styled(
            "  r refresh   q/Esc quit",
            Style::default().fg(Color::DarkGray),
        ),
    ])
    .block(
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Rgb(70, 78, 94))),
    );
    f.render_widget(keys, right[0]);

    let log_title = if app.confirm_remove {
        " WARN confirm uninstall "
    } else {
        " log "
    };
    let log_block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if app.confirm_remove {
            Color::Yellow
        } else {
            Color::Rgb(70, 78, 94)
        }))
        .title(Span::styled(
            log_title,
            Style::default()
                .fg(if app.confirm_remove {
                    Color::Yellow
                } else {
                    ACCENT
                })
                .bold(),
        ));
    let log_area = log_block.inner(right[1]);
    f.render_widget(log_block, right[1]);
    let show: Vec<Line> = app
        .log
        .iter()
        .rev()
        .take(log_area.height as usize)
        .rev()
        .cloned()
        .collect();
    f.render_widget(Paragraph::new(show).wrap(Wrap { trim: true }), log_area);

    // -- Bottom bar: status summary --
    let detected = app.rows.iter().filter(|t| t.likely_installed).count();
    let bottom = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" checked {checked_n}/{} ", app.rows.len()),
            Style::default().fg(ACCENT).bg(BAR_BG),
        ),
        Span::styled(
            format!(" detected {detected}/{} ", app.rows.len()),
            Style::default().fg(Color::DarkGray).bg(BAR_BG),
        ),
        Span::styled(
            " source docs/respire.md (embedded at compile) - rebuild then redistributes ",
            Style::default().fg(Color::DarkGray).bg(BAR_BG),
        ),
    ]))
    .style(Style::default().bg(BAR_BG));
    f.render_widget(bottom, outer[2]);
}
