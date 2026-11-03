//! TUI editor for the OpenAI-compatible title-selection service.
use super::text_input::Input;
use super::{choice, line, retrieval_action, t, KeyCode, Line};
use anyhow::{anyhow, Result};
use crossterm::event::{KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Instant;

pub(super) struct Form {
    values: [Input; 3],
    field: usize,
    error: String,
    saving: Option<(Instant, Receiver<Result<(), String>>)>,
}

pub(super) fn base() -> String {
    respire::service::read_agent_config()["recall_api_base"]
        .as_str()
        .map(str::to_owned)
        .or_else(respire::keystore::load_ds_last_base)
        .unwrap_or_else(|| crate::classify::DEFAULT_DS_BASE.to_owned())
}

fn key_for(base: &str) -> Option<String> {
    respire::env::var("RSRS_RECALL_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .or_else(|| {
            respire::keystore::load_classify_key(&format!(
                "ds@{}",
                respire::keystore::host_of(base)
            ))
        })
}

pub(super) fn ready() -> bool {
    key_for(&base()).is_some()
}

impl Form {
    pub(super) fn new() -> Self {
        let config = respire::service::read_agent_config();
        let values = [
            base(),
            config["recall_model"]
                .as_str()
                .unwrap_or(crate::classify::DEFAULT_DS_MODEL)
                .to_owned(),
            String::new(),
        ];
        Self {
            values: values.map(Input::new),
            field: 0,
            error: String::new(),
            saving: None,
        }
    }

    pub(super) fn paste(&mut self, text: &str) {
        if self.field < 3 && !self.saving() {
            self.values[self.field].paste(text);
        }
    }

    pub(super) fn key(&mut self, key: KeyEvent) {
        if self.saving.is_some() {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('s' | 'S'))
        {
            self.start_save();
            return;
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.field = (self.field + 1) % 4,
            KeyCode::BackTab | KeyCode::Up => self.field = (self.field + 3) % 4,
            KeyCode::Enter if self.field < 3 => self.field += 1,
            KeyCode::Enter => self.start_save(),
            _ if self.field < 3 => self.values[self.field].key(key),
            _ => {}
        }
    }

    fn start_save(&mut self) {
        let values = std::array::from_fn(|index| self.values[index].text.clone());
        let (sender, receiver) = mpsc::channel();
        self.saving = Some((Instant::now(), receiver));
        self.error.clear();
        std::thread::spawn(move || {
            let _ = sender.send(Self::save(&values).map_err(|error| error.to_string()));
        });
    }

    pub(super) fn saving(&self) -> bool {
        self.saving.is_some()
    }

    pub(super) fn poll_saved(&mut self) -> bool {
        let Some((_, receiver)) = &self.saving else {
            return false;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => Err(t(
                "\u{914d}\u{7f6e}\u{4fdd}\u{5b58}\u{7ebf}\u{7a0b}\u{4e2d}\u{65ad}",
                "Configuration save worker disconnected",
            )),
        };
        self.saving = None;
        match result {
            Ok(()) => true,
            Err(error) => {
                self.error = error;
                false
            }
        }
    }

    fn save(values: &[String; 3]) -> Result<()> {
        let base = values[0].trim().trim_end_matches('/');
        let model = values[1].trim();
        let key = values[2].trim();
        let host = base
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(""));
        anyhow::ensure!(
            (base.starts_with("https://") || base.starts_with("http://"))
                && host.is_some_and(|host| !host.is_empty() && !host.contains('@'))
                && !base.chars().any(char::is_whitespace)
                && !base.contains(['?', '#']),
            "{}",
            t(
                "\u{8bf7}\u{8f93}\u{5165}\u{6709}\u{6548}\u{7684} http(s) API \u{5730}\u{5740}\u{ff0c}\u{4e0d}\u{8981}\u{5728}\u{5730}\u{5740}\u{4e2d}\u{653e}\u{5bc6}\u{94a5}",
                "Enter an http(s) API base without credentials, query or fragment"
            )
        );
        anyhow::ensure!(
            !model.is_empty(),
            "{}",
            t("\u{6a21}\u{578b}\u{540d}\u{4e0d}\u{80fd}\u{4e3a}\u{7a7a}", "Model name is required")
        );
        anyhow::ensure!(
            !key.is_empty() || key_for(base).is_some(),
            "{}",
            t(
                "\u{8bf7}\u{8f93}\u{5165}\u{6b64}\u{5730}\u{5740}\u{7684} API Key",
                "API key is required for this endpoint"
            )
        );
        if !key.is_empty() {
            respire::keystore::save_classify_key(
                &format!("ds@{}", respire::keystore::host_of(base)),
                key,
            )?;
        }
        for (name, value) in [("recall_api_base", base), ("recall_model", model)] {
            retrieval_action(&["agent-config", "--set", &format!("{name}={value}")])
                .map_err(|e| anyhow!(e))?;
        }
        Ok(())
    }

    pub(super) fn draw(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title(t(
            "\u{9ad8}\u{8d28}\u{91cf}\u{53ec}\u{56de} API\u{ff08}OpenAI \u{517c}\u{5bb9}\u{ff09}",
            "High-quality recall API (OpenAI compatible)",
        ));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let regions = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner);
        for (index, label) in ["API Base URL", "Model", "API Key"].iter().enumerate() {
            let active = self.field == index;
            let block = Block::default()
                .borders(Borders::ALL)
                .title(*label)
                .border_style(if active {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                });
            frame.render_widget(
                Paragraph::new(self.values[index].line(
                    regions[index].width.saturating_sub(2) as usize,
                    active,
                    index == 2,
                ))
                .block(block),
                regions[index],
            );
        }
        let mut lines: Vec<Line<'static>> = vec![choice(
            self.field == 3,
            t("[ \u{4fdd}\u{5b58}\u{914d}\u{7f6e} ]", "[ Save configuration ]"),
        )];
        lines.push(line(t(
            "\u{5bc6}\u{94a5}\u{7559}\u{7a7a}\u{4fdd}\u{7559}\u{8be5}\u{5730}\u{5740}\u{5df2}\u{6709}\u{5bc6}\u{94a5}\u{ff1b}\u{65b0}\u{5bc6}\u{94a5}\u{5b58}\u{5165}\u{7cfb}\u{7edf}\u{51ed}\u{636e}\u{5e93}\u{3002}",
            "Leave key blank to retain this endpoint's key; new keys use the OS keyring.",
        )));
        lines.push(line(t(
            "\u{67e5}\u{8be2}\u{548c}\u{5019}\u{9009}\u{6807}\u{9898}\u{4f1a}\u{53d1}\u{9001}\u{5230}\u{6b64}\u{670d}\u{52a1}\u{3002}\u{4fdd}\u{5b58}\u{540e}\u{4ecd}\u{9700}\u{9009}\u{62e9}\u{9ad8}\u{8d28}\u{91cf}\u{6a21}\u{5f0f}\u{3002}",
            "Queries and candidate titles go to this service. Select High quality after saving.",
        )));
        lines.push(line(t(
            "Ctrl+A \u{5168}\u{9009}\u{ff0c}Ctrl+U \u{6e05}\u{7a7a}\u{ff0c}Ctrl+S \u{4fdd}\u{5b58}\u{ff1b}\u{6d4b}\u{8bd5}\u{5165}\u{53e3}\u{5728}\u{6a21}\u{578b}\u{9875}\u{3002}",
            "Ctrl+A selects all, Ctrl+U clears, Ctrl+S saves; test recall from the model page.",
        )));
        if !self.error.is_empty() {
            lines.push(super::fail_line(self.error.clone()));
        }
        if let Some((started, _)) = &self.saving {
            lines.push(line(format!(
                "{} {}s",
                t("\u{6b63}\u{5728}\u{4fdd}\u{5b58}\u{914d}\u{7f6e}", "Saving configuration"),
                started.elapsed().as_secs()
            )));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), regions[3]);
    }
}
