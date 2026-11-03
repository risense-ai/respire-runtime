//! Single-line editor with a visible cursor and horizontal scrolling.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;

pub(super) struct Input {
    pub text: String,
    cursor: usize,
    selected: bool,
}

impl Input {
    pub fn new(text: String) -> Self {
        Self {
            cursor: text.chars().count(),
            text,
            selected: false,
        }
    }

    pub fn paste(&mut self, text: &str) {
        self.replace_selection();
        let clean: String = text.chars().filter(|ch| !ch.is_control()).collect();
        self.text.insert_str(self.byte(self.cursor), &clean);
        self.cursor += clean.chars().count();
    }

    fn byte(&self, index: usize) -> usize {
        self.text
            .char_indices()
            .nth(index)
            .map(|(i, _)| i)
            .unwrap_or(self.text.len())
    }

    fn replace_selection(&mut self) {
        if self.selected {
            self.text.clear();
            self.cursor = 0;
            self.selected = false;
        }
    }

    pub fn key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('a' | 'A') => self.selected = true,
                KeyCode::Char('u' | 'U') => {
                    self.selected = true;
                    self.replace_selection();
                }
                _ => {}
            }
            return;
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            return;
        }
        let len = self.text.chars().count();
        match key.code {
            KeyCode::Char(ch) if !ch.is_control() => self.paste(&ch.to_string()),
            KeyCode::Backspace | KeyCode::Delete if self.selected => self.replace_selection(),
            KeyCode::Backspace if self.cursor > 0 => {
                self.text
                    .replace_range(self.byte(self.cursor - 1)..self.byte(self.cursor), "");
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < len => {
                self.text.remove(self.byte(self.cursor));
            }
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                self.selected = false;
            }
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(len);
                self.selected = false;
            }
            KeyCode::Home => {
                self.cursor = 0;
                self.selected = false;
            }
            KeyCode::End => {
                self.cursor = len;
                self.selected = false;
            }
            _ => {}
        }
    }

    pub fn line(&self, width: usize, active: bool, masked: bool) -> Line<'static> {
        let chars: Vec<char> = self
            .text
            .chars()
            .map(|ch| if masked { '*' } else { ch })
            .collect();
        let budget = width.saturating_sub(2).max(1);
        let char_width = |ch: char| Span::raw(ch.to_string()).width();
        let mut start = if active { self.cursor } else { 0 };
        let mut used = chars
            .get(self.cursor)
            .map(|ch| char_width(*ch))
            .unwrap_or(1);
        while start > 0 && used + char_width(chars[start - 1]) <= budget {
            start -= 1;
            used += char_width(chars[start]);
        }
        let mut spans = Vec::new();
        if start > 0 {
            spans.push(Span::raw("\u{2039}"));
        }
        used = 0;
        for index in start..=chars.len() {
            let ch = chars.get(index).copied().unwrap_or(' ');
            let size = char_width(ch);
            if used + size > budget {
                spans.push(Span::raw("\u{203a}"));
                break;
            }
            let selected = active && (self.selected || index == self.cursor);
            let style = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            spans.push(Span::styled(ch.to_string(), style));
            used += size;
        }
        Line::from(spans)
    }
}
