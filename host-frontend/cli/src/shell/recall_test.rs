//! One-request recall checks; never change the saved recall mode.
use super::text_input::Input;
use super::{fail_line, line, ok_line, retrieval_action, t, warn_line};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use serde_json::Value;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

pub(super) struct Form {
    mode: &'static str,
    query: Input,
    pending: Option<(Instant, Receiver<Result<Value, String>>)>,
    result: Vec<Line<'static>>,
    scroll: u16,
    cancel: Arc<AtomicBool>,
}

impl Form {
    pub fn new(mode: &'static str) -> Self {
        Self {
            mode,
            query: Input::new(String::new()),
            pending: None,
            result: Vec::new(),
            scroll: 0,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn paste(&mut self, text: &str) {
        if self.pending.is_none() {
            self.query.paste(text);
        }
    }

    pub fn key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::PageDown => {
                self.scroll = self
                    .scroll
                    .saturating_add(5)
                    .min(self.result.len().saturating_sub(1) as u16);
                return;
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(5);
                return;
            }
            _ => {}
        }
        if self.pending.is_some() {
            return;
        }
        if key.code != KeyCode::Enter {
            self.query.key(key);
            return;
        }
        let query = self.query.text.trim().to_owned();
        if query.is_empty() {
            self.result = vec![fail_line(t(
                "\u{8bf7}\u{8f93}\u{5165}\u{6d4b}\u{8bd5}\u{67e5}\u{8be2}",
                "Enter a query to test",
            ))];
            return;
        }
        let mode = self.mode;
        let cancel = Arc::clone(&self.cancel);
        let (sender, receiver) = mpsc::channel();
        self.pending = Some((Instant::now(), receiver));
        self.result.clear();
        self.scroll = 0;
        std::thread::spawn(move || {
            let result = if mode == "benchmark" {
                run_benchmark(&query, &cancel)
            } else {
                retrieval_action(&[
                    "recall", &query, "--mode", mode, "--titles", "--limit", "20",
                ])
            };
            let _ = sender.send(result);
        });
    }

    pub fn poll(&mut self) {
        let Some((started, receiver)) = &self.pending else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(t(
                "\u{6d4b}\u{8bd5}\u{7ebf}\u{7a0b}\u{4e2d}\u{65ad}",
                "Test worker disconnected",
            )),
        };
        let elapsed = started.elapsed().as_secs_f32();
        self.pending = None;
        self.result.push(line(format!(
            "{}: {elapsed:.2}s",
            t("\u{8017}\u{65f6}", "Elapsed")
        )));
        match result {
            Err(error) => self.result.push(fail_line(error)),
            Ok(value) => {
                if self.mode == "benchmark" {
                    if let Some(rows) = value["rows"].as_array() {
                        self.result.extend(
                            rows.iter()
                                .filter_map(Value::as_str)
                                .map(|row| line(row.to_owned())),
                        );
                    }
                    return;
                }
                let count = value["summary"]["count"].as_u64().unwrap_or(0);
                if let Some(reason) = value["summary"]["selection_fallback"].as_str() {
                    self.result.push(warn_line(format!(
                        "{}: {reason}",
                        t(
                            "\u{9ad8}\u{8d28}\u{91cf}\u{5931}\u{8d25}\u{ff0c}\u{4ee5}\u{4e0b}\u{4e3a}\u{5feb}\u{901f}\u{7ed3}\u{679c}",
                            "Quality failed; showing local results"
                        )
                    )));
                } else if count == 0 {
                    self.result.push(warn_line(if self.mode == "quality" {
                        t(
                            "\u{672a}\u{53ec}\u{56de}\u{7ed3}\u{679c}\u{ff1b}\u{672c}\u{6b21}\u{672a}\u{9a8c}\u{8bc1}\u{9ad8}\u{8d28}\u{91cf} API",
                            "No results; quality API was not exercised",
                        )
                    } else {
                        t(
                            "\u{672a}\u{53ec}\u{56de}\u{7ed3}\u{679c}\u{ff0c}\u{8bf7}\u{6362}\u{4e00}\u{4e2a}\u{67e5}\u{8be2}",
                            "No results; try a different query",
                        )
                    }));
                } else {
                    self.result.push(ok_line(format!(
                        "{} \u{b7} {count} {}",
                        t("\u{6d4b}\u{8bd5}\u{6210}\u{529f}", "Test passed"),
                        t("\u{6761}\u{7ed3}\u{679c}", "results")
                    )));
                }
                if let Some(items) = value["items"].as_array() {
                    self.result.extend(
                        items
                            .iter()
                            .filter_map(|item| item["value"].as_str())
                            .map(|text| line(text.to_owned())),
                    );
                }
                if let Some(related) = value.get("related") {
                    match serde_json::from_value::<Vec<respire_protocol::RelatedMemory>>(
                        related.clone(),
                    ) {
                        Ok(related) => self.result.extend(
                            related
                                .iter()
                                .map(|entry| line(crate::output::related_value(entry))),
                        ),
                        Err(error) => self.result.push(fail_line(error.to_string())),
                    }
                }
            }
        }
    }

    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        let title = if self.mode == "benchmark" {
            t(
                "\u{63a8}\u{7406} / Recall Benchmark",
                "Inference / Recall Benchmark",
            )
        } else if self.mode == "quality" {
            t(
                "\u{6d4b}\u{8bd5}\u{9ad8}\u{8d28}\u{91cf}\u{53ec}\u{56de}",
                "Test high-quality recall",
            )
        } else {
            t(
                "\u{6d4b}\u{8bd5}\u{5feb}\u{901f}\u{53ec}\u{56de}",
                "Test fast recall",
            )
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let regions = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner);
        frame.render_widget(
            Paragraph::new(self.query.line(
                regions[0].width.saturating_sub(2) as usize,
                true,
                false,
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(t("\u{67e5}\u{8be2}", "Query")),
            ),
            regions[0],
        );
        let note = if self.mode == "benchmark" {
            t("\u{56de}\u{8f66}\u{ff1a}\u{9996}\u{8f6e} + 8 \u{8f6e}\u{63a8}\u{7406}\u{9a8c}\u{8bc1}\u{53ca}\u{5feb}\u{901f} Recall\u{3002}\u{5305}\u{542b} RPC \u{7b49}\u{5f85}\u{ff1b}\u{53ea}\u{8bbf}\u{95ee}\u{672c}\u{5730} runtime\u{3002}", "Enter: first call + 8 inference checks and fast recalls. RPC waits included; local runtime only.")
        } else if self.mode == "quality" {
            t("\u{56de}\u{8f66}\u{6d4b}\u{8bd5}\u{ff1a}\u{67e5}\u{8be2}\u{4e0e}\u{5019}\u{9009}\u{6807}\u{9898}\u{4f1a}\u{53d1}\u{5f80}\u{5df2}\u{914d}\u{7f6e} API\u{ff1b}\u{4e0d}\u{6539}\u{53d8}\u{9ed8}\u{8ba4}\u{6a21}\u{5f0f}\u{3002}", "Enter tests: query and candidate titles go to the configured API; saved mode is unchanged.")
        } else {
            t(
                "\u{56de}\u{8f66}\u{6d4b}\u{8bd5}\u{ff1a}\u{4ec5}\u{4f7f}\u{7528}\u{672c}\u{5730}\u{53ec}\u{56de}\u{ff1b}\u{4e0d}\u{6539}\u{53d8}\u{9ed8}\u{8ba4}\u{6a21}\u{5f0f}\u{3002}",
                "Enter tests local recall; saved mode is unchanged.",
            )
        };
        frame.render_widget(Paragraph::new(note).wrap(Wrap { trim: false }), regions[1]);
        let lines = if let Some((started, _)) = &self.pending {
            vec![
                line(format!(
                    "{} {}s",
                    t("\u{6b63}\u{5728}\u{6d4b}\u{8bd5}", "Testing"),
                    started.elapsed().as_secs()
                )),
                line(t(
                    "Esc \u{8fd4}\u{56de}\u{ff1b}\u{5df2}\u{53d1}\u{51fa}\u{7684}\u{8bf7}\u{6c42}\u{5b8c}\u{6210}\u{540e}\u{505c}\u{6b62}\u{540e}\u{7eed}\u{8f6e}\u{6b21}\u{3002}",
                    "Esc returns; the submitted request finishes, then further rounds stop.",
                )),
            ]
        } else {
            self.result.clone()
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            regions[2],
        );
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

// The SDK's reported probe time and RPC wall time have distinct scopes.
// Repeated fast Recall measures the current library without calling a selector API.
fn run_benchmark(query: &str, cancel: &AtomicBool) -> Result<Value, String> {
    const ROUNDS: usize = 8;
    let mut inference = Vec::new();
    let mut probe_wall = Vec::new();
    let mut recall_wall = Vec::new();
    let mut selected = String::new();
    let mut indexed_min = u64::MAX;
    let mut indexed_max = 0;
    let mut pending_max = 0;
    let mut first_probe = 0.0;
    let mut first_recall = 0.0;
    for round in 0..=ROUNDS {
        if cancel.load(Ordering::Acquire) {
            return Err(t("Benchmark \u{5df2}\u{505c}\u{6b62}", "Benchmark stopped"));
        }
        let probe_text = format!("{query} [benchmark {round}]");
        let started = Instant::now();
        let probe = retrieval_action(&["model", "probe", "--text", &probe_text])
            .map_err(|error| format!("Benchmark probe {round}: {error}"))?;
        let wall = started.elapsed().as_secs_f64() * 1000.0;
        let summary = &probe["summary"];
        let elapsed = summary["elapsed_ms"]
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0)
            .ok_or_else(|| "Benchmark: missing probe elapsed_ms".to_owned())?;
        let engine = summary["selected"]
            .as_str()
            .ok_or_else(|| "Benchmark: missing selected engine".to_owned())?;
        if !selected.is_empty() && selected != engine {
            return Err(t("\u{63a8}\u{7406}\u{5f15}\u{64ce}\u{5728}\u{6d4b}\u{8bd5}\u{671f}\u{95f4}\u{53d1}\u{751f}\u{53d8}\u{5316}\u{ff0c}\u{8bf7}\u{91cd}\u{65b0}\u{6d4b}\u{8bd5}", "Inference engine changed during the benchmark; run again"));
        }
        selected = engine.to_owned();
        if round == 0 {
            first_probe = wall;
        } else {
            inference.push(elapsed);
            probe_wall.push(wall);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(t("Benchmark \u{5df2}\u{505c}\u{6b62}", "Benchmark stopped"));
        }
        let started = Instant::now();
        let recalled = retrieval_action(&[
            "recall", query, "--mode", "fast", "--titles", "--limit", "20",
        ])
        .map_err(|error| format!("Benchmark recall {round}: {error}"))?;
        let wall = started.elapsed().as_secs_f64() * 1000.0;
        let summary = &recalled["summary"];
        let indexed = summary["indexed_candidates"].as_u64().ok_or_else(|| {
            "Benchmark: runtime does not report indexed_candidates; update the runtime".to_owned()
        })?;
        let pending = summary["index_pending"].as_u64().ok_or_else(|| {
            "Benchmark: runtime does not report index_pending; update the runtime".to_owned()
        })?;
        indexed_min = indexed_min.min(indexed);
        indexed_max = indexed_max.max(indexed);
        pending_max = pending_max.max(pending);
        if round == 0 {
            first_recall = wall;
        } else {
            recall_wall.push(wall);
        }
    }
    let mut rows = vec![
        format!("{}: {selected}; {ROUNDS} {}", t("\u{5b9e}\u{9645}\u{5f15}\u{64ce}", "Selected engine"), t("\u{91cd}\u{590d}\u{8f6e}\u{6b21}", "repeated rounds")),
        format!("{}: {first_probe:.1} ms / {first_recall:.1} ms", t("\u{9996}\u{8f6e}\u{63a8}\u{7406}\u{8bf7}\u{6c42} / Recall", "First probe request / Recall")),
        benchmark_row(&t("\u{63a8}\u{7406}\u{62a5}\u{544a}\u{8017}\u{65f6}", "Reported probe time"), &inference)?,
        benchmark_row(&t("\u{63a8}\u{7406}\u{8bf7}\u{6c42}\u{5b8c}\u{6574}\u{8017}\u{65f6}", "Probe RPC wall time"), &probe_wall)?,
        benchmark_row(&t("\u{5feb}\u{901f} Recall \u{5b8c}\u{6574}\u{8017}\u{65f6}", "Fast Recall RPC wall time"), &recall_wall)?,
        format!("{}: {indexed_min}\u{2013}{indexed_max}; {}: {pending_max}", t("\u{6709}\u{6548}\u{5019}\u{9009}\u{6570}", "Indexed candidates"), t("\u{6700}\u{591a}\u{5f85}\u{7d22}\u{5f15}\u{6570}", "Maximum pending index")),
        t("\u{9996}\u{8f6e}\u{4e0d}\u{7b49}\u{4e8e}\u{51b7}\u{542f}\u{52a8}\u{ff1b}\u{91cd}\u{590d} Recall \u{53ef}\u{590d}\u{7528}\u{67e5}\u{8be2}\u{7f13}\u{5b58}\u{3002}", "First call is not a cold start; repeated Recall may reuse query caches."),
        t("SDK \u{4e0a}\u{62a5}\u{8017}\u{65f6}\u{4e0e}\u{5b8c}\u{6574}\u{8bf7}\u{6c42}\u{4e0d}\u{540c}\u{ff1b}\u{5b8c}\u{6574} Recall \u{542b}\u{6392}\u{961f}\u{3001}RPC \u{548c}\u{68c0}\u{7d22}\u{3002}", "SDK-reported times differ from full requests; full Recall includes queues, RPC and retrieval."),
        t("Recall \u{4f1a}\u{66f4}\u{65b0}\u{5e38}\u{89c4}\u{67e5}\u{8be2}\u{65e5}\u{5fd7}\u{4e0e}\u{547d}\u{4e2d}\u{7edf}\u{8ba1}\u{ff1b}\u{4e0d}\u{4fee}\u{6539}\u{8bb0}\u{5fc6}\u{6b63}\u{6587}\u{6216}\u{9ed8}\u{8ba4}\u{6a21}\u{5f0f}\u{3002}", "Recall updates normal query logs and hit statistics; content and saved mode are unchanged."),
    ];
    if indexed_min == 0 {
        rows.push(t("\u{6ca1}\u{6709}\u{6709}\u{6548}\u{5019}\u{9009}\u{ff1a}\u{7ed3}\u{679c}\u{4ec5}\u{4ee3}\u{8868}\u{7a7a}\u{5019}\u{9009}\u{67e5}\u{8be2}\u{ff0c}\u{4e0d}\u{4ee3}\u{8868}\u{5b8c}\u{6574}\u{8bb0}\u{5fc6}\u{5e93}\u{901f}\u{5ea6}\u{3002}", "No indexed candidates: timings cover empty-candidate queries, not a populated library."));
    }
    if indexed_min != indexed_max || pending_max > 0 {
        rows.push(t("\u{7d22}\u{5f15}\u{4ecd}\u{6709}\u{53d8}\u{5316}\u{ff1a}\u{672c}\u{6b21}\u{4e3a}\u{5f53}\u{524d}\u{8d1f}\u{8f7d}\u{7ed3}\u{679c}\u{ff0c}\u{4e0d}\u{9002}\u{5408}\u{76f4}\u{63a5}\u{6bd4}\u{8f83}\u{5f15}\u{64ce}\u{3002}", "Index is changing: these timings reflect current load; avoid direct engine comparisons."));
    }
    Ok(serde_json::json!({"rows": rows}))
}

fn benchmark_row(label: &str, samples: &[f64]) -> Result<String, String> {
    if samples.is_empty() {
        return Err("Benchmark: no samples".to_owned());
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let p50 = sorted[(sorted.len() * 50).div_ceil(100) - 1];
    let p95 = sorted[(sorted.len() * 95).div_ceil(100) - 1];
    let rate = if mean > 0.0 {
        format!("{:.2}", 1000.0 / mean)
    } else {
        "n/a".to_owned()
    };
    Ok(format!(
        "{label}: mean {mean:.1} ms  P50 {p50:.1} ms  P95 {p95:.1} ms  {rate}/s"
    ))
}
