//! Draft editor; validation and persistence belong to the host application.
use super::{choice, line, retrieval_action, t, text_input::Input, Line, Value};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use respire_app::recall_fusion::{defaults, validate, MODES, NUMERIC};
use std::sync::mpsc::{self, Receiver, TryRecvError};

pub(super) struct Form {
    mode: usize,
    values: Vec<Input>,
    field: usize,
    receipt: Value,
    message: String,
    saving: Option<Receiver<Result<Value, String>>>,
}

impl Form {
    pub(super) fn new() -> Result<Self, String> {
        let envelope = retrieval_action(&["agent-config"])?;
        let receipt = envelope["summary"]["recall_fusion_runtime"].clone();
        if !receipt["effective"].is_object() {
            return Err(t(
                "请先升级支持五轴融合设置的 CLI",
                "Upgrade the CLI to support recall fusion settings",
            ));
        }
        let mut draft = defaults();
        if let Some(configured) = receipt["configured"].as_object() {
            draft.extend(configured.clone());
        }
        let mode = MODES
            .iter()
            .position(|mode| Some(*mode) == draft["fusion"].as_str())
            .unwrap_or(0);
        let values = NUMERIC
            .iter()
            .map(|(key, _)| Input::new(draft[*key].to_string()))
            .collect();
        Ok(Self {
            mode,
            values,
            field: 0,
            receipt,
            message: String::new(),
            saving: None,
        })
    }

    pub(super) fn paste(&mut self, text: &str) {
        if self.saving.is_none() && (1..=NUMERIC.len()).contains(&self.field) {
            self.values[self.field - 1].paste(text);
        }
    }

    pub(super) fn key(&mut self, key: KeyEvent) -> bool {
        if self.saving.is_some() {
            return false;
        }
        let save = NUMERIC.len() + 1;
        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Char('s' | 'S') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.save()
            }
            KeyCode::Tab | KeyCode::Down => self.field = (self.field + 1) % (save + 3),
            KeyCode::BackTab | KeyCode::Up => self.field = (self.field + save + 2) % (save + 3),
            KeyCode::Left if self.field == 0 => {
                self.mode = (self.mode + MODES.len() - 1) % MODES.len()
            }
            KeyCode::Right | KeyCode::Enter if self.field == 0 => {
                self.mode = (self.mode + 1) % MODES.len()
            }
            KeyCode::Enter if self.field == save => self.save(),
            KeyCode::Enter if self.field == save + 1 => {
                self.mode = 0;
                self.values = NUMERIC
                    .iter()
                    .map(|(_, value)| Input::new(value.to_string()))
                    .collect();
                self.message = t(
                    "已恢复默认草稿；保存后生效",
                    "Default draft restored; save to apply",
                );
            }
            KeyCode::Enter if self.field == save + 2 => return true,
            KeyCode::Enter => self.field += 1,
            _ if (1..=NUMERIC.len()).contains(&self.field) => self.values[self.field - 1].key(key),
            _ => {}
        }
        false
    }

    fn save(&mut self) {
        let result = (|| -> anyhow::Result<Value> {
            let mut values = serde_json::Map::new();
            values.insert("fusion".into(), serde_json::json!(MODES[self.mode]));
            for (index, (key, _)) in NUMERIC.iter().enumerate() {
                let value: f64 = self.values[index]
                    .text
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{key}: invalid number"))?;
                anyhow::ensure!(value.is_finite(), "{key}: invalid number");
                values.insert((*key).into(), serde_json::json!(value));
            }
            let value = Value::Object(values);
            validate(&value)?;
            Ok(value)
        })();
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                self.message = error.to_string();
                return;
            }
        };
        let (sender, receiver) = mpsc::channel();
        self.saving = Some(receiver);
        self.message = t("正在保存设置", "Saving settings");
        std::thread::spawn(move || {
            let result = (|| {
                retrieval_action(&[
                    "agent-config",
                    "--set",
                    &format!("recall_fusion={value}"),
                ])?;
                let read_back = retrieval_action(&["agent-config"])?;
                let receipt = &read_back["summary"]["recall_fusion_runtime"];
                if receipt["configured"] != value {
                    return Err("Recall fusion read-back differs; refresh settings".to_owned());
                }
                Ok(receipt.clone())
            })();
            let _ = sender.send(result);
        });
    }

    pub(super) fn poll(&mut self) {
        let Some(receiver) = &self.saving else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                Err("Configuration save worker disconnected; read settings before retrying".into())
            }
        };
        self.saving = None;
        match result {
            Ok(receipt) => {
                self.receipt = receipt;
                self.message = t(
                    "已保存并回读；下次召回生效",
                    "Saved and read back; applies to the next recall",
                );
            }
            Err(error) => self.message = error,
        }
    }

    pub(super) fn lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![
            line(t("五轴注意力融合", "Five-axis attention fusion")),
            line(self.message.clone()),
            line(format!(
                "{}: {}",
                t("当前生效模式", "Effective mode"),
                self.receipt["effective"]["fusion"]
            )),
            line(format!(
                "{}: {}",
                t("环境覆盖字段", "Environment overrides"),
                self.receipt["overrides"]
            )),
            choice(
                self.field == 0,
                format!("{}: {}  ← →", t("草稿模式", "Draft mode"), MODES[self.mode]),
            ),
        ];
        let labels = [
            t("先验总份额", "Prior share"),
            t("词法份额", "Lexical share"),
            t("注意力温度", "Temperature"),
            t("普通查询时间门", "Recency gate"),
            t("时间查询时间门", "Temporal recency gate"),
            t("热度门", "Heat gate"),
            t("树位置门", "Tree gate"),
            t("时间查询追加份额", "Temporal extra share"),
        ];
        for (index, (key, _)) in NUMERIC.iter().enumerate() {
            let active = self.field == index + 1;
            let mut row = choice(active, format!("{}: ", labels[index]));
            row.spans
                .extend(self.values[index].line(22, active, false).spans);
            row.spans.push(
                format!(
                    "  {}: {}",
                    t("生效", "Effective"),
                    self.receipt["effective"][*key]
                )
                .into(),
            );
            lines.push(row);
        }
        lines.push(choice(self.field == 9, t("保存", "Save")));
        lines.push(choice(
            self.field == 10,
            t("恢复默认草稿", "Restore default draft"),
        ));
        lines.push(choice(
            self.field == 11,
            t("返回（放弃未保存修改）", "Back (discard unsaved changes)"),
        ));
        lines.push(line(t(
            "legacy 保持原算法；auto 按候选库大小选择。alpha + beta ≤ 1。",
            "legacy preserves ranking; auto selects by pool size. alpha + beta <= 1.",
        )));
        lines.push(line(t("Tab 切换字段；Ctrl+A 全选；Ctrl+S 保存；Esc 返回。环境变量优先。", "Tab changes field; Ctrl+A selects all; Ctrl+S saves; Esc returns. Environment overrides win.")));
        lines
    }
}
