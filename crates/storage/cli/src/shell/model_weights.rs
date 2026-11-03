//! Draft-only model picker. All writes/downloads go through existing commands.
use super::{choice, line, t, KeyCode, Line, Value};
use respire::memory::onnx::MODEL_VARIANTS;

const ENGINES: &[&str] = &["cpu", "gpu", "npu"];
pub(super) enum Action { Save, Install, Back }
pub(super) struct Form { pub cursor: usize, engine: usize, variant: usize }
impl Form {
    pub(super) fn new(settings: &Value) -> Self {
        Self { cursor: 0,
            engine: ENGINES.iter().position(|e| Some(*e) == settings["engine"].as_str()).unwrap_or(0),
            variant: MODEL_VARIANTS.iter().position(|v| Some(v.name) == settings["model"].as_str()).unwrap_or(0) }
    }
    pub(super) fn selection(&self) -> (&'static str, &'static str) {
        (ENGINES[self.engine], MODEL_VARIANTS[self.variant].name)
    }
    pub(super) fn key(&mut self, key: KeyCode) -> Option<Action> {
        let count = MODEL_VARIANTS.len() + 4;
        match key {
            KeyCode::Esc | KeyCode::Char('0') => return Some(Action::Back),
            KeyCode::Up => self.cursor = (self.cursor + count - 1) % count,
            KeyCode::Down => self.cursor = (self.cursor + 1) % count,
            KeyCode::Left if self.cursor == 0 => self.engine = (self.engine + ENGINES.len() - 1) % ENGINES.len(),
            KeyCode::Right if self.cursor == 0 => self.engine = (self.engine + 1) % ENGINES.len(),
            KeyCode::Enter if self.cursor == 0 => self.engine = (self.engine + 1) % ENGINES.len(),
            KeyCode::Enter if self.cursor <= MODEL_VARIANTS.len() => self.variant = self.cursor - 1,
            KeyCode::Enter if self.cursor == MODEL_VARIANTS.len() + 1 => return Some(Action::Save),
            KeyCode::Enter if self.cursor == MODEL_VARIANTS.len() + 2 => return Some(Action::Install),
            KeyCode::Enter => return Some(Action::Back),
            _ => {}
        }
        None
    }
    pub(super) fn present(settings: &Value, variant: &str) -> bool {
        settings["variants"].as_array().is_some_and(|rows| rows.iter()
            .any(|row| row["name"] == variant && row["state"] == "present"))
    }
    pub(super) fn lines(&self, settings: &Value) -> Vec<Line<'static>> {
        let (engine, _) = self.selection();
        let supported = super::model_engines().contains(&engine);
        let mut rows = vec![line(t("\u{5f15}\u{64ce}\u{4e0e}\u{6a21}\u{578b}\u{6743}\u{91cd}", "Engine and model weights")),
            line(format!("{}: {} / {}", t("\u{5df2}\u{4fdd}\u{5b58}", "Saved"),
                settings["engine"].as_str().unwrap_or("unknown"), settings["model"].as_str().unwrap_or("unknown"))),
            choice(self.cursor == 0, format!("{}: {engine}  {}{}", t("\u{8349}\u{7a3f}\u{5f15}\u{64ce}", "Draft engine"),
                t("\u{2190} \u{2192} \u{9009}\u{62e9}", "\u{2190} \u{2192} choose"), if supported { String::new() }
                else { t("\u{ff08}\u{6b64}\u{7cfb}\u{7edf}\u{4e0d}\u{652f}\u{6301}\u{ff09}", " (unsupported on this OS)") }))];
        for (index, variant) in MODEL_VARIANTS.iter().enumerate() {
            let state = if Self::present(settings, variant.name) {
                t("\u{5df2}\u{4e0b}\u{8f7d}\u{ff1b}\u{52a0}\u{8f7d}\u{524d}\u{6821}\u{9a8c}", "downloaded; validated before loading")
            } else { t("\u{9700}\u{4e0b}\u{8f7d}\u{6216}\u{91cd}\u{65b0}\u{4e0b}\u{8f7d}", "download or redownload required") };
            rows.push(choice(self.cursor == index + 1, format!("{} {:<10} {:>4.0} MiB  {state}",
                if index == self.variant { "\u{25cf}" } else { "\u{25cb}" }, variant.name, variant.size as f64 / 1048576.0)));
        }
        rows.push(choice(self.cursor == MODEL_VARIANTS.len() + 1, t("\u{6821}\u{9a8c}\u{5e76}\u{52a0}\u{8f7d}\u{6240}\u{9009}\u{6743}\u{91cd}", "Validate and load selected weights")));
        rows.push(choice(self.cursor == MODEL_VARIANTS.len() + 2, t("\u{9884}\u{4e0b}\u{8f7d}\u{6240}\u{9009}\u{6743}\u{91cd}\u{ff08}\u{4e0d}\u{5207}\u{6362}\u{ff09}\u{2026}", "Download selected weights (keep current model)\u{2026}")));
        rows.push(choice(self.cursor == MODEL_VARIANTS.len() + 3, t("\u{8fd4}\u{56de}\u{ff08}\u{653e}\u{5f03}\u{8349}\u{7a3f}\u{ff09}", "Back (discard draft)")));
        rows.push(line(t("\u{4e0a}\u{4e0b}\u{79fb}\u{52a8}\u{ff0c}\u{56de}\u{8f66}\u{9009}\u{6743}\u{91cd}\u{ff1b}\u{53ea}\u{9009}\u{4e0d}\u{4fdd}\u{5b58}\u{4e0d}\u{4f1a}\u{6539}\u{53d8}\u{914d}\u{7f6e}\u{3002}\u{5207}\u{5f15}\u{64ce}\u{4fdd}\u{7559}\u{6240}\u{9009}\u{6743}\u{91cd}\u{3002}",
            "Up/down moves; Enter picks weights. Drafts do not change settings. Engine changes keep the selected weights.")));
        rows.push(line(t("GPU/NPU \u{9700}\u{8981}\u{5b9e}\u{9645}\u{786c}\u{4ef6}\u{53ca} provider\u{ff1b}\u{90e8}\u{5206}\u{53d8}\u{4f53}\u{53ef}\u{80fd}\u{4e0d}\u{652f}\u{6301}\u{3002}\u{52a0}\u{8f7d}\u{65f6}\u{4f1a}\u{6821}\u{9a8c}\u{5e76}\u{8bd5}\u{63a8}\u{7406}\u{ff0c}\u{6210}\u{529f}\u{540e}\u{624d}\u{4fdd}\u{5b58}\u{3002}",
            "GPU/NPU need hardware/providers; some variants may fail. Load validates files and runs trial inference before saving.")));
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drafts_preserve_weights_on_engine_changes_and_cancel_without_an_action() {
        let settings = serde_json::json!({"engine":"cpu","model":"fp16"});
        let mut form = Form::new(&settings);
        form.key(KeyCode::Right);
        assert_eq!(form.selection(), ("gpu", "fp16"));
        assert!(matches!(form.key(KeyCode::Esc), Some(Action::Back)));
        assert_eq!(settings["engine"], "cpu");
        assert_eq!(Form::new(&settings).selection(), ("cpu", "fp16"));
    }
    #[test]
    fn all_variants_are_selectable_without_saving_or_downloading() {
        let mut form = Form::new(&serde_json::json!({"engine":"npu","model":"quantized"}));
        for (index, variant) in MODEL_VARIANTS.iter().enumerate() {
            form.cursor = index + 1;
            assert!(form.key(KeyCode::Enter).is_none());
            assert_eq!(form.selection(), ("npu", variant.name));
        }
        assert!(!Form::present(&serde_json::json!({"variants":[{"name":"q4f16","state":"invalid_size"}]}), "q4f16"));
    }
}
