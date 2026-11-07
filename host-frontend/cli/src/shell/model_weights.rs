//! Draft-only model picker. All writes/downloads go through existing commands.
use super::{choice, line, t, KeyCode, Line, Value};
use anyhow::{Context, Result};

const ENGINES: &[&str] = &["cpu", "gpu", "npu"];
#[derive(serde::Deserialize)]
struct Variant {
    name: String,
    size: u64,
}

pub(super) enum Action {
    Save,
    Install,
    Back,
}
pub(super) struct Form {
    pub cursor: usize,
    engine: usize,
    variant: usize,
    variants: Vec<Variant>,
}
impl Form {
    pub(super) fn new(settings: &Value) -> Result<Self> {
        let variants: Vec<Variant> = serde_json::from_value(settings["variants"].clone())
            .context("Runtime model engine returned invalid variants")?;
        anyhow::ensure!(!variants.is_empty(), "Runtime model engine returned no variants");
        anyhow::ensure!(
            variants.iter().all(|variant| !variant.name.trim().is_empty() && variant.size > 0),
            "Runtime model engine returned an invalid variant name or size"
        );
        let variant = variants
            .iter()
            .position(|variant| Some(variant.name.as_str()) == settings["model"].as_str())
            .context("Runtime selected model is absent from its variant inventory")?;
        Ok(Self {
            cursor: 0,
            engine: ENGINES
                .iter()
                .position(|e| Some(*e) == settings["engine"].as_str())
                .unwrap_or(0),
            variant,
            variants,
        })
    }
    pub(super) fn selection(&self) -> (&'static str, &str) {
        (ENGINES[self.engine], &self.variants[self.variant].name)
    }
    pub(super) fn selected_size(&self) -> u64 {
        self.variants[self.variant].size
    }
    pub(super) fn key(&mut self, key: KeyCode) -> Option<Action> {
        let count = self.variants.len() + 4;
        match key {
            KeyCode::Esc | KeyCode::Char('0') => return Some(Action::Back),
            KeyCode::Up => self.cursor = (self.cursor + count - 1) % count,
            KeyCode::Down => self.cursor = (self.cursor + 1) % count,
            KeyCode::Left if self.cursor == 0 => {
                self.engine = (self.engine + ENGINES.len() - 1) % ENGINES.len()
            }
            KeyCode::Right if self.cursor == 0 => self.engine = (self.engine + 1) % ENGINES.len(),
            KeyCode::Enter if self.cursor == 0 => self.engine = (self.engine + 1) % ENGINES.len(),
            KeyCode::Enter if self.cursor <= self.variants.len() => self.variant = self.cursor - 1,
            KeyCode::Enter if self.cursor == self.variants.len() + 1 => return Some(Action::Save),
            KeyCode::Enter if self.cursor == self.variants.len() + 2 => {
                return Some(Action::Install)
            }
            KeyCode::Enter => return Some(Action::Back),
            _ => {}
        }
        None
    }
    pub(super) fn present(settings: &Value, variant: &str) -> bool {
        settings["variants"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row["name"] == variant && row["state"] == "present")
        })
    }
    pub(super) fn lines(&self, settings: &Value) -> Vec<Line<'static>> {
        let (engine, _) = self.selection();
        let supported = super::model_engines().contains(&engine);
        let mut rows = vec![
            line(t(
                "\u{5f15}\u{64ce}\u{4e0e}\u{6a21}\u{578b}\u{6743}\u{91cd}",
                "Engine and model weights",
            )),
            line(format!(
                "{}: {} / {}",
                t("\u{5df2}\u{4fdd}\u{5b58}", "Saved"),
                settings["engine"].as_str().unwrap_or("unknown"),
                settings["model"].as_str().unwrap_or("unknown")
            )),
            choice(
                self.cursor == 0,
                format!(
                    "{}: {engine}  {}{}",
                    t("\u{8349}\u{7a3f}\u{5f15}\u{64ce}", "Draft engine"),
                    t(
                        "\u{2190} \u{2192} \u{9009}\u{62e9}",
                        "\u{2190} \u{2192} choose"
                    ),
                    if supported {
                        String::new()
                    } else {
                        t(
                            "\u{ff08}\u{6b64}\u{7cfb}\u{7edf}\u{4e0d}\u{652f}\u{6301}\u{ff09}",
                            " (unsupported on this OS)",
                        )
                    }
                ),
            ),
        ];
        for (index, variant) in self.variants.iter().enumerate() {
            let state = if Self::present(settings, &variant.name) {
                t(
                    "\u{5df2}\u{4e0b}\u{8f7d}\u{ff1b}\u{52a0}\u{8f7d}\u{524d}\u{6821}\u{9a8c}",
                    "downloaded; validated before loading",
                )
            } else {
                t(
                    "\u{9700}\u{4e0b}\u{8f7d}\u{6216}\u{91cd}\u{65b0}\u{4e0b}\u{8f7d}",
                    "download or redownload required",
                )
            };
            rows.push(choice(
                self.cursor == index + 1,
                format!(
                    "{} {:<10} {:>4.0} MiB  {state}",
                    if index == self.variant {
                        "\u{25cf}"
                    } else {
                        "\u{25cb}"
                    },
                    variant.name,
                    variant.size as f64 / 1048576.0
                ),
            ));
        }
        rows.push(choice(
            self.cursor == self.variants.len() + 1,
            t(
                "\u{6821}\u{9a8c}\u{5e76}\u{52a0}\u{8f7d}\u{6240}\u{9009}\u{6743}\u{91cd}",
                "Validate and load selected weights",
            ),
        ));
        rows.push(choice(self.cursor == self.variants.len() + 2, t("\u{9884}\u{4e0b}\u{8f7d}\u{6240}\u{9009}\u{6743}\u{91cd}\u{ff08}\u{4e0d}\u{5207}\u{6362}\u{ff09}\u{2026}", "Download selected weights (keep current model)\u{2026}")));
        rows.push(choice(
            self.cursor == self.variants.len() + 3,
            t(
                "\u{8fd4}\u{56de}\u{ff08}\u{653e}\u{5f03}\u{8349}\u{7a3f}\u{ff09}",
                "Back (discard draft)",
            ),
        ));
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
    fn drafts_preserve_weights_on_engine_changes_and_cancel_without_an_action() -> Result<()> {
        let settings = serde_json::json!({"engine":"cpu","model":"runtime-fp16",
            "variants":[{"name":"runtime-fp16","size":7340032,"state":"present"}]});
        let mut form = Form::new(&settings)?;
        form.key(KeyCode::Right);
        assert_eq!(form.selection(), ("gpu", "runtime-fp16"));
        assert_eq!(form.selected_size(), 7340032);
        assert!(matches!(form.key(KeyCode::Esc), Some(Action::Back)));
        assert_eq!(settings["engine"], "cpu");
        assert_eq!(Form::new(&settings)?.selection(), ("cpu", "runtime-fp16"));
        Ok(())
    }
    #[test]
    fn all_variants_are_selectable_without_saving_or_downloading() -> Result<()> {
        let settings = serde_json::json!({"engine":"npu","model":"runtime-q8","variants":[
            {"name":"runtime-q4","size":3145728,"state":"invalid_size"},
            {"name":"runtime-q8","size":1048576,"state":"present"},
            {"name":"runtime-fp16","size":7340032,"state":"missing"}
        ]});
        let mut form = Form::new(&settings)?;
        assert_eq!(form.selection(), ("npu", "runtime-q8"));
        for (index, name) in ["runtime-q4", "runtime-q8", "runtime-fp16"].into_iter().enumerate() {
            form.cursor = index + 1;
            assert!(form.key(KeyCode::Enter).is_none());
            assert_eq!(form.selection(), ("npu", name));
        }
        let before = form.lines(&settings).iter().map(ToString::to_string).collect::<String>();
        assert!(before.contains("runtime-fp16") && before.contains("7 MiB"));
        let mut live = settings.clone();
        live["variants"][2]["state"] = serde_json::json!("present");
        assert!(Form::present(&live, "runtime-fp16"));
        let after = form.lines(&live).iter().map(ToString::to_string).collect::<String>();
        assert_ne!(before, after);
        assert_eq!(form.selection(), ("npu", "runtime-fp16"));
        assert!(!Form::present(
            &serde_json::json!({"variants":[{"name":"q4f16","state":"invalid_size"}]}),
            "q4f16"
        ));
        for variants in [
            Value::Null,
            serde_json::json!([]),
            serde_json::json!([{"name":"runtime-q8","size":"invalid"}]),
            serde_json::json!([{"name":"","size":1048576}]),
            serde_json::json!([{"name":"runtime-q8","size":0}]),
        ] {
            let mut invalid = settings.clone();
            invalid["variants"] = variants;
            assert!(Form::new(&invalid).is_err());
        }
        live["model"] = serde_json::json!("absent-from-runtime-inventory");
        assert!(Form::new(&live).is_err());
        Ok(())
    }
}
