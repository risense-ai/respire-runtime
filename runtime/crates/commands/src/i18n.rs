//! CLI display language. `client.json` key `lang` is `zh` or `en`.
//! Machine JSON keeps English field names; only human chrome is translated.

use std::path::PathBuf;

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

pub fn lang() -> Lang {
    if let Ok(raw) = respire_app::env::var("RSRS_LANG") {
        if let Some(lang) = parse_lang(&raw) {
            return lang;
        }
    }
    read_lang_file().unwrap_or(Lang::En)
}

pub fn parse_lang(raw: &str) -> Option<Lang> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "zh" | "zh-cn" | "cn" | "chinese" => Some(Lang::Zh),
        "en" | "en-us" | "english" => Some(Lang::En),
        _ => None,
    }
}

pub fn set_lang(lang: Lang) -> anyhow::Result<()> {
    let path = client_config_path();
    let mut data = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let obj = data
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("client.json is not an object"))?;
    obj.insert(
        "lang".to_owned(),
        Value::String(match lang {
            Lang::Zh => "zh",
            Lang::En => "en",
        }.to_owned()),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

pub fn chrome(key: &str) -> &'static str {
    chrome_for(lang(), key)
}

/// Human label for a summary or table field. Unknown keys keep their words, with underscores turned into spaces.
pub fn field_label(key: &str) -> String {
    if let Some(label) = known_field(lang(), key) {
        return label.to_owned();
    }
    key.replace('_', " ")
}

fn known_field(lang: Lang, key: &str) -> Option<&'static str> {
    let zh = matches!(lang, Lang::Zh);
    Some(match key {
        "conflict_history" => {
            if zh {
                "\u{51b2}\u{7a81}\u{5386}\u{53f2}"
            } else {
                "Conflict history"
            }
        }
        "conflicts" => {
            if zh {
                "\u{51b2}\u{7a81}"
            } else {
                "Conflicts"
            }
        }
        "converged" => {
            if zh {
                "\u{5df2}\u{5bf9}\u{9f50}"
            } else {
                "Converged"
            }
        }
        "historical_conflicts" => {
            if zh {
                "\u{5386}\u{53f2}\u{51b2}\u{7a81}"
            } else {
                "Historical conflicts"
            }
        }
        "index_pending" => {
            if zh {
                "\u{5f85}\u{5d4c}\u{5165}"
            } else {
                "Index pending"
            }
        }
        "local_alive" => {
            if zh {
                "\u{672c}\u{5730}\u{6709}\u{6548}"
            } else {
                "Local active"
            }
        }
        "local_total" => {
            if zh {
                "\u{672c}\u{5730}\u{603b}\u{6570}"
            } else {
                "Local total"
            }
        }
        "pending" => {
            if zh {
                "\u{5f85}\u{63a8}\u{9001}"
            } else {
                "Pending"
            }
        }
        "processed_conflicts" => {
            if zh {
                "\u{5df2}\u{5904}\u{7406}\u{51b2}\u{7a81}"
            } else {
                "Processed conflicts"
            }
        }
        "protocol" => {
            if zh {
                "\u{534f}\u{8bae}"
            } else {
                "Protocol"
            }
        }
        "pulled" => {
            if zh {
                "\u{4e0b}\u{8f7d}"
            } else {
                "Pulled"
            }
        }
        "purged" => {
            if zh {
                "\u{5df2}\u{6e05}\u{9664}"
            } else {
                "Purged"
            }
        }
        "pushed" => {
            if zh {
                "\u{4e0a}\u{4f20}"
            } else {
                "Pushed"
            }
        }
        "remote_alive" => {
            if zh {
                "\u{4e91}\u{7aef}\u{6709}\u{6548}"
            } else {
                "Remote active"
            }
        }
        "remote_total" => {
            if zh {
                "\u{4e91}\u{7aef}\u{603b}\u{6570}"
            } else {
                "Remote total"
            }
        }
        "resolution_supported" => {
            if zh {
                "\u{53ef}\u{89e3}\u{51b3}\u{51b2}\u{7a81}"
            } else {
                "Resolution supported"
            }
        }
        "resolving_conflicts" => {
            if zh {
                "\u{89e3}\u{51b3}\u{4e2d}"
            } else {
                "Resolving"
            }
        }
        "total_matched" => {
            if zh {
                "\u{603b}\u{6570}\u{4e00}\u{81f4}"
            } else {
                "Totals match"
            }
        }
        "undecodable" => {
            if zh {
                "\u{65e0}\u{6cd5}\u{89e3}\u{7801}"
            } else {
                "Undecodable"
            }
        }
        "remote" => {
            if zh {
                "\u{4e91}\u{7aef}"
            } else {
                "Remote"
            }
        }
        "local" => {
            if zh {
                "\u{672c}\u{5730}"
            } else {
                "Local"
            }
        }
        "changes" => {
            if zh {
                "\u{53d8}\u{66f4}"
            } else {
                "Changes"
            }
        }
        "state" => {
            if zh {
                "\u{72b6}\u{6001}"
            } else {
                "State"
            }
        }
        "user" => {
            if zh {
                "\u{7528}\u{6237}"
            } else {
                "User"
            }
        }
        "server" | "server_addr" | "addr" => {
            if zh {
                "\u{670d}\u{52a1}\u{5668}"
            } else {
                "Server"
            }
        }
        "mode" => {
            if zh {
                "\u{6a21}\u{5f0f}"
            } else {
                "Mode"
            }
        }
        "memories" => {
            if zh {
                "\u{8bb0}\u{5fc6}"
            } else {
                "Memories"
            }
        }
        "max_updated_at" => {
            if zh {
                "\u{6700}\u{8fd1}\u{66f4}\u{65b0}"
            } else {
                "Last update"
            }
        }
        "remote_configured" => {
            if zh {
                "\u{5df2}\u{914d}\u{7f6e}\u{8fdc}\u{7a0b}"
            } else {
                "Remote configured"
            }
        }
        "autosync" => {
            if zh {
                "\u{81ea}\u{52a8}\u{540c}\u{6b65}"
            } else {
                "Auto-sync"
            }
        }
        "workspace" => {
            if zh {
                "\u{5de5}\u{4f5c}\u{533a}"
            } else {
                "Workspace"
            }
        }
        "pass" => {
            if zh {
                "\u{901a}\u{8fc7}\u{6570}"
            } else {
                "Pass"
            }
        }
        "warn" => {
            if zh {
                "\u{8b66}\u{544a}\u{6570}"
            } else {
                "Warn"
            }
        }
        "reembedded" => {
            if zh {
                "\u{5df2}\u{91cd}\u{5d4c}\u{5165}"
            } else {
                "Re-embedded"
            }
        }
        "dimensions" => {
            if zh {
                "\u{7ef4}\u{5ea6}"
            } else {
                "Dimensions"
            }
        }
        _ => return None,
    })
}

pub fn yes_no(flag: bool) -> &'static str {
    match (lang(), flag) {
        (Lang::Zh, true) => "\u{662f}",
        (Lang::Zh, false) => "\u{5426}",
        (_, true) => "yes",
        (_, false) => "no",
    }
}

pub fn chrome_for(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::Zh, "summary") => "\u{6458}\u{8981}",
        (Lang::Zh, "result") => "\u{7ed3}\u{679c}",
        (Lang::Zh, "item") => "\u{9879}",
        (Lang::Zh, "status") => "\u{72b6}\u{6001}",
        (Lang::Zh, "value") => "\u{503c}",
        (Lang::Zh, "action") => "\u{52a8}\u{4f5c}",
        (Lang::Zh, "pass") => "\u{901a}\u{8fc7}",
        (Lang::Zh, "warn") => "\u{8b66}\u{544a}",
        (Lang::Zh, "fail") => "\u{5931}\u{8d25}",
        (Lang::Zh, "skip") => "\u{8df3}\u{8fc7}",
        (Lang::Zh, "pending") => "\u{7b49}\u{5f85}",
        (_, "summary") => "SUMMARY",
        (_, "result") => "RESULT",
        (_, "item") => "ITEM",
        (_, "status") => "STATUS",
        (_, "value") => "VALUE",
        (_, "action") => "ACTION",
        (_, "pass") => "PASS",
        (_, "warn") => "WARN",
        (_, "fail") => "FAIL",
        (_, "skip") => "SKIP",
        (_, "pending") => "PENDING",
        _ => "?",
    }
}

pub fn text(key: &str) -> &'static str {
    match (lang(), key) {
        (Lang::Zh, "need_tty") => {
            "\u{65e0}\u{53c2}\u{6570}\u{542f}\u{52a8}\u{9700}\u{8981}\u{7ec8}\u{7aef}\u{3002}\u{67e5}\u{770b}\u{72b6}\u{6001}\u{8bf7}\u{8fd0}\u{884c} rsrs status\u{3002}"
        }
        (_, "need_tty") => "A terminal is required when no command is given. Use `rsrs status`.",
        (Lang::Zh, "direct") => "\u{8b66}\u{544a}\u{ff1a}--direct \u{7ed5}\u{8fc7}\u{672c}\u{673a} runtime\u{ff0c}\u{76f4}\u{63a5}\u{6253}\u{5f00}\u{672c}\u{5730}\u{5e93}\u{3002}",
        (_, "direct") => "WARN: --direct bypasses the local runtime and opens the library itself.",
        (Lang::Zh, "web_down") => "\u{672c}\u{673a} runtime \u{6ca1}\u{6709}\u{5728}\u{8fd0}\u{884c}\u{3002}",
        (_, "web_down") => "The local runtime is not running.",
        (Lang::Zh, "busy") => "\u{6709}\u{957f}\u{4efb}\u{52a1}\u{5728}\u{8fd0}\u{884c}\u{ff0c}status \u{5148}\u{8fd4}\u{56de}\u{3002}",
        (_, "busy") => "A long task is running; status returns without waiting.",
        _ => "",
    }
}

fn read_lang_file() -> Option<Lang> {
    let text = std::fs::read_to_string(client_config_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    parse_lang(data.get("lang")?.as_str()?)
}

/// Same path rule as app-core: `RSRS_DATA_DIR/client.json`, else `~/.rsrs/client.json`.
pub fn client_config_path() -> PathBuf {
    if let Some(root) = respire_app::service::env_root_dir() {
        return root.join("client.json");
    }
    respire_app::service::home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
        .join("client.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        crate::TEST_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner())
    }

    #[test]
    fn chinese_chrome_is_translated() {
        for (key, zh, en) in [
            ("summary", "\u{6458}\u{8981}", "SUMMARY"),
            ("result", "\u{7ed3}\u{679c}", "RESULT"),
            ("item", "\u{9879}", "ITEM"),
            ("status", "\u{72b6}\u{6001}", "STATUS"),
            ("value", "\u{503c}", "VALUE"),
            ("action", "\u{52a8}\u{4f5c}", "ACTION"),
            ("pass", "\u{901a}\u{8fc7}", "PASS"),
            ("warn", "\u{8b66}\u{544a}", "WARN"),
            ("fail", "\u{5931}\u{8d25}", "FAIL"),
            ("skip", "\u{8df3}\u{8fc7}", "SKIP"),
            ("pending", "\u{7b49}\u{5f85}", "PENDING"),
        ] {
            assert_eq!(chrome_for(Lang::Zh, key), zh);
            assert_eq!(chrome_for(Lang::En, key), en);
        }
        assert_eq!(chrome_for(Lang::En, "missing"), "?");
    }

    #[test]
    fn field_labels_follow_the_configured_language() -> anyhow::Result<()> {
        let _guard = lock_env();
        let prev = respire_app::env::var("RSRS_LANG").ok();
        let keys = [
            "conflict_history",
            "conflicts",
            "converged",
            "historical_conflicts",
            "index_pending",
            "local_alive",
            "local_total",
            "pending",
            "processed_conflicts",
            "protocol",
            "pulled",
            "purged",
            "pushed",
            "remote_alive",
            "remote_total",
            "resolution_supported",
            "resolving_conflicts",
            "total_matched",
            "undecodable",
            "remote",
            "local",
            "changes",
            "state",
            "user",
            "server",
            "server_addr",
            "addr",
            "mode",
            "memories",
            "max_updated_at",
            "remote_configured",
            "autosync",
            "workspace",
            "pass",
            "warn",
            "reembedded",
            "dimensions",
        ];
        std::env::set_var("RSRS_LANG", "zh");
        for key in keys {
            let label = field_label(key);
            anyhow::ensure!(!label.is_empty() && label != key, "{key} -> {label}");
        }
        anyhow::ensure!(yes_no(true) == "\u{662f}" && yes_no(false) == "\u{5426}");
        std::env::set_var("RSRS_LANG", "en");
        for key in keys {
            anyhow::ensure!(!field_label(key).is_empty(), "{key}");
        }
        anyhow::ensure!(field_label("not_a_known_field") == "not a known field");
        anyhow::ensure!(yes_no(true) == "yes" && yes_no(false) == "no");
        match prev {
            Some(value) => std::env::set_var("RSRS_LANG", value),
            None => std::env::remove_var("RSRS_LANG"),
        }
        Ok(())
    }

    #[test]
    fn parse_lang_accepts_aliases() {
        assert_eq!(parse_lang("zh-CN"), Some(Lang::Zh));
        assert_eq!(parse_lang(" chinese "), Some(Lang::Zh));
        assert_eq!(parse_lang("en-US"), Some(Lang::En));
        assert_eq!(parse_lang("fr"), None);
        assert_eq!(parse_lang("  "), None);
    }

    #[test]
    fn lang_file_and_text_follow_isolated_config() -> anyhow::Result<()> {
        let _guard = lock_env();
        let previous_dir = respire_app::env::var("RSRS_DATA_DIR").ok();
        let previous_lang = respire_app::env::var("RSRS_LANG").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::remove_var("RSRS_LANG");
        assert!(client_config_path().starts_with(dir.path()));
        assert_eq!(lang(), Lang::En);
        set_lang(Lang::Zh)?;
        assert_eq!(read_lang_file(), Some(Lang::Zh));
        assert_eq!(lang(), Lang::Zh);
        assert_eq!(chrome("summary"), "\u{6458}\u{8981}");
        assert!(text("need_tty").contains("\u{7ec8}\u{7aef}"));
        assert!(text("direct").contains("\u{8b66}\u{544a}"));
        assert!(text("web_down").contains("\u{6ca1}\u{6709}"));
        assert!(text("busy").contains("\u{957f}\u{4efb}\u{52a1}"));
        set_lang(Lang::En)?;
        assert_eq!(lang(), Lang::En);
        assert!(text("need_tty").contains("terminal"));
        assert!(text("direct").contains("WARN"));
        assert!(text("web_down").contains("not running"));
        assert!(text("busy").contains("long task"));
        assert!(text("missing").is_empty());
        std::fs::write(client_config_path(), "[]")?;
        assert!(set_lang(Lang::Zh).is_err());
        std::env::set_var("RSRS_LANG", "zh-cn");
        assert_eq!(lang(), Lang::Zh);
        std::env::set_var("RSRS_LANG", "nope");
        assert_eq!(lang(), Lang::En);
        match previous_dir {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match previous_lang {
            Some(value) => std::env::set_var("RSRS_LANG", value),
            None => std::env::remove_var("RSRS_LANG"),
        }
        Ok(())
    }
}
