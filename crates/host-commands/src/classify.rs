//! Shared classification constants; the command surface references them
//! across the crate boundary for clap defaults.

pub const DEFAULT_MODEL: &str = "jev-latest";
// Host credentials and network transport. Core owns classification policy.
#[cfg(feature = "server")]
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use serde_json::json;
use serde_json::Value;

pub const DEFAULT_API_BASE: &str = "https://api.typesafe.ai/v1/systemone";
// The clap default references the const in this module; the re-export line
// the CLI carried is folded away now that both halves share one module.

pub const DEFAULT_DS_BASE: &str = "https://api.deepseek.com/v1";
pub const DEFAULT_DS_MODEL: &str = "deepseek-flash";

pub struct Backend {
    pub name: &'static str,
    pub key: String,
    pub model: String,
    pub endpoint: String,
    pub base_shown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub choice: String,
    pub confidence: f32,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResult {
    pub id: String,
    pub title: String,
    pub current_root: String,
    pub verdict: Option<Verdict>,
    pub error: Option<String>,
    pub suggest_parent: Option<(String, String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyReport {
    pub command: String,
    pub status: String,
    pub summary: ReportSummary,
    pub items: Vec<ReportItem>,
    pub actions: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total: usize,
    pub matched: usize,
    pub mismatch: usize,
    pub unrooted: usize,
    pub low_confidence: usize,
    pub failed: usize,
    pub min_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportItem {
    pub id: String,
    pub class: String,
    pub status: String,
    pub current: String,
    pub choice: String,
    pub confidence: Option<f32>,
    pub title: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub parent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessResult {
    pub report: Option<ClassifyReport>,
    pub actions: Vec<Action>,
    pub warnings: Vec<String>,
    pub summary: Value,
    pub items: Vec<ItemResult>,
}

#[cfg(feature = "server")]
pub fn execute(
    memories: &[respire_app::StoredMemory],
    backend: Option<&Backend>,
    options: Value,
) -> Result<BusinessResult> {
    let provider = backend.map(|backend| {
        json!({
            "name": backend.name,
            "model": backend.model,
        })
    });
    let mut transport = |request: &Value| -> Result<Value> {
        let backend = backend.ok_or_else(|| anyhow::anyhow!("model provider is not configured"))?;
        call_api(backend, request)
    };
    respire_app::core_sdk::execute_with_transport(
        "classify_business",
        json!({
            "snapshots": respire_app::core_sdk::metadata_snapshots(memories),
            "backend": provider,
            "options": options,
        }),
        &mut transport,
    )
}

/// Do not include credentials, endpoint query parameters, prompts or provider
/// response bodies in errors crossing the SDK boundary.
#[cfg(feature = "server")]
pub fn call_api(backend: &Backend, request: &Value) -> Result<Value> {
    anyhow::ensure!(
        request["provider"].as_str() == Some(backend.name),
        "model provider mismatch"
    );
    anyhow::ensure!(
        !backend.endpoint.trim().is_empty(),
        "model endpoint is required"
    );
    anyhow::ensure!(!backend.key.trim().is_empty(), "model API key is required");
    let timeout = request["timeout"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("model request timeout missing"))?;
    let retries = request["retries"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("model request retries missing"))?;
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(true)
        .timeout(std::time::Duration::from_secs(timeout))
        .build();
    for attempt in 0..=retries {
        match agent.post(&backend.endpoint)
            .set("Authorization", &format!("Bearer {}", backend.key))
            .set("Content-Type", "application/json").send_json(&request["body"]) {
            Ok(response) => return response.into_json()
                .map_err(|_| anyhow::anyhow!("model response is not JSON")),
            Err(ureq::Error::Status(code, _)) if !(code == 429 || code == 529 || code >= 500) || attempt == retries =>
                anyhow::bail!("model request failed (HTTP {code}); check endpoint credentials or service availability"),
            Err(_) if attempt == retries => anyhow::bail!("model network request failed; check endpoint, timeout, TLS and proxy settings"),
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_secs(1 << attempt));
    }
    anyhow::bail!("model request exhausted retries")
}

pub fn ds_endpoint(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/chat/completions") {
        base.to_owned()
    } else {
        format!("{base}/chat/completions")
    }
}

#[cfg(all(test, feature = "server"))]
mod transport_tests {
    use super::*;

    #[test]
    fn classification_uses_host_http_without_sending_credentials_to_core() -> Result<()> {
        for status in [200, 401] {
            let server = tiny_http::Server::http("127.0.0.1:0")
                .map_err(|error| anyhow::anyhow!("fixture bind failed: {error}"))?;
            let address = server
                .server_addr()
                .to_ip()
                .ok_or_else(|| anyhow::anyhow!("fixture address missing"))?;
            let fixture = std::thread::spawn(move || -> Result<()> {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(10))?
                    .ok_or_else(|| anyhow::anyhow!("host transport did not send a request"))?;
                anyhow::ensure!(
                    request
                        .headers()
                        .iter()
                        .any(|header| header.field.equiv("Authorization")
                            && header.value.as_str() == "Bearer synthetic-host-only-key"),
                    "host authentication header missing"
                );
                let response = if status == 200 {
                    r#"{"choices":[{"message":{"content":"1"},"logprobs":{"content":[{"token":"1","logprob":0,"top_logprobs":[{"token":"1","logprob":0}]}]}}]}"#
                } else {
                    "synthetic-host-only-key must not be echoed"
                };
                request
                    .respond(tiny_http::Response::from_string(response).with_status_code(status))?;
                Ok(())
            });
            let backend = Backend {
                name: "ds",
                key: "synthetic-host-only-key".into(),
                model: "fixture".into(),
                endpoint: format!("http://{address}/model"),
                base_shown: "fixture".into(),
            };
            let payload = json!({
                "backend":{"name":"ds","model":"fixture"},
                "snapshots":[{"id":"host-transport","title":"native","importance":"important"}],
                "options":{"mode":"standard","limit":1,"all":true,"root":null,"max_chars":100,
                    "min_confidence":0.5,"dry_run":false,"samples":1,"batch":1,"tree_depth":1,
                    "min_kids":1,"segments":1,"rounds":1}
            });
            let mut calls = 0;
            let mut transport = |request: &Value| -> Result<Value> {
                calls += 1;
                anyhow::ensure!(
                    request.get("key").is_none() && request.get("endpoint").is_none(),
                    "credential field entered Core callback"
                );
                anyhow::ensure!(
                    !request.to_string().contains(&backend.key),
                    "key entered Core request"
                );
                call_api(&backend, request)
            };
            let mut core = respire_app::core_sdk::Core::new()?;
            let result =
                core.call_with_transport("classify_business", payload.clone(), &mut transport)?;
            fixture
                .join()
                .map_err(|_| anyhow::anyhow!("HTTP fixture panicked"))??;
            assert_eq!(calls, 1);
            if status == 200 {
                assert!(
                    result["items"][0]["error"].is_null(),
                    "classification failed: {}",
                    result["items"][0]["error"]
                );
                assert!(result["items"][0]["verdict"].is_object());
            } else {
                let error = result["items"][0]["error"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("HTTP error missing"))?;
                assert!(error.contains("HTTP 401"));
                assert!(!error.contains(&backend.key));
            }
            assert_eq!(core.capabilities()?["model_transport"], "host_callback");
            let mut forbidden = payload;
            forbidden["backend"]["key"] = json!("must-be-rejected");
            assert!(core.call("classify_business", forbidden).is_err());
            let rejected = core.call(
                "query_business",
                json!({"mode":"fast",
                "query":{"text":"native","limit":1},
                "provider":{"name":"ds","model":"fixture","key":"must-be-rejected"}}),
            );
            let error = rejected
                .err()
                .ok_or_else(|| anyhow::anyhow!("local recall accepted credential fields"))?;
            assert!(error.to_string().contains("unknown field `key`"));
        }
        Ok(())
    }
}
