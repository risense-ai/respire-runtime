//! transport::remote — cloud backup store client (sync protocol)
//!
//! local-first: server = dumb ciphertext store. The client only moves two ways:
//!   push (local → cloud upsert, LWW), pull (cloud → local full, LWW).
//! Search / decrypt are all local; the server does not take part.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::Read as _;
use std::time::Duration;

use super::{FetchReply, MemoryTransport};
use crate::memory::model::StoredMemory;

/// When the server revokes the session (401), switch this machine to read-only — write commands then hit the local gate,
/// the user sees a clear reason, not a silent "local writes work, cloud never accepts" failure.
///
/// Idempotent and conservative: already read-only does not rewrite; a write fail only warns, does not block (401 itself is the main error).
/// Where: a kicked member's profile had no agent.json, so the local gate did not fire (gap measured 2026-09-21).
fn mark_session_revoked_readonly() {
    use crate::service::{off_mode, readonly_mode, write_agent_config_key};
    if readonly_mode() || off_mode() {
        return; // Read-only members already carry the marker.
    }
    if let Err(e) = write_agent_config_key("readonly", &json!(true)) {
        eprintln!("warning: session invalid, but failed to switch local library to read-only ({e}) \u{2014} run rsrs space use <other> by hand");
    }
}

#[derive(Debug, Clone)]
pub struct RemoteConfig {
    /// e.g. http://127.0.0.1:8787
    pub address: String,
    pub token: String,
}

#[derive(Serialize)]
struct PushReq<'a> {
    id: &'a str,
    ciphertext: &'a str,
    nonce: &'a str,
    embedding_enc: &'a str,
    updated_at: &'a str,
    deleted: bool,
}

#[derive(Deserialize)]
struct PushReply {
    replaced: bool,
}

#[derive(Deserialize)]
struct BatchPushReply {
    replaced: Vec<bool>,
}

#[derive(Deserialize)]
struct PullReply {
    blobs: Vec<StoredMemory>,
    #[serde(default)]
    cursor: u64,
    #[serde(default)]
    total: u64,
    #[serde(default)]
    alive: u64,
}

#[derive(Deserialize)]
struct BoolReply {
    deleted: bool,
}

#[derive(Deserialize)]
struct MaxReply {
    max: Option<String>,
}

#[derive(Deserialize)]
struct CountReply {
    count: i64,
}

pub struct RemoteTransport {
    config: RemoteConfig,
    /// Persistent Agent: ureq's top-level helpers build a new agent each time (a fresh TLS handshake per request),
    /// a full push of thousands of rows was ~0.7 rows/s; reusing the connection drops the per-row handshake.
    agent: ureq::Agent,
}

impl RemoteTransport {
    pub fn new(config: RemoteConfig) -> Self {
        // ureq's default read timeout is unlimited. A stalled proxy then pins
        // the caller until something outside kills it. Bound each call instead
        // of the whole multi-page sync: a finished page is already committed.
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .timeout_write(Duration::from_secs(30))
            .build();
        Self { config, agent }
    }

    fn base(&self) -> String {
        self.config.address.trim().trim_end_matches('/').to_owned()
    }

    fn send(&self, req: ureq::Request, body: Option<serde_json::Value>) -> Result<String> {
        let req = req.set("Authorization", &format!("Bearer {}", self.config.token));
        let result = match body {
            Some(value) => req.send_json(value),
            None => req.call(),
        };
        match result {
            Ok(resp) => {
                // into_string has a 10MB hard cap (INTO_STRING_LIMIT); a full pull easily exceeds it —
                // switch to a streaming read, no size cap (the synced set grows with the library).
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .context("failed to read response")?;
                Ok(String::from_utf8_lossy(&buf).into_owned())
            }
            Err(ureq::Error::Status(401, _)) => {
                // 401 = session revoked by the server (typical: kicked by the space owner).
                // Auto switch local to read-only: otherwise a kicked member can keep writing locally forever and never reach the cloud
                // (gap measured 2026-09-21). After the flag, the local gate blocks writes and the user sees a clear reason.
                mark_session_revoked_readonly();
                bail!("unauthorized: token rejected (session revoked by the server \u{2014} possibly kicked by the space owner; local library is read-only, recall only)")
            }
            Err(ureq::Error::Status(code, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                bail!("remote request failed ({code}): {text}")
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Status-aware send: Ok(Ok(body)) = 2xx; Ok(Err(code)) = HTTP status error
    /// (404-fallback branches need the code itself, not a folded message); outer Err is transport only.
    fn send_with_status(
        &self,
        req: ureq::Request,
        body: Option<serde_json::Value>,
    ) -> Result<std::result::Result<String, u16>> {
        let req = req.set("Authorization", &format!("Bearer {}", self.config.token));
        let result = match body {
            Some(value) => req.send_json(value),
            None => req.call(),
        };
        match result {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .context("failed to read response")?;
                Ok(Ok(String::from_utf8_lossy(&buf).into_owned()))
            }
            Err(ureq::Error::Status(code, resp)) => {
                // L10 (2026-09-20 audit): previously dropped the body, the upper layer only had the code, so diagnosis
                // could not see the server error text. Now read it and warn (return contract unchanged).
                let body = resp.into_string().unwrap_or_default();
                if !body.trim().is_empty() {
                    eprintln!("warning: server returned {code}: {}", body.chars().take(300).collect::<String>());
                }
                Ok(Err(code))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Old server has no /push/batch → fall back to per-row /push.
    fn put_batch_fallback(&self, memories: &[StoredMemory]) -> Result<Vec<bool>> {
        let mut replaced = Vec::with_capacity(memories.len());
        for m in memories {
            replaced.push(self.put(m)?);
        }
        Ok(replaced)
    }
}

impl MemoryTransport for RemoteTransport {
    fn resolve_conflicts(&self,request:&super::protocol::ResolveRequest)->Result<super::protocol::ResolveReply> {
        let text=self.send(self.agent.post(&format!("{}/v2/conflicts/resolve",self.base())),Some(serde_json::to_value(request)?))?;
        Ok(serde_json::from_str(&text)?)
    }

    fn fetch_resolutions(&self,epoch:&str,after:i64,until:Option<i64>)->Result<super::protocol::ResolutionPage> {
        let mut req=self.agent.get(&format!("{}/v2/conflicts/resolutions",self.base()))
            .query("epoch",epoch).query("after",&after.to_string());
        if let Some(high)=until {req=req.query("until",&high.to_string());}
        Ok(serde_json::from_str(&self.send(req,None)?)?)
    }
    fn capabilities(&self) -> Result<Option<super::protocol::Capabilities>> {
        match self.send_with_status(self.agent.get(&format!("{}/sync/capabilities",self.base())),None)? {
            Ok(body)=>Ok(Some(serde_json::from_str(&body)?)),
            Err(404)=>Ok(None),
            Err(code)=>bail!("sync capability query failed ({code})"),
        }
    }

    fn push_v2(&self, request:&super::protocol::PushRequest)->Result<super::protocol::PushReply> {
        let body=self.send(self.agent.post(&format!("{}/v2/push/batch",self.base())),Some(serde_json::to_value(request)?))?;
        Ok(serde_json::from_str(&body)?)
    }

    fn pull_v2(&self, epoch:&str, after:i64, until:Option<i64>, snapshot:bool)->Result<super::protocol::Page> {
        let endpoint=if snapshot {"snapshot"} else {"pull"};
        let mut req=self.agent.get(&format!("{}/v2/{endpoint}",self.base()))
            .query("epoch",epoch).query("after",&after.to_string());
        if let Some(high)=until {req=req.query("until",&high.to_string());}
        let body=self.send(req,None)?;
        Ok(serde_json::from_str(&body)?)
    }

    fn put(&self, memory: &StoredMemory) -> Result<bool> {
        let text = self.send(
            self.agent.post(&format!("{}/push", self.base())),
            Some(json!(PushReq {
                id: &memory.id,
                ciphertext: &memory.ciphertext,
                nonce: &memory.nonce,
                embedding_enc: "",
                updated_at: &memory.updated_at,
                deleted: memory.deleted,
            })),
        )?;
        Ok(serde_json::from_str::<PushReply>(&text)?.replaced)
    }

    /// Batch push: one HTTP carries the whole batch (caller already chunks ~100 rows).
    /// If the server is not upgraded (404), fall back to per-row /push — a new CLI can still sync with an old server.
    fn put_batch(&self, memories: &[StoredMemory]) -> Result<Vec<bool>> {
        if memories.is_empty() {
            return Ok(Vec::new());
        }
        let items: Vec<PushReq<'_>> = memories
            .iter()
            .map(|m| PushReq {
                id: &m.id,
                ciphertext: &m.ciphertext,
                nonce: &m.nonce,
                embedding_enc: "",
                updated_at: &m.updated_at,
                deleted: m.deleted,
            })
            .collect();
        let text = match self.send_with_status(
            self.agent.post(&format!("{}/push/batch", self.base())),
            Some(json!({ "items": items })),
        )? {
            Ok(text) => text,
            // Old server has no /push/batch → per-row fallback
            Err(404) => return self.put_batch_fallback(memories),
            Err(code) => bail!("remote request failed ({code})"),
        };
        let reply: BatchPushReply =
            serde_json::from_str(&text).with_context(|| format!("\u{6279}\u{91cf}\u{63a8}\u{9001}\u{54cd}\u{5e94}\u{89e3}\u{6790}\u{5931}\u{8d25}: {text}"))?;
        if reply.replaced.len() != memories.len() {
            anyhow::bail!(
                "\u{6279}\u{91cf}\u{63a8}\u{9001}\u{54cd}\u{5e94}\u{957f}\u{5ea6}\u{4e0d}\u{7b26}\u{ff1a}\u{53d1} {} \u{56de} {}",
                memories.len(),
                reply.replaced.len()
            );
        }
        Ok(reply.replaced)
    }

    fn all(&self, include_deleted: bool) -> Result<Vec<StoredMemory>> {
        let text = self.send(self.agent.get(&format!("{}/pull", self.base())), None)?;
        let reply = serde_json::from_str::<PullReply>(&text)?;
        Ok(if include_deleted {
            reply.blobs
        } else {
            reply.blobs.into_iter().filter(|b| !b.deleted).collect()
        })
    }

    /// Incremental pull: /pull?since=<cursor> (server arrival order, see server.rs rev). No cursor → full.
    fn fetch_rev(&self, since: Option<u64>) -> Result<FetchReply> {
        let url = match since {
            Some(n) => format!("{}/pull?since={n}", self.base()),
            None => format!("{}/pull", self.base()),
        };
        let text = self.send(self.agent.get(&url), None)?;
        let reply = serde_json::from_str::<PullReply>(&text)?;
        Ok(FetchReply {
            blobs: reply.blobs,
            cursor: reply.cursor,
            total: reply.total,
            alive: reply.alive,
        })
    }

    fn max_updated_at(&self) -> Result<Option<String>> {
        let text = self.send(ureq::get(&format!("{}/max", self.base())), None)?;
        Ok(serde_json::from_str::<MaxReply>(&text)?.max)
    }

    fn forget(&self, id: &str) -> Result<bool> {
        let text = self.send(
            self.agent.post(&format!("{}/forget", self.base())),
            Some(json!({"id": id})),
        )?;
        Ok(serde_json::from_str::<BoolReply>(&text)?.deleted)
    }

    fn count(&self) -> Result<i64> {
        let text = self.send(self.agent.get(&format!("{}/count", self.base())), None)?;
        Ok(serde_json::from_str::<CountReply>(&text)?.count)
    }
}
