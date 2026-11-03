//! Errors that must never be mistaken for permission to take over a runtime.

use std::fmt;

#[derive(Debug)]
pub enum RuntimeError {
    Unavailable,
    TokenUnreadable(String),
    Unauthorized,
    Transport(String),
    OutcomeUnknown { request_id: String, detail: String },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "runtime_unavailable: host HTTP runtime is not running at {}; start `rsrs --runtime-internal` in the host terminal", crate::net_rpc::rpc_base_url()),
            Self::TokenUnreadable(detail) => write!(f, "runtime_token_unreadable: {detail}; have the host provide RPC authentication"),
            Self::Unauthorized => write!(f, "runtime_unauthorized: HTTP runtime rejected authentication; legacy loopback runtimes require their existing RSRS_RPC_TOKEN or runtime token file, and non-loopback clients need a valid token"),
            Self::Transport(detail) => write!(f, "runtime_transport: {detail}; check sandbox access to the host HTTP runtime"),
            Self::OutcomeUnknown { request_id, detail } => write!(f, "request_outcome_unknown: request_id={request_id}; {detail}; query runtime.result with this ID before any retry; the command was not replayed"),
        }
    }
}

impl std::error::Error for RuntimeError {}

pub fn http(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(401 | 403, _) => RuntimeError::Unauthorized.into(),
        error => RuntimeError::Transport(error.to_string()).into(),
    }
}
