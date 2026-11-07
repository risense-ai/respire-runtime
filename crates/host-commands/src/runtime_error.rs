//! Errors that must never be mistaken for permission to take over a runtime.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContext {
    pub scope: respire_protocol::RuntimeRequestScope,
    pub operation_id: String,
    pub idempotency_key: String,
}

#[derive(Debug)]
pub enum RuntimeError {
    Unavailable,
    TokenUnreadable(String),
    Unauthorized,
    Transport(String),
    OutcomeUnknown {
        request_id: String,
        operation: OperationContext,
        detail: String,
    },
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "runtime_unavailable: HTTP runtime is unavailable; for a managed local component, run `rsrs runtime start`; for a remote endpoint, check its address and connectivity"),
            Self::TokenUnreadable(detail) => write!(f, "runtime_token_unreadable: {detail}; have the host provide RPC authentication"),
            Self::Unauthorized => write!(f, "runtime_unauthorized: HTTP runtime rejected authentication; legacy loopback runtimes require their existing RSRS_RPC_TOKEN or runtime token file, and non-loopback clients need a valid token"),
            Self::Transport(detail) => write!(f, "runtime_transport: {detail}; check sandbox access to the host HTTP runtime"),
            Self::OutcomeUnknown { request_id, operation, detail } => write!(f, "request_outcome_unknown: request_id={request_id}; operation_id={}; idempotency_key={}; scope=({}, {}, {}); {detail}; query runtime.result with the original operation context before any retry; the command was not replayed", operation.operation_id, operation.idempotency_key, operation.scope.account_id, operation.scope.instance_id, operation.scope.generation),
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
