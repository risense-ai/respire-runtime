//! Local HTTP RPC/MCP transport: loopback peers do not require a token.
//!
//! Split-era home: this module serves both the CLI-hosted runtime and the
//! standalone `rsrs-runtime` binary through `respire_commands`; host-specific
//! concerns (MCP bridge, managed-registration id) arrive via `host_hooks`.
use serde_json::json;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

struct HttpRequest {
    method: tiny_http::Method,
    url: String,
    headers: Vec<tiny_http::Header>,
    peer: SocketAddr,
    body: std::io::Cursor<Vec<u8>>,
}

impl HttpRequest {
    fn method(&self) -> &tiny_http::Method {
        &self.method
    }
    fn url(&self) -> &str {
        &self.url
    }
    fn headers(&self) -> &[tiny_http::Header] {
        &self.headers
    }
    fn remote_addr(&self) -> Option<&SocketAddr> {
        Some(&self.peer)
    }
    fn as_reader(&mut self) -> &mut dyn Read {
        &mut self.body
    }
}

static ACCESS_TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
const MAX_BODY: u64 = 32 * 1024 * 1024;

fn set_access_token(t: Option<String>) {
    let _ = ACCESS_TOKEN.set(t);
}

/// Loopback peers need no token. Other peers must authenticate with a header.
fn token_ok(req: &HttpRequest) -> bool {
    if req
        .remote_addr()
        .is_some_and(|addr| addr.ip().is_loopback())
    {
        return true;
    }
    let Some(Some(expected)) = ACCESS_TOKEN.get() else {
        return false;
    };
    // Header first
    for h in req.headers() {
        if h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("X-respire-Token")
        {
            if h.value.as_str() == expected.as_str() {
                return true;
            }
        }
        if h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("Authorization")
        {
            let value = h.value.as_str();
            let token = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "));
            if token == Some(expected.as_str()) {
                return true;
            }
        }
    }
    false
}

fn header_value(req: &HttpRequest, name: &str) -> String {
    for header in req.headers() {
        if header.field.as_str().as_str().eq_ignore_ascii_case(name) {
            return header.value.as_str().to_owned();
        }
    }
    String::new()
}

fn mcp_http(
    req: &mut HttpRequest,
    method: &tiny_http::Method,
    path: &str,
    bound: SocketAddr,
) -> (u16, &'static str, Vec<u8>) {
    let method_name = match *method {
        tiny_http::Method::Get => "GET",
        tiny_http::Method::Post => "POST",
        _ => "OTHER",
    };
    let mut body = String::new();
    let admission = if *method == tiny_http::Method::Post && matches!(path, "/mcp" | "/sse") {
        match crate::rpc_serve::begin_admission(uuid::Uuid::new_v4().to_string(), "mcp_call") {
            Some(admission) => Some(admission),
            None => return (
                503,
                "application/json; charset=utf-8",
                json!({"error":"runtime is draining and rejected new MCP business","code":"runtime_maintenance"})
                    .to_string().into_bytes(),
            ),
        }
    } else {
        None
    };
    let _admission = admission;
    if *method == tiny_http::Method::Post {
        if req
            .as_reader()
            .take(MAX_BODY + 1)
            .read_to_string(&mut body)
            .is_err()
        {
            return (
                400,
                "application/json; charset=utf-8",
                json!({"error":"request body unreadable"})
                    .to_string()
                    .into_bytes(),
            );
        }
        if body.len() as u64 > MAX_BODY {
            return (
                413,
                "application/json; charset=utf-8",
                json!({"error":"request body exceeds runtime frame limit"})
                    .to_string()
                    .into_bytes(),
            );
        }
    }
    crate::host_hooks::mcp_http_response(crate::host_hooks::McpHttpIn {
        method: method_name.to_owned(),
        path: path.to_owned(),
        origin: format!("http://{bound}"),
        accept: header_value(req, "Accept"),
        body,
    })
}

fn dispatch_rpc(body: &[u8], action: impl FnOnce(crate::rpc_serve::RpcResponse) + Send + 'static) -> anyhow::Result<()> {
    match crate::legacy_host::prepare(body)? {
        Some((request, projection)) => crate::rpc_serve::handle_http_legacy_deferred(request,
            move |response| action(crate::legacy_host::project(response, projection))),
        None => crate::rpc_serve::handle_http_rpc_deferred(body, action),
    }
}
fn dispatch_rpc_sync(body: &[u8]) -> anyhow::Result<crate::rpc_serve::RpcResponse> {
    match crate::legacy_host::prepare(body)? {
        Some((request, projection)) => Ok(crate::legacy_host::project(
            crate::rpc_serve::handle_http_legacy(request)?, projection)),
        None => crate::rpc_serve::handle_http_rpc(body),
    }
}
fn legacy_host_headers(headers: &axum::http::HeaderMap) -> anyhow::Result<()> {
    for (name, required) in [("host", true), ("origin", false)] {
        let mut values = headers.get_all(name).iter();
        let first = values.next();
        anyhow::ensure!(!required || first.is_some(), "legacy_host_header_rejected");
        anyhow::ensure!(values.next().is_none(), "legacy_host_header_rejected");
        if let Some(value) = first {
            tiny_http::Header::from_bytes(name, value.as_bytes())
                .map_err(|_| anyhow::anyhow!("legacy_host_header_rejected"))?;
        }
    }
    Ok(())
}


fn handle_request(req: &mut HttpRequest, bound: SocketAddr) -> (u16, &'static str, Vec<u8>) {
    let url = req.url().to_owned();
    let method = req.method().to_owned();

    // Only actual loopback peers are exempt; Host and forwarded headers are ignored.
    if !token_ok(req) {
        return (
            401,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"unauthorized: send Authorization: Bearer or X-respire-Token"}).to_string().into_bytes(),
        );
    }

    let host = header_value(req, "Host");
    let authority = bound.to_string();
    let default_port_host = bound.port() == 80
        && (host.eq_ignore_ascii_case("localhost")
            || authority
                .strip_suffix(":80")
                .is_some_and(|canonical| host.eq_ignore_ascii_case(canonical)));
    if !host.eq_ignore_ascii_case(&authority)
        && !host.eq_ignore_ascii_case(&format!("localhost:{}", bound.port()))
        && !default_port_host
    {
        return (
            403,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"forbidden host"})
                .to_string()
                .into_bytes(),
        );
    }
    let origin = header_value(req, "Origin");
    if !crate::net_rpc::origin_ok(&origin, &format!("http://{bound}")) {
        return (
            403,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"forbidden origin"})
                .to_string()
                .into_bytes(),
        );
    }
    let path = url.split('?').next().unwrap_or(url.as_str());
    if path == "/api/health" && method == tiny_http::Method::Get {
        if crate::legacy_host::health().is_err() {
            return (503, "application/json", br#"{"error":"legacy_host_binding_changed"}"#.to_vec());
        }
        if crate::legacy_host::is_enabled() && !crate::rpc_serve::startup_complete() {
            return (503, "application/json", br#"{"error":"runtime_starting"}"#.to_vec());
        }
        return (
            200,
            "application/json; charset=utf-8",
            serde_json::to_vec(&crate::rpc_serve::health_body()).unwrap_or_default(),
        );
    }
    if path == "/api/runtime/stop" && method == tiny_http::Method::Post {
        // Coordination-version handshake, not an authorization credential. Old
        // hosts must not detach/replace a manager-supervised process.
        if crate::host_hooks::managed_id().is_some()
            && header_value(req, "X-Respire-Lifecycle") != "coordinator-v1"
        {
            return (
                409,
                "application/json; charset=utf-8",
                br#"{"error":"managed_lifecycle_required"}"#.to_vec(),
            );
        }
        let mut body = String::new();
        if req
            .as_reader()
            .take(4097)
            .read_to_string(&mut body)
            .is_err()
            || body.len() > 4096
        {
            return (
                400,
                "application/json; charset=utf-8",
                br#"{"error":"invalid_stop_identity"}"#.to_vec(),
            );
        }
        let expected: serde_json::Value = if body.is_empty() && crate::legacy_host::is_enabled() {
            // This is the explicitly launched old local-host trust boundary.
            // Bind legacy stop to this immutable actor, never current-account
            // discovery. Ordinary and supervisor-managed instances stay strict.
            match crate::legacy_host::stop_identity() {
                Ok(Some(expected)) => expected,
                _ => return (409, "application/json", br#"{"error":"legacy_host_binding_unavailable"}"#.to_vec()),
            }
        } else {
            match serde_json::from_str(&body) {
                Ok(expected) => expected,
                Err(_) => return (400, "application/json", br#"{"error":"invalid_stop_identity"}"#.to_vec()),
            }
        };
        let operation_id = match crate::rpc_serve::request_drain_exit(&expected) {
            Ok(operation_id) => operation_id,
            Err(error) => {
                let (status, code) = match error.to_string().as_str() {
                    "stop_identity_mismatch" => (409, "stop_identity_mismatch"),
                    "stop_operation_mismatch" => (409, "stop_operation_mismatch"),
                    "invalid_stop_force" => (400, "invalid_stop_force"),
                    _ => {
                        eprintln!("runtime stop could not be accepted: {error:#}");
                        (503, "stop_unavailable")
                    }
                };
                return (
                    status,
                    "application/json; charset=utf-8",
                    serde_json::json!({"error":code}).to_string().into_bytes(),
                )
            }
        };
        let force_deadline = crate::rpc_serve::stop_force_deadline_ms();
        return (
            200,
            "application/json; charset=utf-8",
            serde_json::json!({
                "ok": true,
                "server": "respire",
                "request_id": uuid::Uuid::new_v4().to_string(),
                "operation_id": operation_id,
                "state": "accepted",
                "deadline_ms": force_deadline,
                "timeout_state": force_deadline.map(|_| "forced_timeout"),
                "admitted": crate::rpc_serve::admitted_list(),
            })
            .to_string()
            .into_bytes(),
        );
    }
    if path == "/api/rpc" && method == tiny_http::Method::Post {
        let mut body = String::new();
        if req
            .as_reader()
            .take(MAX_BODY + 1)
            .read_to_string(&mut body)
            .is_err()
        {
            return (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error":"request body unreadable"})
                    .to_string()
                    .into_bytes(),
            );
        }
        if body.len() as u64 > MAX_BODY {
            return (
                413,
                "application/json; charset=utf-8",
                json!({"error":"request body exceeds runtime frame limit"})
                    .to_string()
                    .into_bytes(),
            );
        }
        return match dispatch_rpc_sync(body.as_bytes()) {
            Ok(response) => (
                200,
                "application/json; charset=utf-8",
                serde_json::to_vec(&response).unwrap_or_default(),
            ),
            Err(error) => (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error": error.to_string()})
                    .to_string()
                    .into_bytes(),
            ),
        };
    }
    if path == "/mcp" || path == "/sse" {
        return mcp_http(req, &method, path, bound);
    }

    (
        404,
        "application/json; charset=utf-8",
        json!({"error":"unknown runtime endpoint"})
            .to_string()
            .into_bytes(),
    )
}

pub struct BoundRuntime {
    pub server: std::net::TcpListener,
    pub url: String,
}

pub fn bind_runtime(port: Option<u16>, host: &str) -> anyhow::Result<BoundRuntime> {
    let actual = port.unwrap_or_else(crate::net_rpc::rpc_port);
    let address = if host == "localhost" {
        let addresses: Vec<SocketAddr> = (host, actual).to_socket_addrs()?.collect();
        anyhow::ensure!(
            !addresses.is_empty() && addresses.iter().all(|address| address.ip().is_loopback()),
            "local runtime requires an exclusively loopback localhost address"
        );
        addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.first())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("localhost has no loopback address"))?
    } else {
        let ip: IpAddr = host.parse().map_err(|_| {
            anyhow::anyhow!("local runtime requires a literal loopback IP or localhost")
        })?;
        anyhow::ensure!(
            ip.is_loopback(),
            "local runtime cannot bind a non-loopback address"
        );
        SocketAddr::new(ip, actual)
    };
    set_access_token(None);
    let server = std::net::TcpListener::bind(address)
        .map_err(|error| anyhow::anyhow!("failed to bind local runtime at {address}: {error}"))?;
    server.set_nonblocking(true)?;
    let url = format!("http://{}", server.local_addr()?);
    Ok(BoundRuntime { server, url })
}

struct HttpShutdown {
    requested: tokio::sync::Notify,
    drained: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

static HTTP_SHUTDOWN: std::sync::OnceLock<HttpShutdown> = std::sync::OnceLock::new();

pub(crate) fn shutdown() -> anyhow::Result<()> {
    use anyhow::Context;
    if let Some(shutdown) = HTTP_SHUTDOWN.get() {
        shutdown.requested.notify_one();
        shutdown
            .drained
            .lock()
            .map_err(|_| anyhow::anyhow!("HTTP shutdown state poisoned"))?
            .recv_timeout(crate::network::IO_WAIT)
            .context("HTTP response drain did not complete")?;
    }
    Ok(())
}

pub fn serve_loop(server: std::net::TcpListener) -> anyhow::Result<()> {
    let bound = server.local_addr()?;
    let (finished, drained) = std::sync::mpsc::sync_channel(1);
    HTTP_SHUTDOWN
        .set(HttpShutdown {
            requested: tokio::sync::Notify::new(),
            drained: std::sync::Mutex::new(drained),
        })
        .map_err(|_| anyhow::anyhow!("HTTP server already initialized"))?;
    let shutdown = HTTP_SHUTDOWN
        .get()
        .ok_or_else(|| anyhow::anyhow!("HTTP shutdown state unavailable"))?;
    crate::network::runtime()?.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(server)?;
        let app = axum::Router::new()
            .fallback(serve_request)
            .with_state(bound);
        axum::serve(
            crate::network::Listener(listener),
            app.into_make_service_with_connect_info::<crate::network::Peer>(),
        )
        .with_graceful_shutdown(async move { shutdown.requested.notified().await })
        .await?;
        finished.send(()).map_err(|_| {
            std::io::Error::other("HTTP shutdown coordinator unavailable")
        })?;
        // The dispatcher must persist the final receipt before terminating the process.
        std::future::pending::<std::io::Result<()>>().await
    })?;
    Ok(())
}

fn response(status: u16, content_type: &'static str, body: Vec<u8>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut response = (
        axum::http::StatusCode::from_u16(status)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
        body,
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(content_type),
    );
    if content_type.starts_with("text/event-stream") {
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache"),
        );
    }
    response
}

async fn serve_request(
    axum::extract::State(bound): axum::extract::State<SocketAddr>,
    axum::extract::ConnectInfo(crate::network::Peer(peer)): axum::extract::ConnectInfo<
        crate::network::Peer,
    >,
    request: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    if crate::legacy_host::is_enabled() && (!peer.ip().is_loopback()
        || legacy_host_headers(&parts.headers).is_err()) {
        return response(403, "application/json", br#"{"error":"invalid local transport"}"#.to_vec());
    }
    let method = match parts.method.as_str().parse::<tiny_http::Method>() {
        Ok(method) => method,
        Err(_) => {
            return response(
                400,
                "application/json",
                b"{\"error\":\"invalid method\"}".to_vec(),
            )
        }
    };
    let mut local = HttpRequest {
        method,
        url: parts.uri.to_string(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(key, value)| {
                tiny_http::Header::from_bytes(key.as_str(), value.as_bytes()).ok()
            })
            .collect(),
        peer,
        body: std::io::Cursor::new(Vec::new()),
    };
    if !request_authorized(&local, bound) {
        let (status, content_type, bytes) = handle_request(&mut local, bound);
        return response(status, content_type, bytes);
    }
    // Partial bodies wait in a connection future, never the accept loop.
    let bytes = match tokio::time::timeout(
        crate::network::IO_WAIT,
        axum::body::to_bytes(body, MAX_BODY as usize),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        result => {
            let status = if result.is_err() { 408 } else { 413 };
            let mut response = response(
                status,
                "application/json",
                b"{\"error\":\"request body incomplete or exceeds frame limit\"}".to_vec(),
            );
            response.headers_mut().insert(
                axum::http::header::CONNECTION,
                axum::http::HeaderValue::from_static("close"),
            );
            return response;
        }
    };
    let path = local.url().split('?').next().unwrap_or("").to_owned();
    if local.method() == &tiny_http::Method::Post && path == "/api/rpc" {
        let (send, receive) = tokio::sync::oneshot::channel();
        // The completion callback only sends an in-memory result. Hyper owns
        // response ordering and all socket backpressure in its async task.
        // Admission may wait for a business gate; never block a network worker.
        match tokio::task::spawn_blocking(move || {
            dispatch_rpc(&bytes, move |value| {
                let _ = send.send(value);
            })
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return response(
                    400,
                    "application/json",
                    json!({"error": error.to_string()}).to_string().into_bytes(),
                )
            }
            Err(_) => {
                return response(
                    503,
                    "application/json",
                    b"{\"error\":\"runtime admission unavailable\"}".to_vec(),
                )
            }
        }
        return match receive.await {
            Ok(value) => response(
                200,
                "application/json; charset=utf-8",
                serde_json::to_vec(&value).unwrap_or_default(),
            ),
            Err(_) => response(
                503,
                "application/json",
                b"{\"error\":\"runtime reply unavailable\"}".to_vec(),
            ),
        };
    }
    local.body = std::io::Cursor::new(bytes.to_vec());
    // Health and stop also acquire synchronous state locks.
    let result = match tokio::task::spawn_blocking(move || handle_request(&mut local, bound)).await
    {
        Ok(result) => result,
        Err(_) => {
            return response(
                503,
                "application/json",
                b"{\"error\":\"runtime handler unavailable\"}".to_vec(),
            )
        }
    };
    response(result.0, result.1, result.2)
}

fn request_authorized(request: &HttpRequest, bound: SocketAddr) -> bool {
    let host = header_value(request, "Host");
    let authority = bound.to_string();
    let default_port_host = bound.port() == 80
        && (host.eq_ignore_ascii_case("localhost")
            || authority
                .strip_suffix(":80")
                .is_some_and(|canonical| host.eq_ignore_ascii_case(canonical)));
    token_ok(request)
        && (host.eq_ignore_ascii_case(&authority)
            || host.eq_ignore_ascii_case(&format!("localhost:{}", bound.port()))
            || default_port_host)
        && crate::net_rpc::origin_ok(&header_value(request, "Origin"), &format!("http://{bound}"))
}
