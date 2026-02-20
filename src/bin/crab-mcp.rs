use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use clap::{ArgAction, Parser, ValueEnum};
use crab_mitm::daemon::{
    default_socket_path, default_token_path_for_principal, ensure_daemon_started, send_rpc,
};
use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_MAX_AGE, AUTHORIZATION, CONTENT_TYPE, ORIGIN, VARY,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::task::JoinSet;
use uuid::Uuid;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const TRAFFIC_BODY_PREVIEW_MAX_CHARS: usize = 2048;
const MCP_SESSION_ID_HEADER: &str = "Mcp-Session-Id";
const HTTP_SESSION_TTL_SECONDS: u64 = 30 * 60;
const HTTP_SESSION_CLEANUP_SECONDS: u64 = 60;

type HttpBody = Full<Bytes>;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportMode {
    Stdio,
    Http,
    Both,
}

#[derive(Debug, Parser)]
#[command(
    name = "crab-mcp",
    version,
    about = "Crab Proxy MCP server (stdio + Streamable HTTP)"
)]
struct Cli {
    #[arg(long)]
    socket: Option<PathBuf>,

    #[arg(long)]
    daemon_path: Option<PathBuf>,

    #[arg(long, default_value = "mcp")]
    principal: String,

    #[arg(long)]
    token_path: Option<PathBuf>,

    #[arg(
        long,
        default_value_t = true,
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    ensure_daemon: bool,

    #[arg(long, value_enum, default_value_t = TransportMode::Stdio)]
    transport: TransportMode,

    #[arg(long, default_value = "127.0.0.1")]
    http_bind: String,

    #[arg(long, default_value_t = 3847)]
    http_port: u16,
}

struct DaemonBridge {
    socket_path: PathBuf,
    daemon_path: PathBuf,
    token_path: PathBuf,
    principal: String,
    ensure_daemon: bool,
    daemon_start_lock: Mutex<()>,
}

impl DaemonBridge {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        if self.ensure_daemon {
            self.ensure_daemon_ready().await?;
        }
        let token = self.read_token_async().await?;
        send_rpc(&self.socket_path, &token, &self.principal, method, params).await
    }

    async fn ensure_daemon_ready(&self) -> Result<()> {
        if can_connect_socket(&self.socket_path) {
            return Ok(());
        }

        let _guard = self.daemon_start_lock.lock().await;
        if can_connect_socket(&self.socket_path) {
            return Ok(());
        }

        let daemon_path = self.daemon_path.clone();
        let daemon_path_for_error = daemon_path.clone();
        let socket_path = self.socket_path.clone();
        tokio::task::spawn_blocking(move || ensure_daemon_started(&daemon_path, &socket_path))
            .await
            .context("failed to join daemon start task")?
            .with_context(|| {
                format!(
                    "failed to ensure daemon at {}",
                    daemon_path_for_error.display()
                )
            })?;
        Ok(())
    }

    async fn read_token_async(&self) -> Result<String> {
        let raw = tokio::fs::read_to_string(&self.token_path)
            .await
            .with_context(|| format!("failed to read token from {}", self.token_path.display()))?;
        let normalized = raw.trim().to_string();
        if normalized.is_empty() {
            bail!("token file is empty: {}", self.token_path.display());
        }
        Ok(normalized)
    }
}

#[derive(Clone)]
struct HttpConfig {
    bind: String,
    port: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct HttpSession {
    id: String,
    created_at: Instant,
    last_activity: Instant,
    client_info: Option<Value>,
    capabilities: Option<Value>,
}

#[derive(Clone)]
struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, HttpSession>>>,
    ttl: Duration,
}

impl SessionManager {
    fn new(ttl: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    async fn create(&self, client_info: Option<Value>, capabilities: Option<Value>) -> String {
        let id = Uuid::new_v4().to_string();
        let now = Instant::now();
        let session = HttpSession {
            id: id.clone(),
            created_at: now,
            last_activity: now,
            client_info,
            capabilities,
        };
        self.sessions.write().await.insert(id.clone(), session);
        id
    }

    async fn validate_and_touch(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(session_id) else {
            return false;
        };
        if session.last_activity.elapsed() > self.ttl {
            sessions.remove(session_id);
            return false;
        }
        session.last_activity = Instant::now();
        true
    }

    async fn cleanup_once(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, session| session.last_activity.elapsed() <= self.ttl);
    }

    async fn cleanup_loop(&self, mut shutdown_rx: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(HTTP_SESSION_CLEANUP_SECONDS)) => {
                    self.cleanup_once().await;
                }
            }
        }
    }
}

#[derive(Clone)]
struct HttpState {
    bridge: Arc<DaemonBridge>,
    token_path: PathBuf,
    sessions: SessionManager,
}

struct StdioRequest {
    message: Value,
    response_tx: std_mpsc::Sender<Option<Value>>,
}

enum TaskEvent {
    StdioDispatch(Result<()>),
    Http(Result<()>),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let socket_path = match cli.socket {
        Some(path) => path,
        None => default_socket_path().context("failed to resolve default socket path")?,
    };
    let token_path = match cli.token_path {
        Some(path) => path,
        None => default_token_path_for_principal(&cli.principal)
            .with_context(|| format!("failed to resolve token path for {}", cli.principal))?,
    };
    let daemon_path = match cli.daemon_path {
        Some(path) => path,
        None => default_daemon_path().context("failed to resolve daemon path")?,
    };

    let bridge = Arc::new(DaemonBridge {
        socket_path,
        daemon_path,
        token_path: token_path.clone(),
        principal: cli.principal,
        ensure_daemon: cli.ensure_daemon,
        daemon_start_lock: Mutex::new(()),
    });

    match cli.transport {
        TransportMode::Stdio => {
            if cli.http_bind != "127.0.0.1" || cli.http_port != 3847 {
                eprintln!("warning: HTTP options are ignored in stdio mode");
            }
            run_stdio_mode(bridge).await
        }
        TransportMode::Http => {
            let http_config = HttpConfig {
                bind: cli.http_bind,
                port: cli.http_port,
            };
            run_http_mode(bridge, token_path, http_config).await
        }
        TransportMode::Both => {
            let http_config = HttpConfig {
                bind: cli.http_bind,
                port: cli.http_port,
            };
            run_both_mode(bridge, token_path, http_config).await
        }
    }
}

async fn run_stdio_mode(bridge: Arc<DaemonBridge>) -> Result<()> {
    let (request_tx, request_rx) = mpsc::channel::<StdioRequest>(16);
    let stdio_thread = start_stdio_thread(request_tx);
    let dispatch_result = run_stdio_dispatch(bridge, request_rx).await;
    let _ = stdio_thread.join();
    dispatch_result
}

async fn run_http_mode(
    bridge: Arc<DaemonBridge>,
    token_path: PathBuf,
    config: HttpConfig,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let sessions = SessionManager::new(Duration::from_secs(HTTP_SESSION_TTL_SECONDS));
    let state = HttpState {
        bridge,
        token_path,
        sessions,
    };
    let mut http_task = tokio::spawn(run_http_server(config, state, shutdown_rx));

    tokio::select! {
        task = &mut http_task => {
            task.context("http task join failed")?
        }
        _ = shutdown_signal() => {
            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut http_task).await;
            Ok(())
        }
    }
}

async fn run_both_mode(
    bridge: Arc<DaemonBridge>,
    token_path: PathBuf,
    config: HttpConfig,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let sessions = SessionManager::new(Duration::from_secs(HTTP_SESSION_TTL_SECONDS));
    let state = HttpState {
        bridge: Arc::clone(&bridge),
        token_path,
        sessions,
    };

    let (request_tx, request_rx) = mpsc::channel::<StdioRequest>(16);
    let stdio_thread = start_stdio_thread(request_tx);

    let mut set = JoinSet::new();
    let bridge_s = Arc::clone(&bridge);
    set.spawn(
        async move { TaskEvent::StdioDispatch(run_stdio_dispatch(bridge_s, request_rx).await) },
    );

    let shutdown_http = shutdown_rx.clone();
    set.spawn(async move { TaskEvent::Http(run_http_server(config, state, shutdown_http).await) });

    let mut stdio_done = false;

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                let _ = shutdown_tx.send(true);
                // signal path: do not block on stdio thread join
                return Ok(());
            }
            joined = set.join_next() => {
                let Some(joined) = joined else { break; };
                match joined.context("task join failed")? {
                    TaskEvent::StdioDispatch(Ok(())) => {
                        stdio_done = true;
                    }
                    TaskEvent::StdioDispatch(Err(err)) => {
                        stdio_done = true;
                        eprintln!("warning: stdio dispatch ended with error: {err:#}");
                    }
                    TaskEvent::Http(Ok(())) => {
                        if stdio_done {
                            let _ = stdio_thread.join();
                        }
                        return Ok(());
                    }
                    TaskEvent::Http(Err(err)) => {
                        // HTTP fatal -> fail-fast
                        let _ = shutdown_tx.send(true);
                        return Err(err);
                    }
                }
            }
        }
    }

    if stdio_done {
        let _ = stdio_thread.join();
    }
    Ok(())
}

fn start_stdio_thread(request_tx: mpsc::Sender<StdioRequest>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = BufWriter::new(stdout.lock());

        loop {
            let message = match read_framed_message(&mut reader) {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(err) => {
                    let response = rpc_error(Value::Null, -32700, format!("parse error: {err:#}"));
                    let _ = write_framed_message(&mut writer, &response);
                    break;
                }
            };

            let (resp_tx, resp_rx) = std_mpsc::channel();
            let request = StdioRequest {
                message,
                response_tx: resp_tx,
            };
            if request_tx.blocking_send(request).is_err() {
                break;
            }

            let Ok(response) = resp_rx.recv() else {
                break;
            };
            if let Some(response) = response
                && write_framed_message(&mut writer, &response).is_err()
            {
                break;
            }
        }
    })
}

async fn run_stdio_dispatch(
    bridge: Arc<DaemonBridge>,
    mut request_rx: mpsc::Receiver<StdioRequest>,
) -> Result<()> {
    while let Some(req) = request_rx.recv().await {
        let response = handle_message(req.message, &bridge).await;
        let _ = req.response_tx.send(response);
    }
    Ok(())
}

async fn run_http_server(
    config: HttpConfig,
    state: HttpState,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let (listener, actual_port) = bind_http_listener(&config).await?;
    if actual_port != config.port {
        eprintln!(
            "warning: requested HTTP port {} unavailable, fell back to {}",
            config.port, actual_port
        );
    }
    eprintln!(
        "crab-mcp listening on http://{}:{}/mcp",
        config.bind, actual_port
    );

    let cleanup_state = state.sessions.clone();
    let cleanup_shutdown = shutdown_rx.clone();
    let cleanup_task =
        tokio::spawn(async move { cleanup_state.cleanup_loop(cleanup_shutdown).await });

    let mut conn_tasks = JoinSet::new();
    let conn_builder = AutoBuilder::new(TokioExecutor::new());

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _peer): (tokio::net::TcpStream, SocketAddr) =
                    accepted.context("failed to accept HTTP client")?;
                let io = TokioIo::new(stream);
                let state_clone = state.clone();
                let svc_builder = conn_builder.clone();
                conn_tasks.spawn(async move {
                    let service = service_fn(move |req| {
                        let state = state_clone.clone();
                        async move { handle_http_request(req, state).await }
                    });
                    svc_builder
                        .serve_connection_with_upgrades(io, service)
                        .await
                        .map_err(|err| anyhow!("http connection error: {err}"))
                });
            }
        }
    }

    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if conn_tasks.is_empty() {
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= drain_deadline {
            conn_tasks.abort_all();
            break;
        }
        let wait_for = drain_deadline - now;
        match tokio::time::timeout(wait_for, conn_tasks.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                conn_tasks.abort_all();
                break;
            }
        }
    }

    cleanup_task.abort();
    Ok(())
}

async fn bind_http_listener(config: &HttpConfig) -> Result<(TcpListener, u16)> {
    let candidate_ports: Vec<u16> = if config.port == 3847 {
        (3847..=3857).collect()
    } else {
        vec![config.port]
    };

    let mut last_error: Option<std::io::Error> = None;
    for port in candidate_ports {
        match TcpListener::bind((config.bind.as_str(), port)).await {
            Ok(listener) => return Ok((listener, port)),
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    let detail = last_error
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown bind failure".to_string());
    bail!(
        "failed to bind HTTP listener on {}:{} (fallback exhausted): {}",
        config.bind,
        config.port,
        detail
    );
}

async fn handle_http_request(
    req: Request<Incoming>,
    state: HttpState,
) -> std::result::Result<Response<HttpBody>, Infallible> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let headers = parts.headers.clone();

    let origin = match extract_origin(&headers) {
        Ok(origin) => origin,
        Err(response) => return Ok(response),
    };

    if method == Method::GET && path == "/healthz" {
        return Ok(json_response(
            StatusCode::OK,
            json!({ "status": "ok" }),
            origin.as_deref(),
            false,
        ));
    }

    if path != "/mcp" {
        return Ok(json_error_response(
            StatusCode::NOT_FOUND,
            "not found",
            origin.as_deref(),
        ));
    }

    if method == Method::OPTIONS {
        return Ok(preflight_response(origin.as_deref()));
    }

    if method != Method::POST {
        return Ok(json_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
            origin.as_deref(),
        ));
    }

    let auth_ok = match validate_bearer(&headers, &state.token_path).await {
        Ok(ok) => ok,
        Err(err) => {
            return Ok(json_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("token read failed: {err:#}"),
                origin.as_deref(),
            ));
        }
    };
    if !auth_ok {
        return Ok(json_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or missing token",
            origin.as_deref(),
        ));
    }

    if !is_json_content_type(&headers) {
        return Ok(json_error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected application/json",
            origin.as_deref(),
        ));
    }

    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Ok(json_error_response(
                StatusCode::BAD_REQUEST,
                &format!("failed to read request body: {err}"),
                origin.as_deref(),
            ));
        }
    };

    let message: Value = match serde_json::from_slice(&body_bytes) {
        Ok(value) => value,
        Err(err) => {
            return Ok(json_error_response(
                StatusCode::BAD_REQUEST,
                &format!("invalid JSON body: {err}"),
                origin.as_deref(),
            ));
        }
    };

    let method_name = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_initialize = method_name == "initialize";

    let session_id = headers
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    if !is_initialize {
        let Some(session_id) = session_id.as_deref() else {
            return Ok(json_error_response(
                StatusCode::BAD_REQUEST,
                "missing Mcp-Session-Id header",
                origin.as_deref(),
            ));
        };
        if !state.sessions.validate_and_touch(session_id).await {
            return Ok(json_error_response(
                StatusCode::UNAUTHORIZED,
                "session expired or invalid",
                origin.as_deref(),
            ));
        }
    }

    let response = handle_message(message.clone(), &state.bridge).await;
    let Some(response_payload) = response else {
        return Ok(no_content_response(origin.as_deref()));
    };

    let mut response = json_response(StatusCode::OK, response_payload, origin.as_deref(), false);
    if is_initialize {
        let params = message
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let client_info = params.get("clientInfo").cloned();
        let capabilities = params.get("capabilities").cloned();
        let session_id = state.sessions.create(client_info, capabilities).await;
        if let Ok(header_value) = HeaderValue::from_str(&session_id) {
            response
                .headers_mut()
                .insert(MCP_SESSION_ID_HEADER, header_value);
        }
    }
    Ok(response)
}

fn extract_origin(headers: &HeaderMap) -> std::result::Result<Option<String>, Response<HttpBody>> {
    let Some(origin_value) = headers.get(ORIGIN) else {
        return Ok(None);
    };
    let origin = match origin_value.to_str() {
        Ok(origin) => origin,
        Err(_) => {
            return Err(json_error_response(
                StatusCode::FORBIDDEN,
                "origin not allowed",
                None,
            ));
        }
    };
    if !is_origin_allowed(origin) {
        return Err(json_error_response(
            StatusCode::FORBIDDEN,
            "origin not allowed",
            None,
        ));
    }
    Ok(Some(origin.to_string()))
}

fn is_origin_allowed(origin: &str) -> bool {
    let Ok(uri) = Uri::from_str(origin) else {
        return false;
    };
    matches!(uri.host(), Some("localhost") | Some("127.0.0.1"))
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    content_type
        .split(';')
        .next()
        .map(|base| base.trim().eq_ignore_ascii_case("application/json"))
        .unwrap_or(false)
}

async fn validate_bearer(headers: &HeaderMap, token_path: &Path) -> Result<bool> {
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Ok(false);
    };
    let header_value = match value.to_str() {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let token = match header_value.strip_prefix("Bearer ") {
        Some(token) if !token.is_empty() => token,
        _ => return Ok(false),
    };
    let expected = tokio::fs::read_to_string(token_path)
        .await
        .with_context(|| format!("failed to read token from {}", token_path.display()))?;
    Ok(expected.trim() == token)
}

fn preflight_response(origin: Option<&str>) -> Response<HttpBody> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::NO_CONTENT;
    if let Some(origin) = origin
        && let Ok(origin_value) = HeaderValue::from_str(origin)
    {
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
    }
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Authorization, Content-Type, Mcp-Session-Id"),
    );
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Origin"));
    response
}

fn no_content_response(origin: Option<&str>) -> Response<HttpBody> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::NO_CONTENT;
    apply_cors_headers(response.headers_mut(), origin);
    response
}

fn json_error_response(
    status: StatusCode,
    message: &str,
    origin: Option<&str>,
) -> Response<HttpBody> {
    json_response(status, json!({ "error": message }), origin, true)
}

fn json_response(
    status: StatusCode,
    payload: Value,
    origin: Option<&str>,
    include_json_content_type: bool,
) -> Response<HttpBody> {
    let body = serde_json::to_vec(&payload)
        .unwrap_or_else(|_| b"{\"error\":\"serialization failure\"}".to_vec());
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    if include_json_content_type || status != StatusCode::NO_CONTENT {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    apply_cors_headers(response.headers_mut(), origin);
    response
}

fn apply_cors_headers(headers: &mut HeaderMap, origin: Option<&str>) {
    if let Some(origin) = origin
        && let Ok(origin_value) = HeaderValue::from_str(origin)
    {
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
        headers.insert(VARY, HeaderValue::from_static("Origin"));
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).ok();
    let mut sigterm = signal(SignalKind::terminate()).ok();
    tokio::select! {
        _ = async {
            if let Some(sigint) = &mut sigint {
                sigint.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        _ = async {
            if let Some(sigterm) = &mut sigterm {
                sigterm.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn can_connect_socket(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

async fn handle_message(message: Value, bridge: &DaemonBridge) -> Option<Value> {
    let obj = match message.as_object() {
        Some(obj) => obj,
        None => {
            return Some(rpc_error(
                Value::Null,
                -32600,
                "invalid request: expected object",
            ));
        }
    };

    let method = match obj.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => {
            let id = obj.get("id").cloned().unwrap_or(Value::Null);
            return Some(rpc_error(id, -32600, "invalid request: method is required"));
        }
    };

    let id = obj.get("id").cloned();
    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    let Some(id) = id else {
        return None;
    };

    let response = match method {
        "initialize" => {
            log_protocol_version_mismatch(&params);
            rpc_ok(id, initialize_result())
        }
        "ping" => rpc_ok(id, json!({})),
        "tools/list" => rpc_ok(id, json!({ "tools": tool_definitions() })),
        "tools/call" => match handle_tools_call(&params, bridge).await {
            Ok(result) => rpc_ok(id, result),
            Err(err) => rpc_error(id, -32602, format!("invalid tools/call params: {err:#}")),
        },
        _ => rpc_error(id, -32601, format!("method not found: {method}")),
    };

    Some(response)
}

fn log_protocol_version_mismatch(params: &Value) {
    let Some(version) = params
        .as_object()
        .and_then(|obj| obj.get("protocolVersion"))
        .and_then(Value::as_str)
    else {
        return;
    };
    if version != MCP_PROTOCOL_VERSION {
        eprintln!(
            "warning: client protocolVersion '{}' differs from server '{}'; continuing in lenient mode",
            version, MCP_PROTOCOL_VERSION
        );
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "crab-mcp",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Use Crab tools to inspect status/logs/traffic and manage proxy runtime, engine config, and map/allow/rewrite rules."
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "crab_ping",
            "description": "Ping Crab daemon and verify RPC connectivity.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_version",
            "description": "Get daemon engine/protocol version.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_proxy_status",
            "description": "Get proxy runtime status.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_proxy_start",
            "description": "Start proxy runtime.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_proxy_stop",
            "description": "Stop proxy runtime.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_daemon_doctor",
            "description": "Run daemon self-check and return diagnostic fields.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_config_get",
            "description": "Read current daemon engine config.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_listen_addr",
            "description": "Set listen address (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "listen_addr": { "type": "string" }
                },
                "required": ["listen_addr"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_inspect_enabled",
            "description": "Enable/disable body inspection (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" }
                },
                "required": ["enabled"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_throttle",
            "description": "Set throttle config (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "latency_ms": { "type": "integer", "minimum": 0 },
                    "downstream_bps": { "type": "integer", "minimum": 0 },
                    "upstream_bps": { "type": "integer", "minimum": 0 },
                    "only_selected_hosts": { "type": "boolean" },
                    "selected_hosts": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "required": [
                    "enabled",
                    "latency_ms",
                    "downstream_bps",
                    "upstream_bps",
                    "only_selected_hosts",
                    "selected_hosts"
                ],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_client_allowlist",
            "description": "Set LAN client allowlist (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "ips": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "required": ["enabled", "ips"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_transparent",
            "description": "Set transparent proxy mode (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "listen_port": { "type": "integer", "minimum": 1, "maximum": 65535 }
                },
                "required": ["enabled", "listen_port"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_load_ca",
            "description": "Load CA cert/key paths (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cert_path": { "type": "string" },
                    "key_path": { "type": "string" }
                },
                "required": ["cert_path", "key_path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_logs_tail",
            "description": "Read recent logs from daemon ring buffer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "after_seq": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_traffic_tail",
            "description": "Read recent HTTP(S) traffic entries with response/request previews from structured logs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "after_seq": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "max_entries": { "type": "integer", "minimum": 1, "maximum": 500 },
                    "include_headers": { "type": "boolean" },
                    "include_body_sample_b64": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_traffic_get",
            "description": "Get one HTTP(S) traffic entry by request_id from recent structured logs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": { "type": "string" },
                    "after_seq": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 2000 },
                    "include_headers": { "type": "boolean" },
                    "include_body_sample_b64": { "type": "boolean" }
                },
                "required": ["request_id"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_dump",
            "description": "Read current allow/map/rewrite rules.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_allow",
            "description": "Read allowlist rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_map_local",
            "description": "Read map_local rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_map_remote",
            "description": "Read map_remote rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_status_rewrite",
            "description": "Read status_rewrite rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_clear",
            "description": "Clear all rules (daemon must be stopped).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_allow",
            "description": "Add allowlist rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_allow",
            "description": "Remove allowlist rules by matcher.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_map_local_text",
            "description": "Add Map Local (inline text) rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "text": { "type": "string" },
                    "status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
                    "content_type": { "type": "string" }
                },
                "required": ["matcher", "text"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_map_local_file",
            "description": "Add Map Local (file path) rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "file_path": { "type": "string" },
                    "status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
                    "content_type": { "type": "string" }
                },
                "required": ["matcher", "file_path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_map_local",
            "description": "Remove map_local rules by matcher (optionally source_kind/source_value).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "source_kind": { "type": "string", "enum": ["file", "text"] },
                    "source_value": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_map_remote",
            "description": "Add Map Remote rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "destination": { "type": "string" }
                },
                "required": ["matcher", "destination"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_map_remote",
            "description": "Remove map_remote rules by matcher (optionally destination).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "destination": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_status_rewrite",
            "description": "Add response status rewrite rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "to_status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
                    "from_status_code": { "type": "integer", "minimum": -1, "maximum": 599 }
                },
                "required": ["matcher", "to_status_code"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_status_rewrite",
            "description": "Remove status_rewrite rules by matcher (optionally from/to filters).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "from_status_code": { "type": "integer", "minimum": -1, "maximum": 599 },
                    "to_status_code": { "type": "integer", "minimum": 100, "maximum": 599 }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rpc",
            "description": "Send a raw daemon RPC method call (advanced).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "method": { "type": "string" },
                    "params": { "type": "object" }
                },
                "required": ["method"],
                "additionalProperties": false
            }
        }),
    ]
}

async fn handle_tools_call(params: &Value, bridge: &DaemonBridge) -> Result<Value> {
    let obj = params
        .as_object()
        .ok_or_else(|| anyhow!("params must be an object"))?;
    let tool_name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("name is required"))?;

    let arguments = match obj.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => bail!("arguments must be an object"),
    };

    let result = match call_tool(tool_name, &arguments, bridge).await {
        Ok(value) => tool_success(value),
        Err(err) => tool_error(format!("{err:#}")),
    };

    Ok(result)
}

async fn call_tool(
    tool_name: &str,
    args: &Map<String, Value>,
    bridge: &DaemonBridge,
) -> Result<Value> {
    match tool_name {
        "crab_ping" => bridge.call("system.ping", json!({})).await,
        "crab_version" => bridge.call("system.version", json!({})).await,
        "crab_proxy_status" => bridge.call("proxy.status", json!({})).await,
        "crab_proxy_start" => bridge.call("proxy.start", json!({})).await,
        "crab_proxy_stop" => bridge.call("proxy.stop", json!({})).await,
        "crab_daemon_doctor" => bridge.call("daemon.doctor", json!({})).await,
        "crab_engine_config_get" => bridge.call("engine.config_dump", json!({})).await,
        "crab_engine_set_listen_addr" => {
            ensure_allowed_keys(args, &["listen_addr"])?;
            let listen_addr = arg_str_required(args, "listen_addr")?;
            bridge
                .call(
                    "engine.set_listen_addr",
                    json!({
                        "listen_addr": listen_addr,
                    }),
                )
                .await
        }
        "crab_engine_set_inspect_enabled" => {
            ensure_allowed_keys(args, &["enabled"])?;
            let enabled = arg_bool_required(args, "enabled")?;
            bridge
                .call(
                    "engine.set_inspect_enabled",
                    json!({
                        "enabled": enabled,
                    }),
                )
                .await
        }
        "crab_engine_set_throttle" => {
            ensure_allowed_keys(
                args,
                &[
                    "enabled",
                    "latency_ms",
                    "downstream_bps",
                    "upstream_bps",
                    "only_selected_hosts",
                    "selected_hosts",
                ],
            )?;
            let enabled = arg_bool_required(args, "enabled")?;
            let latency_ms = arg_u64_required(args, "latency_ms")?;
            let downstream_bps = arg_u64_required(args, "downstream_bps")?;
            let upstream_bps = arg_u64_required(args, "upstream_bps")?;
            let only_selected_hosts = arg_bool_required(args, "only_selected_hosts")?;
            let selected_hosts = arg_string_vec_required(args, "selected_hosts")?;
            bridge
                .call(
                    "engine.set_throttle",
                    json!({
                        "enabled": enabled,
                        "latency_ms": latency_ms,
                        "downstream_bps": downstream_bps,
                        "upstream_bps": upstream_bps,
                        "only_selected_hosts": only_selected_hosts,
                        "selected_hosts": selected_hosts,
                    }),
                )
                .await
        }
        "crab_engine_set_client_allowlist" => {
            ensure_allowed_keys(args, &["enabled", "ips"])?;
            let enabled = arg_bool_required(args, "enabled")?;
            let ips = arg_string_vec_required(args, "ips")?;
            bridge
                .call(
                    "engine.set_client_allowlist",
                    json!({
                        "enabled": enabled,
                        "ips": ips,
                    }),
                )
                .await
        }
        "crab_engine_set_transparent" => {
            ensure_allowed_keys(args, &["enabled", "listen_port"])?;
            let enabled = arg_bool_required(args, "enabled")?;
            let listen_port = arg_u64_required(args, "listen_port")?;
            if listen_port == 0 || listen_port > 65535 {
                bail!("listen_port must be between 1 and 65535");
            }
            bridge
                .call(
                    "engine.set_transparent",
                    json!({
                        "enabled": enabled,
                        "listen_port": listen_port,
                    }),
                )
                .await
        }
        "crab_engine_load_ca" => {
            ensure_allowed_keys(args, &["cert_path", "key_path"])?;
            let cert_path = arg_str_required(args, "cert_path")?;
            let key_path = arg_str_required(args, "key_path")?;
            bridge
                .call(
                    "engine.load_ca",
                    json!({
                        "cert_path": cert_path,
                        "key_path": key_path,
                    }),
                )
                .await
        }
        "crab_logs_tail" => {
            ensure_allowed_keys(args, &["after_seq", "limit"])?;
            let after_seq = arg_u64(args, "after_seq")?.unwrap_or(0);
            let limit = arg_u64(args, "limit")?.unwrap_or(200).min(1000);
            bridge
                .call(
                    "logs.tail",
                    json!({
                        "after_seq": after_seq,
                        "limit": limit,
                    }),
                )
                .await
        }
        "crab_traffic_tail" => {
            ensure_allowed_keys(
                args,
                &[
                    "after_seq",
                    "limit",
                    "max_entries",
                    "include_headers",
                    "include_body_sample_b64",
                ],
            )?;
            let after_seq = arg_u64(args, "after_seq")?.unwrap_or(0);
            let limit = arg_u64(args, "limit")?.unwrap_or(400).min(1000);
            let max_entries = arg_u64(args, "max_entries")?.unwrap_or(100).min(500) as usize;
            let include_headers = arg_bool(args, "include_headers")?.unwrap_or(true);
            let include_body_sample_b64 =
                arg_bool(args, "include_body_sample_b64")?.unwrap_or(false);
            traffic_tail(
                bridge,
                after_seq,
                limit,
                max_entries,
                include_headers,
                include_body_sample_b64,
            )
            .await
        }
        "crab_traffic_get" => {
            ensure_allowed_keys(
                args,
                &[
                    "request_id",
                    "after_seq",
                    "limit",
                    "include_headers",
                    "include_body_sample_b64",
                ],
            )?;
            let request_id = arg_str_required(args, "request_id")?;
            let after_seq = arg_u64(args, "after_seq")?.unwrap_or(0);
            let limit = arg_u64(args, "limit")?.unwrap_or(1000).min(2000);
            let include_headers = arg_bool(args, "include_headers")?.unwrap_or(true);
            let include_body_sample_b64 =
                arg_bool(args, "include_body_sample_b64")?.unwrap_or(false);
            traffic_get(
                bridge,
                &request_id,
                after_seq,
                limit,
                include_headers,
                include_body_sample_b64,
            )
            .await
        }
        "crab_rules_dump" => bridge.call("engine.rules_dump", json!({})).await,
        "crab_rules_list_allow" => rules_dump_field(bridge, "allowlist").await,
        "crab_rules_list_map_local" => rules_dump_field(bridge, "map_local").await,
        "crab_rules_list_map_remote" => rules_dump_field(bridge, "map_remote").await,
        "crab_rules_list_status_rewrite" => rules_dump_field(bridge, "status_rewrite").await,
        "crab_rules_clear" => bridge.call("engine.rules_clear", json!({})).await,
        "crab_rules_add_allow" => {
            ensure_allowed_keys(args, &["matcher"])?;
            let matcher = arg_str_required(args, "matcher")?;
            bridge
                .call("engine.rules_add_allow", json!({ "matcher": matcher }))
                .await
        }
        "crab_rules_remove_allow" => {
            ensure_allowed_keys(args, &["matcher"])?;
            let matcher = arg_str_required(args, "matcher")?;
            bridge
                .call("engine.rules_remove_allow", json!({ "matcher": matcher }))
                .await
        }
        "crab_rules_add_map_local_text" => {
            ensure_allowed_keys(args, &["matcher", "text", "status_code", "content_type"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let text = arg_str_required(args, "text")?;
            let status_code = arg_u64(args, "status_code")?.unwrap_or(200);
            if !(100..=599).contains(&status_code) {
                bail!("status_code must be between 100 and 599");
            }
            let mut params = json!({
                "matcher": matcher,
                "text": text,
                "status_code": status_code,
            });
            if let Some(content_type) = arg_str(args, "content_type")? {
                params["content_type"] = Value::String(content_type);
            }
            bridge.call("engine.rules_add_map_local_text", params).await
        }
        "crab_rules_add_map_local_file" => {
            ensure_allowed_keys(
                args,
                &["matcher", "file_path", "status_code", "content_type"],
            )?;
            let matcher = arg_str_required(args, "matcher")?;
            let file_path = arg_str_required(args, "file_path")?;
            let status_code = arg_u64(args, "status_code")?.unwrap_or(200);
            if !(100..=599).contains(&status_code) {
                bail!("status_code must be between 100 and 599");
            }
            let mut params = json!({
                "matcher": matcher,
                "file_path": file_path,
                "status_code": status_code,
            });
            if let Some(content_type) = arg_str(args, "content_type")? {
                params["content_type"] = Value::String(content_type);
            }
            bridge.call("engine.rules_add_map_local_file", params).await
        }
        "crab_rules_remove_map_local" => {
            ensure_allowed_keys(args, &["matcher", "source_kind", "source_value"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let mut params = json!({
                "matcher": matcher,
            });
            if let Some(source_kind) = arg_str(args, "source_kind")? {
                if source_kind != "file" && source_kind != "text" {
                    bail!("source_kind must be 'file' or 'text'");
                }
                params["source_kind"] = Value::String(source_kind);
            }
            if let Some(source_value) = arg_str(args, "source_value")? {
                params["source_value"] = Value::String(source_value);
            }
            bridge.call("engine.rules_remove_map_local", params).await
        }
        "crab_rules_add_map_remote" => {
            ensure_allowed_keys(args, &["matcher", "destination"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let destination = arg_str_required(args, "destination")?;
            bridge
                .call(
                    "engine.rules_add_map_remote",
                    json!({
                        "matcher": matcher,
                        "destination": destination,
                    }),
                )
                .await
        }
        "crab_rules_remove_map_remote" => {
            ensure_allowed_keys(args, &["matcher", "destination"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let mut params = json!({
                "matcher": matcher,
            });
            if let Some(destination) = arg_str(args, "destination")? {
                params["destination"] = Value::String(destination);
            }
            bridge.call("engine.rules_remove_map_remote", params).await
        }
        "crab_rules_add_status_rewrite" => {
            ensure_allowed_keys(args, &["matcher", "to_status_code", "from_status_code"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let to_status_code = arg_u64(args, "to_status_code")?
                .ok_or_else(|| anyhow!("to_status_code is required"))?;
            if !(100..=599).contains(&to_status_code) {
                bail!("to_status_code must be between 100 and 599");
            }
            let from_status_code = arg_i64(args, "from_status_code")?.unwrap_or(-1);
            if !(from_status_code == -1 || (100..=599).contains(&from_status_code)) {
                bail!("from_status_code must be -1 or between 100 and 599");
            }
            bridge
                .call(
                    "engine.rules_add_status_rewrite",
                    json!({
                        "matcher": matcher,
                        "to_status_code": to_status_code,
                        "from_status_code": from_status_code,
                    }),
                )
                .await
        }
        "crab_rules_remove_status_rewrite" => {
            ensure_allowed_keys(args, &["matcher", "from_status_code", "to_status_code"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let mut params = json!({
                "matcher": matcher,
            });
            if let Some(from_status_code) = arg_i64(args, "from_status_code")? {
                if !(from_status_code == -1 || (100..=599).contains(&from_status_code)) {
                    bail!("from_status_code must be -1 or between 100 and 599");
                }
                params["from_status_code"] = Value::Number(from_status_code.into());
            }
            if let Some(to_status_code) = arg_u64(args, "to_status_code")? {
                if !(100..=599).contains(&to_status_code) {
                    bail!("to_status_code must be between 100 and 599");
                }
                params["to_status_code"] = Value::Number(to_status_code.into());
            }
            bridge
                .call("engine.rules_remove_status_rewrite", params)
                .await
        }
        "crab_rpc" => {
            ensure_allowed_keys(args, &["method", "params"])?;
            let method = arg_str_required(args, "method")?;
            let params = match args.get("params") {
                None | Some(Value::Null) => json!({}),
                Some(Value::Object(map)) => Value::Object(map.clone()),
                Some(_) => bail!("params must be an object"),
            };
            bridge.call(&method, params).await
        }
        _ => bail!("unknown tool: {tool_name}"),
    }
}

async fn rules_dump_field(bridge: &DaemonBridge, key: &str) -> Result<Value> {
    let dump = bridge.call("engine.rules_dump", json!({})).await?;
    let object = dump
        .as_object()
        .ok_or_else(|| anyhow!("engine.rules_dump returned non-object result"))?;
    let value = object
        .get(key)
        .ok_or_else(|| anyhow!("engine.rules_dump missing key: {key}"))?;
    Ok(json!({
        key: value
    }))
}

#[derive(Debug, Default, Clone)]
struct TrafficAggregate {
    request_id: Option<String>,
    event: Option<String>,
    method: Option<String>,
    url: Option<String>,
    peer: Option<String>,
    status: Option<u16>,
    duration_ms: Option<f64>,
    response_size_bytes: Option<u64>,
    map_local: Option<String>,
    map_remote: Option<String>,
    map_remote_to: Option<String>,
    request_headers: Option<String>,
    response_headers: Option<String>,
    request_body_preview: Option<String>,
    request_body_bytes: Option<u64>,
    request_body_sample_b64: Option<String>,
    response_body_preview: Option<String>,
    response_body_bytes: Option<u64>,
    response_body_sample_b64: Option<String>,
    seq_first: u64,
    seq_last: u64,
    ts_unix_ms: u64,
}

impl TrafficAggregate {
    fn to_value(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "event": self.event,
            "method": self.method,
            "url": self.url,
            "peer": self.peer,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "response_size_bytes": self.response_size_bytes,
            "map_local": self.map_local,
            "map_remote": self.map_remote,
            "map_remote_to": self.map_remote_to,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "request_body": {
                "bytes": self.request_body_bytes,
                "preview": self.request_body_preview,
                "sample_b64": self.request_body_sample_b64
            },
            "response_body": {
                "bytes": self.response_body_bytes,
                "preview": self.response_body_preview,
                "sample_b64": self.response_body_sample_b64
            },
            "seq_first": self.seq_first,
            "seq_last": self.seq_last,
            "ts_unix_ms": self.ts_unix_ms
        })
    }
}

async fn traffic_tail(
    bridge: &DaemonBridge,
    after_seq: u64,
    limit: u64,
    max_entries: usize,
    include_headers: bool,
    include_body_sample_b64: bool,
) -> Result<Value> {
    let logs = bridge
        .call(
            "logs.tail",
            json!({
                "after_seq": after_seq,
                "limit": limit,
            }),
        )
        .await?;
    let (next_seq, records_scanned, mut entries) =
        aggregate_traffic_entries(&logs, include_headers, include_body_sample_b64)?;
    entries.sort_by(|left, right| right.seq_last.cmp(&left.seq_last));
    if entries.len() > max_entries {
        entries.truncate(max_entries);
    }

    Ok(json!({
        "next_seq": next_seq,
        "records_scanned": records_scanned,
        "entry_count": entries.len(),
        "entries": entries.iter().map(TrafficAggregate::to_value).collect::<Vec<_>>(),
    }))
}

async fn traffic_get(
    bridge: &DaemonBridge,
    request_id: &str,
    after_seq: u64,
    limit: u64,
    include_headers: bool,
    include_body_sample_b64: bool,
) -> Result<Value> {
    let logs = bridge
        .call(
            "logs.tail",
            json!({
                "after_seq": after_seq,
                "limit": limit,
            }),
        )
        .await?;
    let (next_seq, records_scanned, mut entries) =
        aggregate_traffic_entries(&logs, include_headers, include_body_sample_b64)?;
    entries.sort_by(|left, right| right.seq_last.cmp(&left.seq_last));

    let Some(entry) = entries
        .into_iter()
        .find(|item| item.request_id.as_deref() == Some(request_id))
    else {
        bail!("request_id not found in current log window: {request_id}");
    };

    Ok(json!({
        "next_seq": next_seq,
        "records_scanned": records_scanned,
        "request_id": request_id,
        "entry": entry.to_value(),
    }))
}

fn aggregate_traffic_entries(
    logs: &Value,
    include_headers: bool,
    include_body_sample_b64: bool,
) -> Result<(u64, usize, Vec<TrafficAggregate>)> {
    let next_seq = value_to_u64(logs.get("next_seq").unwrap_or(&Value::Null)).unwrap_or(0);
    let records = logs
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("logs.tail response missing records array"))?;

    let mut by_key: HashMap<String, TrafficAggregate> = HashMap::new();
    let mut scanned = 0usize;

    for record in records {
        let Some(message) = record.get("message").and_then(Value::as_str) else {
            continue;
        };
        let Some(payload) = parse_structured_payload(message) else {
            continue;
        };

        scanned += 1;
        let seq = value_to_u64(record.get("seq").unwrap_or(&Value::Null)).unwrap_or(0);
        let ts_unix_ms =
            value_to_u64(record.get("ts_unix_ms").unwrap_or(&Value::Null)).unwrap_or(0);
        let payload_type = object_string_field(&payload, "type").unwrap_or_default();
        let event = object_string_field(&payload, "event").unwrap_or_default();
        let method = object_string_field(&payload, "method");
        let url = object_string_field(&payload, "url");
        let peer = object_string_field(&payload, "peer");
        let request_id =
            object_string_field(&payload, "request_id").filter(|value| !value.is_empty());

        let key = if let Some(id) = request_id.as_ref() {
            format!("id:{id}")
        } else if let (Some(m), Some(u), Some(p)) = (method.as_ref(), url.as_ref(), peer.as_ref()) {
            format!("fallback:{p}|{m}|{u}")
        } else {
            continue;
        };

        let entry = by_key.entry(key).or_insert_with(|| TrafficAggregate {
            seq_first: seq,
            seq_last: seq,
            ts_unix_ms,
            ..TrafficAggregate::default()
        });
        if seq > 0 && (entry.seq_first == 0 || seq < entry.seq_first) {
            entry.seq_first = seq;
        }
        if seq >= entry.seq_last {
            entry.seq_last = seq;
            entry.ts_unix_ms = ts_unix_ms;
        }

        if entry.request_id.is_none() {
            entry.request_id = request_id.clone();
        }
        if entry.method.is_none() {
            entry.method = method.clone();
        }
        if entry.url.is_none() {
            entry.url = url.clone();
        }
        if entry.peer.is_none() {
            entry.peer = peer.clone();
        }
        if !event.is_empty() {
            entry.event = Some(event.clone());
        }

        if payload_type == "entry" {
            if let Some(status) = object_u16_field(&payload, "status")
                .or_else(|| object_u16_field(&payload, "response_status"))
            {
                entry.status = Some(status);
            }
            if let Some(duration_ms) = object_f64_field(&payload, "duration_ms") {
                entry.duration_ms = Some(duration_ms);
            }
            if let Some(size) = object_u64_field(&payload, "response_size_bytes") {
                entry.response_size_bytes = Some(size);
            }
            if let Some(value) = object_string_field(&payload, "map_local") {
                entry.map_local = Some(value);
            }
            if let Some(value) = object_string_field(&payload, "map_remote") {
                entry.map_remote = Some(value);
            }
            if let Some(value) = object_string_field(&payload, "map_remote_to") {
                entry.map_remote_to = Some(value);
            }
            continue;
        }

        if payload_type != "meta" {
            continue;
        }

        match event.as_str() {
            "request_headers" => {
                if include_headers
                    && let Some(headers_b64) = object_string_field(&payload, "headers_b64")
                {
                    entry.request_headers = Some(
                        decode_base64_to_text(&headers_b64)
                            .unwrap_or_else(|| "<failed to decode headers_b64>".to_string()),
                    );
                }
            }
            "response_headers" => {
                if include_headers
                    && let Some(headers_b64) = object_string_field(&payload, "headers_b64")
                {
                    entry.response_headers = Some(
                        decode_base64_to_text(&headers_b64)
                            .unwrap_or_else(|| "<failed to decode headers_b64>".to_string()),
                    );
                }
                if let Some(status) = object_u16_field(&payload, "status")
                    .or_else(|| object_u16_field(&payload, "response_status"))
                {
                    entry.status = Some(status);
                }
            }
            "body_inspection" => {
                let direction = object_string_field(&payload, "direction").unwrap_or_default();
                let body_bytes = object_u64_field(&payload, "body_bytes");
                let response_status = object_u16_field(&payload, "response_status");
                let sample_b64 = object_string_field(&payload, "sample_b64");
                let preview = sample_b64.as_deref().and_then(decode_body_preview);

                if direction == "request" {
                    if let Some(bytes) = body_bytes {
                        entry.request_body_bytes = Some(bytes);
                    }
                    if let Some(text) = preview {
                        entry.request_body_preview = Some(text);
                    }
                    if include_body_sample_b64 {
                        entry.request_body_sample_b64 = sample_b64;
                    }
                } else if direction == "response" {
                    if let Some(bytes) = body_bytes {
                        entry.response_body_bytes = Some(bytes);
                        if entry.response_size_bytes.is_none() {
                            entry.response_size_bytes = Some(bytes);
                        }
                    }
                    if let Some(text) = preview {
                        entry.response_body_preview = Some(text);
                    }
                    if include_body_sample_b64 {
                        entry.response_body_sample_b64 = sample_b64;
                    }
                    if let Some(status) = response_status {
                        entry.status = Some(status);
                    }
                }
            }
            _ => {}
        }
    }

    Ok((next_seq, scanned, by_key.into_values().collect::<Vec<_>>()))
}

fn parse_structured_payload(line: &str) -> Option<Map<String, Value>> {
    let marker = line.find("CRAB_JSON ")?;
    let json_text = line[(marker + "CRAB_JSON ".len())..].trim();
    if json_text.is_empty() {
        return None;
    }

    let value: Value = serde_json::from_str(json_text).ok()?;
    value.as_object().cloned()
}

fn object_string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    let value = object.get(key)?;
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

fn object_u64_field(object: &Map<String, Value>, key: &str) -> Option<u64> {
    let value = object.get(key)?;
    value_to_u64(value)
}

fn object_u16_field(object: &Map<String, Value>, key: &str) -> Option<u16> {
    let value = object.get(key)?;
    value_to_u64(value).and_then(|raw| u16::try_from(raw).ok())
}

fn object_f64_field(object: &Map<String, Value>, key: &str) -> Option<f64> {
    let value = object.get(key)?;
    value_to_f64(value)
}

fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_i64()
                .and_then(|signed| u64::try_from(signed).ok())
        }),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn decode_base64_to_text(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(String::new());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn decode_body_preview(sample_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(sample_b64)
        .ok()?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    Some(truncate_chars(&text, TRAFFIC_BODY_PREVIEW_MAX_CHARS))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut output = String::with_capacity(max_chars + 16);
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        output.push(ch);
    }
    output.push_str("...(truncated)");
    output
}

fn tool_success(payload: Value) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": payload
    })
}

fn tool_error(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

fn ensure_allowed_keys(args: &Map<String, Value>, allowed_keys: &[&str]) -> Result<()> {
    let allowed = allowed_keys.iter().copied().collect::<HashSet<_>>();
    for key in args.keys() {
        if !allowed.contains(key.as_str()) {
            bail!("unknown argument: {key}");
        }
    }
    Ok(())
}

fn arg_str_required(args: &Map<String, Value>, key: &str) -> Result<String> {
    arg_str(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_str(args: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("{key} must be a string"),
    }
}

fn arg_bool_required(args: &Map<String, Value>, key: &str) -> Result<bool> {
    arg_bool(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_bool(args: &Map<String, Value>, key: &str) -> Result<Option<bool>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => bail!("{key} must be a boolean"),
    }
}

fn arg_u64_required(args: &Map<String, Value>, key: &str) -> Result<u64> {
    arg_u64(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_string_vec_required(args: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    arg_string_vec(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_string_vec(args: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut result = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Value::String(text) => result.push(text.clone()),
                    _ => bail!("{key} must be an array of strings"),
                }
            }
            Ok(Some(result))
        }
        Some(_) => bail!("{key} must be an array of strings"),
    }
}

fn arg_u64(args: &Map<String, Value>, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("{key} must be an unsigned integer")),
        Some(_) => bail!("{key} must be an unsigned integer"),
    }
}

fn arg_i64(args: &Map<String, Value>, key: &str) -> Result<Option<i64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("{key} must be an integer")),
        Some(_) => bail!("{key} must be an integer"),
    }
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

fn read_framed_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;
    let mut saw_header_line = false;

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .context("failed to read frame header line")?;
        if read == 0 {
            if !saw_header_line {
                return Ok(None);
            }
            bail!("unexpected EOF while reading frame headers");
        }
        saw_header_line = true;

        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid frame header: {line}"))?;
        if name.eq_ignore_ascii_case("Content-Length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("invalid Content-Length: {}", value.trim()))?;
            content_length = Some(parsed);
        }
    }

    let length = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .with_context(|| format!("failed to read frame payload ({length} bytes)"))?;

    let value: Value = serde_json::from_slice(&payload).context("failed to parse JSON payload")?;
    Ok(Some(value))
}

fn write_framed_message<W: Write>(writer: &mut W, message: &Value) -> Result<()> {
    let body = serde_json::to_vec(message).context("failed to serialize JSON response")?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())
        .context("failed to write frame header")?;
    writer
        .write_all(&body)
        .context("failed to write frame payload")?;
    writer.flush().context("failed to flush frame output")?;
    Ok(())
}

fn default_daemon_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to resolve current executable path")?;
    let sibling = exe.with_file_name("crabd");
    if sibling.exists() {
        return Ok(sibling);
    }

    if let Some(dir) = exe.parent() {
        let candidate = dir.join("crabd");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Ok(Path::new("crabd").to_path_buf())
}
