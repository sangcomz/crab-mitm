use std::collections::{HashSet, VecDeque};
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tracing::info;
use uuid::Uuid;

use crate::ca::CertificateAuthority;
use crate::ipc::{
    AUTH_FAILED, HandshakeParams, HandshakeResult, INTERNAL_ERROR, INVALID_PARAMS, IO_ERROR,
    LogRecord, LogsTailResult, METHOD_NOT_FOUND, PERMISSION_DENIED, PRINCIPAL_MISMATCH,
    PROTOCOL_VERSION, RpcRequest, RpcResponse, SESSION_EXPIRED, STATE_ERROR, param_as_bool,
    param_as_i64, param_as_str, param_as_string_vec, param_as_u64, parse_params_map,
};
use crate::proxy::{self, ClientAccessConfig, InspectConfig, ThrottleConfig, TransparentConfig};
use crate::rules::{
    AllowRule, MapLocalRule, MapRemoteRule, MapSource, Matcher, Rules, StatusRewriteRule,
};

const LOG_BUFFER_LIMIT: usize = 10_000;
const APP_BUNDLE_ID: &str = "com.sangcomz.CrabProxyMacApp";
const CLI_BUNDLE_ID: &str = "com.sangcomz.crabctl";
const MCP_BUNDLE_ID: &str = "com.sangcomz.crab-mcp";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct DaemonOptions {
    pub socket_path: Option<PathBuf>,
    pub run_dir: Option<PathBuf>,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            socket_path: None,
            run_dir: None,
        }
    }
}

#[derive(Debug, Clone)]
struct RunPaths {
    run_dir: PathBuf,
    socket_path: PathBuf,
    app_token_path: PathBuf,
    cli_token_path: PathBuf,
    mcp_token_path: PathBuf,
}

impl RunPaths {
    fn resolve(options: DaemonOptions) -> Result<Self> {
        let run_dir = if let Some(path) = options.run_dir {
            path
        } else {
            default_run_dir()?
        };
        let socket_path = options
            .socket_path
            .unwrap_or_else(|| run_dir.join("crabd.sock"));
        Ok(Self {
            app_token_path: run_dir.join("app.token"),
            cli_token_path: run_dir.join("cli.token"),
            mcp_token_path: run_dir.join("mcp.token"),
            run_dir,
            socket_path,
        })
    }

    fn prepare(&self) -> Result<()> {
        std::fs::create_dir_all(&self.run_dir)
            .with_context(|| format!("failed to create run dir: {}", self.run_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.run_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| {
                    format!(
                        "failed to set run dir permissions: {}",
                        self.run_dir.display()
                    )
                })?;
        }

        if self.socket_path.exists() {
            match std::fs::remove_file(&self.socket_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "failed to remove stale socket: {}",
                            self.socket_path.display()
                        )
                    });
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenPayload {
    aud: String,
    scopes: Vec<String>,
    iat: i64,
    jti: String,
}

#[derive(Debug)]
struct AuthState {
    hmac_key: [u8; 32],
}

#[derive(Debug, Clone)]
struct AuthManager {
    paths: RunPaths,
    inner: Arc<RwLock<AuthState>>,
}

impl AuthManager {
    fn new(paths: RunPaths) -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self {
            paths,
            inner: Arc::new(RwLock::new(AuthState { hmac_key: key })),
        }
    }

    fn write_token_files(&self) -> Result<()> {
        let app = TokenPayload {
            aud: "app".to_string(),
            scopes: vec![
                "read".to_string(),
                "rules.write".to_string(),
                "control".to_string(),
                "admin".to_string(),
            ],
            iat: now_unix_seconds(),
            jti: Uuid::new_v4().to_string(),
        };
        let cli = TokenPayload {
            aud: "cli".to_string(),
            scopes: vec![
                "read".to_string(),
                "rules.write".to_string(),
                "control".to_string(),
                "admin".to_string(),
            ],
            iat: now_unix_seconds(),
            jti: Uuid::new_v4().to_string(),
        };
        let mcp = TokenPayload {
            aud: "mcp".to_string(),
            scopes: vec!["read".to_string(), "rules.write".to_string()],
            iat: now_unix_seconds(),
            jti: Uuid::new_v4().to_string(),
        };

        write_private_file(&self.paths.app_token_path, self.encode_token(&app).as_bytes())?;
        write_private_file(&self.paths.cli_token_path, self.encode_token(&cli).as_bytes())?;
        write_private_file(&self.paths.mcp_token_path, self.encode_token(&mcp).as_bytes())?;

        Ok(())
    }

    fn rotate_tokens(&self) -> Result<()> {
        {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| anyhow::anyhow!("auth lock poisoned"))?;
            rand::rng().fill_bytes(&mut guard.hmac_key);
        }
        self.write_token_files()
    }

    fn decode_and_verify(&self, token: &str) -> Result<TokenPayload> {
        let (payload_b64, signature_b64) = token
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid token format"))?;

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .context("invalid token payload")?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .context("invalid token signature")?;

        let expected_sig = {
            let guard = self
                .inner
                .read()
                .map_err(|_| anyhow::anyhow!("auth lock poisoned"))?;
            sign_hmac(&guard.hmac_key, &payload_bytes)?
        };
        if expected_sig != signature {
            anyhow::bail!("token signature mismatch");
        }

        let payload: TokenPayload =
            serde_json::from_slice(&payload_bytes).context("invalid token payload JSON")?;
        Ok(payload)
    }

    fn encode_token(&self, payload: &TokenPayload) -> String {
        let payload_bytes = serde_json::to_vec(payload).expect("token payload JSON serialization");
        let signature = {
            let guard = self.inner.read().expect("auth lock");
            sign_hmac(&guard.hmac_key, &payload_bytes).expect("token signing")
        };
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_bytes);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
        format!("{payload_b64}.{sig_b64}")
    }
}

#[derive(Debug, Clone)]
struct Session {
    id: String,
    principal: String,
    scopes: HashSet<String>,
    epoch: u64,
}

#[derive(Debug, Clone)]
struct RuntimeConfig {
    listen_addr: String,
    inspect: InspectConfig,
    throttle: ThrottleConfig,
    client_access: ClientAccessConfig,
    transparent: TransparentConfig,
    ca_cert_path: Option<PathBuf>,
    ca_key_path: Option<PathBuf>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8888".to_string(),
            inspect: InspectConfig {
                enabled: true,
                sample_bytes: 16 * 1024,
                spool: false,
                spool_dir: None,
                spool_max_bytes: 100 * 1024 * 1024,
            },
            throttle: ThrottleConfig::default(),
            client_access: ClientAccessConfig::default(),
            transparent: TransparentConfig::default(),
            ca_cert_path: None,
            ca_key_path: None,
        }
    }
}

struct DaemonState {
    config: RuntimeConfig,
    rules: Rules,
    running: bool,
    shutdown_tx: Option<watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    logs: VecDeque<LogRecord>,
    next_log_seq: u64,
    token_epoch: u64,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            config: RuntimeConfig::default(),
            rules: Rules::default(),
            running: false,
            shutdown_tx: None,
            task: None,
            logs: VecDeque::new(),
            next_log_seq: 1,
            token_epoch: 1,
        }
    }

    fn push_log(&mut self, level: u8, message: String) {
        let record = LogRecord {
            seq: self.next_log_seq,
            level,
            message,
            ts_unix_ms: now_unix_millis(),
        };
        self.next_log_seq = self.next_log_seq.saturating_add(1);
        self.logs.push_back(record);
        if self.logs.len() > LOG_BUFFER_LIMIT {
            let overflow = self.logs.len() - LOG_BUFFER_LIMIT;
            for _ in 0..overflow {
                let _ = self.logs.pop_front();
            }
        }
    }
}

pub async fn run_forever(options: DaemonOptions) -> Result<()> {
    let paths = RunPaths::resolve(options)?;
    paths.prepare()?;

    let auth = AuthManager::new(paths.clone());
    auth.write_token_files()
        .context("failed to write token files")?;

    let shared = Arc::new(Mutex::new(DaemonState::new()));

    let (log_tx, mut log_rx) = mpsc::unbounded_channel::<String>();
    proxy::set_structured_log_callback(Some(Arc::new(move |line: String| {
        let _ = log_tx.send(line);
    })));

    let state_for_logs = Arc::clone(&shared);
    tokio::spawn(async move {
        while let Some(line) = log_rx.recv().await {
            let mut guard = state_for_logs.lock().await;
            guard.push_log(2, line);
        }
    });

    let listener = UnixListener::bind(&paths.socket_path)
        .with_context(|| format!("failed to bind socket: {}", paths.socket_path.display()))?;

    info!(socket = %paths.socket_path.display(), "crabd listening");

    loop {
        let (stream, _) = listener.accept().await.context("accept failed")?;
        let state = Arc::clone(&shared);
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state, auth).await {
                tracing::debug!(error = %err, "connection closed with error");
            }
        });
    }
}

async fn handle_connection(
    stream: UnixStream,
    state: Arc<Mutex<DaemonState>>,
    auth: AuthManager,
) -> Result<()> {
    let peer = stream.peer_cred().context("failed to read peer credentials")?;
    let peer_uid = peer.uid();
    let peer_pid = peer.pid();

    let daemon_uid = unsafe { libc::geteuid() };
    if peer_uid != daemon_uid {
        anyhow::bail!("peer uid mismatch: {peer_uid} != {daemon_uid}");
    }

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut session: Option<Session> = None;

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .await
            .context("failed to read request")?;
        if read == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: RpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(err) => {
                let response = RpcResponse::failure(None, INVALID_PARAMS, format!("invalid JSON: {err}"));
                write_json_line(&mut write_half, &response).await?;
                continue;
            }
        };

        let id = req.id.clone();
        let response = match dispatch_request(&req, &state, &auth, &mut session, peer_pid).await {
            Ok(value) => RpcResponse::success(id, value),
            Err((code, message)) => RpcResponse::failure(id, code, message),
        };

        write_json_line(&mut write_half, &response).await?;
    }

    Ok(())
}

async fn dispatch_request(
    req: &RpcRequest,
    state: &Arc<Mutex<DaemonState>>,
    auth: &AuthManager,
    session: &mut Option<Session>,
    peer_pid: Option<i32>,
) -> std::result::Result<Value, (i32, String)> {
    if req.jsonrpc != "2.0" {
        return Err((INVALID_PARAMS, "jsonrpc must be 2.0".to_string()));
    }

    if req.method == "system.handshake" {
        return handle_handshake(req, state, auth, session, peer_pid).await;
    }

    let Some(active) = session.as_ref() else {
        return Err((AUTH_FAILED, "session not established".to_string()));
    };

    let epoch = { state.lock().await.token_epoch };
    if active.epoch != epoch {
        return Err((
            SESSION_EXPIRED,
            "session expired after token rotation".to_string(),
        ));
    }

    if let Some(scope) = required_scope(&req.method)
        && !active.scopes.contains(scope)
    {
        return Err((PERMISSION_DENIED, format!("scope '{scope}' required")));
    }

    let params = match parse_params_map(&req.params) {
        Ok(params) => params,
        Err(message) => return Err((INVALID_PARAMS, message)),
    };

    let result = match req.method.as_str() {
        "system.ping" => Ok(json!({"pong": true})),
        "system.version" => Ok(json!({"engine": env!("CARGO_PKG_VERSION"), "protocol": PROTOCOL_VERSION})),
        "system.rotate_token" => {
            if let Err(err) = auth.rotate_tokens() {
                Err((IO_ERROR, format!("failed to rotate token: {err:#}")))
            } else {
                let mut guard = state.lock().await;
                guard.token_epoch = guard.token_epoch.saturating_add(1);
                Ok(json!({"rotated": true, "reconnect_required": true}))
            }
        }
        "proxy.start" => start_proxy(state).await,
        "proxy.stop" => stop_proxy(state).await,
        "proxy.status" => {
            let running = state.lock().await.running;
            Ok(json!({"status": if running {"running"} else {"stopped"}}))
        }
        "engine.set_listen_addr" => {
            let listen = param_as_str(&params, "listen_addr")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "listen_addr is required".to_string()))?;
            if std::net::SocketAddr::from_str(listen).is_err() {
                return Err((INVALID_PARAMS, "listen_addr must be host:port".to_string()));
            }
            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change listen_addr while running".to_string()))
            } else {
                guard.config.listen_addr = listen.to_string();
                Ok(json!({"ok": true}))
            }
        }
        "engine.load_ca" => {
            let cert = param_as_str(&params, "cert_path")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "cert_path is required".to_string()))?;
            let key = param_as_str(&params, "key_path")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "key_path is required".to_string()))?;

            let cert_path = PathBuf::from(cert);
            let key_path = PathBuf::from(key);
            if !cert_path.exists() || !key_path.exists() {
                return Err((IO_ERROR, "CA cert/key path does not exist".to_string()));
            }

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot load CA while running".to_string()))
            } else {
                guard.config.ca_cert_path = Some(cert_path);
                guard.config.ca_key_path = Some(key_path);
                Ok(json!({"ok": true}))
            }
        }
        "engine.set_inspect_enabled" => {
            let enabled = param_as_bool(&params, "enabled")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "enabled is required".to_string()))?;
            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change inspect while running".to_string()))
            } else {
                guard.config.inspect.enabled = enabled;
                Ok(json!({"ok": true}))
            }
        }
        "engine.set_transparent" => {
            let enabled = param_as_bool(&params, "enabled")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(false);
            let port = param_as_u64(&params, "listen_port")
                .map_err(|e| (INVALID_PARAMS, e))?
                .map(|value| value as u16)
                .unwrap_or(8889);
            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change transparent mode while running".to_string()))
            } else {
                guard.config.transparent.enabled = enabled;
                guard.config.transparent.listen_port = port;
                Ok(json!({"ok": true}))
            }
        }
        "engine.set_client_allowlist" => {
            let enabled = param_as_bool(&params, "enabled")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(false);
            let ips = param_as_string_vec(&params, "ips")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or_default();

            let parsed = match parse_ip_allowlist(&ips) {
                Ok(v) => v,
                Err(err) => return Err((INVALID_PARAMS, err)),
            };

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change allowlist while running".to_string()))
            } else {
                guard.config.client_access.enforce_allowlist = enabled;
                guard.config.client_access.allowed_client_ips = parsed;
                Ok(json!({"ok": true}))
            }
        }
        "engine.set_throttle" => {
            let enabled = param_as_bool(&params, "enabled")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(false);
            let latency_ms = param_as_u64(&params, "latency_ms")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(0);
            let downstream = param_as_u64(&params, "downstream_bps")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(0);
            let upstream = param_as_u64(&params, "upstream_bps")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(0);
            let only_selected_hosts = param_as_bool(&params, "only_selected_hosts")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(false);
            let selected_hosts = param_as_string_vec(&params, "selected_hosts")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or_default()
                .into_iter()
                .map(AllowRule::new)
                .collect::<Vec<_>>();

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change throttle while running".to_string()))
            } else {
                guard.config.throttle.enabled = enabled;
                guard.config.throttle.latency_ms = latency_ms;
                guard.config.throttle.downstream_bytes_per_sec = downstream;
                guard.config.throttle.upstream_bytes_per_sec = upstream;
                guard.config.throttle.only_selected_hosts = only_selected_hosts;
                guard.config.throttle.selected_hosts = selected_hosts;
                Ok(json!({"ok": true}))
            }
        }
        "engine.rules_clear" => {
            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change rules while running".to_string()))
            } else {
                guard.rules = Rules::default();
                Ok(json!({"ok": true}))
            }
        }
        "engine.rules_add_allow" => {
            let matcher = param_as_str(&params, "matcher")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "matcher is required".to_string()))?;
            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change rules while running".to_string()))
            } else {
                guard.rules.allowlist.push(AllowRule::new(matcher));
                Ok(json!({"ok": true}))
            }
        }
        "engine.rules_add_map_local_file" => {
            let matcher = param_as_str(&params, "matcher")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "matcher is required".to_string()))?;
            let file_path = param_as_str(&params, "file_path")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "file_path is required".to_string()))?;
            let status_code = param_as_u64(&params, "status_code")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(200);
            let content_type = param_as_str(&params, "content_type")
                .map_err(|e| (INVALID_PARAMS, e))?
                .map(|v| v.to_string());

            let status = match http::StatusCode::from_u16(status_code as u16) {
                Ok(status) => status,
                Err(_) => {
                    return Err((
                        INVALID_PARAMS,
                        "status_code must be valid HTTP status".to_string(),
                    ))
                }
            };

            let path = PathBuf::from(file_path);
            if !path.exists() {
                return Err((IO_ERROR, "map_local file not found".to_string()));
            }

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change rules while running".to_string()))
            } else {
                guard.rules.map_local.push(MapLocalRule {
                    matcher: Matcher::new(matcher),
                    source: MapSource::File(path),
                    status,
                    content_type,
                });
                Ok(json!({"ok": true}))
            }
        }
        "engine.rules_add_map_local_text" => {
            let matcher = param_as_str(&params, "matcher")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "matcher is required".to_string()))?;
            let text = param_as_str(&params, "text")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "text is required".to_string()))?;
            let status_code = param_as_u64(&params, "status_code")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(200);
            let content_type = param_as_str(&params, "content_type")
                .map_err(|e| (INVALID_PARAMS, e))?
                .map(|v| v.to_string());

            let status = match http::StatusCode::from_u16(status_code as u16) {
                Ok(status) => status,
                Err(_) => {
                    return Err((
                        INVALID_PARAMS,
                        "status_code must be valid HTTP status".to_string(),
                    ))
                }
            };

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change rules while running".to_string()))
            } else {
                guard.rules.map_local.push(MapLocalRule {
                    matcher: Matcher::new(matcher),
                    source: MapSource::Text(text.to_string()),
                    status,
                    content_type,
                });
                Ok(json!({"ok": true}))
            }
        }
        "engine.rules_add_map_remote" => {
            let matcher = param_as_str(&params, "matcher")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "matcher is required".to_string()))?;
            let destination = param_as_str(&params, "destination")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "destination is required".to_string()))?;

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change rules while running".to_string()))
            } else {
                guard.rules.map_remote.push(MapRemoteRule {
                    matcher: Matcher::new(matcher),
                    destination: destination.to_string(),
                });
                Ok(json!({"ok": true}))
            }
        }
        "engine.rules_add_status_rewrite" => {
            let matcher = param_as_str(&params, "matcher")
                .map_err(|e| (INVALID_PARAMS, e))?
                .ok_or_else(|| (INVALID_PARAMS, "matcher is required".to_string()))?;
            let to_status = param_as_u64(&params, "to_status_code")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(200);
            let from_status_raw = param_as_i64(&params, "from_status_code")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(-1);

            let to = match http::StatusCode::from_u16(to_status as u16) {
                Ok(status) => status,
                Err(_) => {
                    return Err((
                        INVALID_PARAMS,
                        "to_status_code must be valid HTTP status".to_string(),
                    ))
                }
            };
            let from = if from_status_raw < 0 {
                None
            } else {
                match http::StatusCode::from_u16(from_status_raw as u16) {
                    Ok(status) => Some(status),
                    Err(_) => {
                        return Err((
                            INVALID_PARAMS,
                            "from_status_code must be -1 or valid HTTP status".to_string(),
                        ))
                    }
                }
            };

            let mut guard = state.lock().await;
            if guard.running {
                Err((STATE_ERROR, "cannot change rules while running".to_string()))
            } else {
                guard.rules.status_rewrite.push(StatusRewriteRule {
                    matcher: Matcher::new(matcher),
                    from,
                    to,
                });
                Ok(json!({"ok": true}))
            }
        }
        "logs.tail" => {
            let after_seq = param_as_u64(&params, "after_seq")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(0);
            let limit = param_as_u64(&params, "limit")
                .map_err(|e| (INVALID_PARAMS, e))?
                .unwrap_or(200)
                .min(1000) as usize;

            let guard = state.lock().await;
            let records = guard
                .logs
                .iter()
                .filter(|record| record.seq > after_seq)
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            let next_seq = records.last().map(|record| record.seq).unwrap_or(after_seq);

            Ok(serde_json::to_value(LogsTailResult { next_seq, records }).expect("serialize logs.tail"))
        }
        "daemon.doctor" => {
            let guard = state.lock().await;
            Ok(json!({
                "socket": "ok",
                "state_db": "ok",
                "helper_xpc": "ok",
                "ca": if guard.config.ca_cert_path.is_some() && guard.config.ca_key_path.is_some() { "loaded" } else { "missing" },
                "launch_agent": "unmanaged",
                "principal_verification": "enabled",
                "running": guard.running,
            }))
        }
        _ => Err((METHOD_NOT_FOUND, format!("unknown method: {}", req.method))),
    };

    result
}

fn required_scope(method: &str) -> Option<&'static str> {
    match method {
        "system.handshake" => None,
        "system.ping" | "system.version" | "proxy.status" | "logs.tail" | "daemon.doctor" => {
            Some("read")
        }
        "proxy.start" | "proxy.stop" => Some("control"),
        "engine.set_listen_addr"
        | "engine.load_ca"
        | "engine.set_inspect_enabled"
        | "engine.set_throttle"
        | "engine.set_client_allowlist"
        | "engine.set_transparent" => Some("control"),
        "engine.rules_clear"
        | "engine.rules_add_allow"
        | "engine.rules_add_map_local_file"
        | "engine.rules_add_map_local_text"
        | "engine.rules_add_map_remote"
        | "engine.rules_add_status_rewrite" => Some("rules.write"),
        "system.rotate_token" => Some("admin"),
        _ => None,
    }
}

async fn handle_handshake(
    req: &RpcRequest,
    state: &Arc<Mutex<DaemonState>>,
    auth: &AuthManager,
    session: &mut Option<Session>,
    peer_pid: Option<i32>,
) -> std::result::Result<Value, (i32, String)> {
    let params: HandshakeParams = serde_json::from_value(req.params.clone())
        .map_err(|err| (INVALID_PARAMS, format!("invalid handshake params: {err}")))?;

    if params.protocol_version != PROTOCOL_VERSION {
        return Err((
            INVALID_PARAMS,
            format!(
                "protocol_version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, params.protocol_version
            ),
        ));
    }

    let token = auth
        .decode_and_verify(&params.token)
        .map_err(|err| (AUTH_FAILED, format!("token verify failed: {err}")))?;

    let pid = peer_pid.ok_or_else(|| (AUTH_FAILED, "missing peer pid".to_string()))?;
    if pid <= 0 {
        return Err((AUTH_FAILED, "invalid peer pid".to_string()));
    }
    let principal = verify_principal(pid as u32)
        .map_err(|err| (AUTH_FAILED, format!("principal verification failed: {err}")))?;

    if token.aud != principal {
        return Err((
            PRINCIPAL_MISMATCH,
            format!(
                "token aud '{}' does not match principal '{}'",
                token.aud, principal
            ),
        ));
    }

    let epoch = state.lock().await.token_epoch;

    let new_session = Session {
        id: Uuid::new_v4().to_string(),
        principal: principal.clone(),
        scopes: token.scopes.iter().cloned().collect::<HashSet<_>>(),
        epoch,
    };

    let result = HandshakeResult {
        session_id: new_session.id.clone(),
        protocol_version: PROTOCOL_VERSION,
        principal: new_session.principal.clone(),
        scopes: token.scopes,
        principal_verified: true,
    };

    *session = Some(new_session);

    serde_json::to_value(result).map_err(|err| {
        (
            INTERNAL_ERROR,
            format!("failed to serialize handshake result: {err}"),
        )
    })
}

async fn start_proxy(state: &Arc<Mutex<DaemonState>>) -> std::result::Result<Value, (i32, String)> {
    let mut guard = state.lock().await;
    if guard.running {
        return Err((STATE_ERROR, "proxy already running".to_string()));
    }

    let config = guard.config.clone();
    let rules = guard.rules.clone();

    let ca = match (&config.ca_cert_path, &config.ca_key_path) {
        (Some(cert), Some(key)) => {
            match CertificateAuthority::from_pem_files(cert, key)
                .with_context(|| format!("failed to load CA cert={} key={}", cert.display(), key.display()))
            {
                Ok(ca) => Some(Arc::new(ca)),
                Err(err) => return Err((IO_ERROR, err.to_string())),
            }
        }
        (None, None) => None,
        _ => {
            return Err((
                INVALID_PARAMS,
                "CA cert/key must be configured together".to_string(),
            ));
        }
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let state_for_task = Arc::clone(state);

    let task = tokio::spawn(async move {
        let result = proxy::run_with_shutdown(
            &config.listen_addr,
            ca,
            Arc::new(rules),
            Arc::new(config.inspect),
            Arc::new(config.throttle),
            Arc::new(config.client_access),
            Some(config.transparent),
            shutdown_rx,
            Some(ready_tx),
        )
        .await;

        let mut guard = state_for_task.lock().await;
        guard.running = false;
        guard.shutdown_tx = None;
        guard.task = None;
        result
    });

    guard.running = true;
    guard.shutdown_tx = Some(shutdown_tx);
    guard.task = Some(task);
    drop(guard);

    let startup = tokio::time::timeout(std::time::Duration::from_secs(3), ready_rx).await;
    match startup {
        Ok(Ok(Ok(()))) => Ok(json!({"status": "running"})),
        Ok(Ok(Err(message))) => {
            let cleanup = stop_proxy(state).await.err().map(|(_, m)| m);
            let mut details = format!("proxy startup failed: {message}");
            if let Some(cleanup_msg) = cleanup {
                details.push_str(&format!("; cleanup failed: {cleanup_msg}"));
            }
            Err((IO_ERROR, details))
        }
        Ok(Err(_)) => {
            let cleanup = stop_proxy(state).await.err().map(|(_, m)| m);
            let mut details = "proxy startup channel closed before ready".to_string();
            if let Some(cleanup_msg) = cleanup {
                details.push_str(&format!("; cleanup failed: {cleanup_msg}"));
            }
            Err((IO_ERROR, details))
        }
        Err(_) => {
            let cleanup = stop_proxy(state).await.err().map(|(_, m)| m);
            let mut details = "proxy startup timed out".to_string();
            if let Some(cleanup_msg) = cleanup {
                details.push_str(&format!("; cleanup failed: {cleanup_msg}"));
            }
            Err((IO_ERROR, details))
        }
    }
}

async fn stop_proxy(state: &Arc<Mutex<DaemonState>>) -> std::result::Result<Value, (i32, String)> {
    let (shutdown_tx, join_handle) = {
        let mut guard = state.lock().await;
        if !guard.running {
            return Ok(json!({"status": "stopped"}));
        }
        guard.running = false;
        (guard.shutdown_tx.take(), guard.task.take())
    };

    if let Some(tx) = shutdown_tx {
        let _ = tx.send(true);
    }

    if let Some(handle) = join_handle {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err((IO_ERROR, format!("proxy task failed: {err:#}"))),
            Err(err) => return Err((IO_ERROR, format!("proxy join failed: {err}"))),
        }
    }

    Ok(json!({"status": "stopped"}))
}

fn verify_principal(peer_pid: u32) -> Result<String> {
    let binary_path = executable_path_for_pid(peer_pid as i32)
        .with_context(|| format!("failed to resolve executable path for pid {peer_pid}"))?;

    #[cfg(debug_assertions)]
    {
        if let Some(fallback) = debug_principal_fallback_for_binary(&binary_path) {
            return Ok(fallback.to_string());
        }
    }

    let identifier = match codesign_identifier(&binary_path) {
        Ok(identifier) => identifier,
        Err(err) => return Err(err)
            .with_context(|| format!("failed to inspect code signature: {}", binary_path.display())),
    };

    let principal = match identifier.as_str() {
        APP_BUNDLE_ID => "app",
        CLI_BUNDLE_ID => "cli",
        MCP_BUNDLE_ID => "mcp",
        _ => anyhow::bail!("identifier not mapped: {identifier}"),
    };

    Ok(principal.to_string())
}

#[cfg(debug_assertions)]
fn debug_principal_fallback_for_binary(path: &Path) -> Option<&'static str> {
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if stem.eq_ignore_ascii_case("crabctl") {
        return Some("cli");
    }
    if stem.eq_ignore_ascii_case("crab-mcp") {
        return Some("mcp");
    }
    if stem.eq_ignore_ascii_case("CrabProxyMacApp")
        || stem.eq_ignore_ascii_case("Crab Proxy")
        || stem.eq_ignore_ascii_case("CrabProxy")
    {
        return Some("app");
    }
    None
}

fn executable_path_for_pid(pid: i32) -> Result<PathBuf> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let size = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len() as u32,
        )
    };
    if size <= 0 {
        return Err(std::io::Error::last_os_error()).context("proc_pidpath failed");
    }

    let text = CStr::from_bytes_until_nul(&buffer)
        .context("invalid executable path bytes")?
        .to_string_lossy()
        .to_string();

    Ok(PathBuf::from(text))
}

fn codesign_identifier(path: &Path) -> Result<String> {
    let output = Command::new("/usr/bin/codesign")
        .arg("-dv")
        .arg("--verbose=4")
        .arg(path)
        .output()
        .with_context(|| format!("failed to execute codesign: {}", path.display()))?;

    if !output.status.success() {
        anyhow::bail!(
            "codesign failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stderr_text = String::from_utf8_lossy(&output.stderr);
    for line in stderr_text.lines() {
        if let Some(identifier) = line.strip_prefix("Identifier=") {
            let value = identifier.trim();
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }

    anyhow::bail!("codesign output missing Identifier field")
}

fn parse_ip_allowlist(raw: &[String]) -> std::result::Result<Vec<std::net::IpAddr>, String> {
    let mut parsed = Vec::with_capacity(raw.len());
    for value in raw {
        let ip = value
            .trim()
            .parse::<std::net::IpAddr>()
            .map_err(|_| format!("invalid IP address: {value}"))?;
        parsed.push(proxy::normalize_client_ip(ip));
    }
    Ok(parsed)
}

async fn write_json_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
) -> Result<()> {
    let payload = serde_json::to_vec(response).context("failed to serialize response")?;
    writer.write_all(&payload).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn sign_hmac(key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).context("invalid HMAC key")?;
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to open file: {}", path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("failed to write file: {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 0600: {}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
            .with_context(|| format!("failed to write file: {}", path.display()))
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn default_run_dir() -> Result<PathBuf> {
    let base = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("failed to resolve home dir"))?;
    Ok(base
        .join("Library")
        .join("Application Support")
        .join("CrabProxy")
        .join("run"))
}

pub fn default_socket_path() -> Result<PathBuf> {
    Ok(default_run_dir()?.join("crabd.sock"))
}

pub fn default_token_path_for_principal(principal: &str) -> Result<PathBuf> {
    let run_dir = default_run_dir()?;
    let file = match principal {
        "app" => "app.token",
        "cli" => "cli.token",
        "mcp" => "mcp.token",
        _ => return Err(anyhow::anyhow!("unknown principal: {principal}")),
    };
    Ok(run_dir.join(file))
}

pub async fn send_rpc(
    socket_path: &Path,
    token: &str,
    client_type: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect daemon socket: {}", socket_path.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let handshake_req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "system.handshake".to_string(),
        params: serde_json::to_value(HandshakeParams {
            protocol_version: PROTOCOL_VERSION,
            token: token.to_string(),
            client_type: Some(client_type.to_string()),
        })
        .expect("serialize handshake params"),
    };

    send_request(&mut write_half, &handshake_req).await?;
    let handshake_resp = read_response(&mut reader).await?;
    if let Some(error) = handshake_resp.error {
        anyhow::bail!("handshake failed ({}): {}", error.code, error.message);
    }

    let request = RpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(2)),
        method: method.to_string(),
        params,
    };
    send_request(&mut write_half, &request).await?;

    let response = read_response(&mut reader).await?;
    if let Some(error) = response.error {
        anyhow::bail!("rpc failed ({}): {}", error.code, error.message);
    }

    Ok(response.result.unwrap_or(Value::Null))
}

async fn send_request<W: AsyncWrite + Unpin>(stream: &mut W, req: &RpcRequest) -> Result<()> {
    let payload = serde_json::to_vec(req).context("failed to serialize request")?;
    stream
        .write_all(&payload)
        .await
        .context("failed to write request")?;
    stream
        .write_all(b"\n")
        .await
        .context("failed to write request delimiter")?;
    stream.flush().await.context("failed to flush request")?;
    Ok(())
}

async fn read_response<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<RpcResponse> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .context("failed to read response")?;
    if read == 0 {
        anyhow::bail!("daemon closed connection unexpectedly");
    }
    serde_json::from_str(line.trim()).context("failed to parse response JSON")
}

pub fn read_token_from_file(path: &Path) -> Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read token: {}", path.display()))?;
    let normalized = token.trim().to_string();
    if normalized.is_empty() {
        anyhow::bail!("token file is empty: {}", path.display());
    }
    Ok(normalized)
}

pub fn ensure_daemon_started(daemon_path: &Path, socket_path: &Path) -> Result<()> {
    if can_connect_socket(socket_path) {
        return Ok(());
    }

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    Command::new(daemon_path)
        .arg("serve")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn daemon: {}", daemon_path.display()))?;

    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(3) {
        if can_connect_socket(socket_path) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    anyhow::bail!("daemon socket did not appear: {}", socket_path.display())
}

fn can_connect_socket(socket_path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket_path).is_ok()
}
