use std::convert::Infallible;
use std::error::Error as StdError;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::RootCertStore;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::ca::CertificateAuthority;
use crate::rules::{AllowRule, MapSource, Rules};

mod cert_portal;
mod inspect;
mod response;
mod throttle;
pub mod transparent;

use cert_portal::maybe_handle_cert_portal;
use inspect::{InspectMeta, encode_headers_for_log, maybe_inspect_body};
use response::{apply_content_headers, text_response};
use throttle::{maybe_throttle_body, maybe_throttle_body_with_rate};
pub use transparent::TransparentConfig;

#[cfg(test)]
use cert_portal::{
    build_cert_portal_page, build_ios_mobileconfig, ca_cert_fingerprint_sha256, is_cert_portal_host,
};
#[cfg(test)]
use inspect::{BodyInspector, escape_for_log};

type BoxError = Box<dyn StdError + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, ProxyBody>;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
type StructuredLogCallback = Arc<dyn Fn(String) + Send + Sync + 'static>;
static STRUCTURED_LOG_CALLBACK: OnceLock<RwLock<Option<StructuredLogCallback>>> = OnceLock::new();

pub fn set_structured_log_callback(callback: Option<StructuredLogCallback>) {
    let store = STRUCTURED_LOG_CALLBACK.get_or_init(|| RwLock::new(None));
    if let Ok(mut guard) = store.write() {
        *guard = callback;
    }
}

#[derive(Clone, Debug)]
pub struct InspectConfig {
    pub enabled: bool,
    pub sample_bytes: usize,
    pub spool: bool,
    pub spool_dir: Option<PathBuf>,
    pub spool_max_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ThrottleConfig {
    pub enabled: bool,
    pub latency_ms: u64,
    pub downstream_bytes_per_sec: u64,
    pub upstream_bytes_per_sec: u64,
    pub only_selected_hosts: bool,
    pub selected_hosts: Vec<AllowRule>,
}

impl ThrottleConfig {
    fn has_throttle_limits(&self) -> bool {
        self.latency_ms > 0 || self.downstream_bytes_per_sec > 0 || self.upstream_bytes_per_sec > 0
    }

    fn matches_location(&self, scheme: &str, authority: &str) -> bool {
        if !self.only_selected_hosts {
            return true;
        }
        if self.selected_hosts.is_empty() {
            return false;
        }
        self.selected_hosts
            .iter()
            .any(|rule| rule.is_ssl_proxy_match(scheme, authority))
    }

    fn is_active_for(&self, scheme: &str, authority: &str) -> bool {
        self.enabled && self.has_throttle_limits() && self.matches_location(scheme, authority)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ClientAccessConfig {
    pub enforce_allowlist: bool,
    pub allowed_client_ips: Vec<IpAddr>,
}

pub fn normalize_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        value => value,
    }
}

#[derive(Clone)]
struct ProxyState {
    client: HttpClient,
    rules: Arc<Rules>,
    ca: Option<Arc<CertificateAuthority>>,
    inspect: Arc<InspectConfig>,
    throttle: Arc<ThrottleConfig>,
    plugin: Option<Arc<PluginRuntime>>,
    transparent: bool,
}

#[derive(Clone)]
struct RequestContext {
    default_scheme: &'static str,
    default_authority: Option<String>,
}

#[derive(Clone)]
struct PluginRuntime {
    hook_command: Arc<str>,
    timeout: Duration,
}

impl PluginRuntime {
    fn from_env() -> Option<Arc<Self>> {
        let raw = std::env::var("CRAB_PLUGIN_HOOK").ok()?;
        let command = raw.trim();
        if command.is_empty() {
            return None;
        }
        Some(Arc::new(Self {
            hook_command: Arc::from(command.to_string()),
            timeout: plugin_hook_timeout(),
        }))
    }

    fn emit(&self, topic: &'static str, payload: serde_json::Value) {
        let command = self.hook_command.clone();
        let timeout = self.timeout;
        let event_payload = json!({
            "source": "crab-mitm",
            "topic": topic,
            "payload": payload,
            "ts_unix_ms": unix_timestamp_ms(),
        });
        let payload_text = event_payload.to_string();
        tokio::spawn(async move {
            let join = tokio::task::spawn_blocking(move || {
                run_plugin_hook_command(command.as_ref(), payload_text.as_bytes())
            });
            match tokio::time::timeout(timeout, join).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(err))) => {
                    tracing::debug!(error = %err, "plugin hook failed");
                }
                Ok(Err(err)) => {
                    tracing::debug!(error = %err, "plugin hook task join failed");
                }
                Err(_) => {
                    tracing::debug!("plugin hook timed out");
                }
            }
        });
    }
}

pub async fn run(
    listen: &str,
    ca: Option<Arc<CertificateAuthority>>,
    rules: Arc<Rules>,
    inspect: Arc<InspectConfig>,
    throttle: Arc<ThrottleConfig>,
    client_access: Arc<ClientAccessConfig>,
    transparent: Option<TransparentConfig>,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    run_with_shutdown(
        listen,
        ca,
        rules,
        inspect,
        throttle,
        client_access,
        transparent,
        shutdown_rx,
        None,
    )
    .await
}

pub async fn run_with_shutdown(
    listen: &str,
    ca: Option<Arc<CertificateAuthority>>,
    rules: Arc<Rules>,
    inspect: Arc<InspectConfig>,
    throttle: Arc<ThrottleConfig>,
    client_access: Arc<ClientAccessConfig>,
    transparent: Option<TransparentConfig>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut ready_tx: Option<oneshot::Sender<std::result::Result<(), String>>>,
) -> Result<()> {
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            notify_startup_error(
                &mut ready_tx,
                format!("failed to bind listener {listen}: {err}"),
            );
            return Err(err).with_context(|| format!("failed to bind: {listen}"));
        }
    };

    let transparent_listener = match transparent.as_ref() {
        Some(cfg) if cfg.enabled => {
            let addr = format!("127.0.0.1:{}", cfg.listen_port);
            let tl = match TcpListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(err) => {
                    notify_startup_error(
                        &mut ready_tx,
                        format!("failed to bind transparent listener {addr}: {err}"),
                    );
                    return Err(err)
                        .with_context(|| format!("failed to bind transparent listener: {addr}"));
                }
            };
            tracing::info!(listen = %addr, "transparent proxy listening");
            Some(tl)
        }
        _ => None,
    };

    notify_startup_ready(&mut ready_tx);

    let plugin = PluginRuntime::from_env();
    if let Some(runtime) = plugin.as_ref() {
        tracing::info!(
            hook = %runtime.hook_command,
            timeout_ms = runtime.timeout.as_millis() as u64,
            "plugin hook enabled"
        );
    }

    if http3_observer_enabled() {
        let mut observer_shutdown = shutdown_rx.clone();
        let listen_addr = listen.to_string();
        let plugin_runtime = plugin.clone();
        tokio::spawn(async move {
            if let Err(err) =
                run_http3_udp_observer(&listen_addr, plugin_runtime, &mut observer_shutdown).await
            {
                tracing::warn!(error = %err, listen = %listen_addr, "HTTP/3 observer stopped");
            }
        });
    }

    let client = build_client()?;
    let forward_state = ProxyState {
        client: client.clone(),
        rules: rules.clone(),
        ca: ca.clone(),
        inspect: inspect.clone(),
        throttle: throttle.clone(),
        plugin: plugin.clone(),
        transparent: false,
    };
    let transparent_state = ProxyState {
        client,
        rules,
        ca,
        inspect,
        throttle,
        plugin,
        transparent: true,
    };

    let max_conn = max_connections();
    let semaphore = Arc::new(Semaphore::new(max_conn));
    tracing::info!(
        listen = %listen,
        max_connections = max_conn,
        lan_allowlist_enforced = client_access.enforce_allowlist,
        lan_allowlist_count = client_access.allowed_client_ips.len(),
        "proxy listening"
    );

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer) = res?;
                if !is_client_ip_allowed(peer, client_access.as_ref()) {
                    log_blocked_client(peer);
                    continue;
                }
                let permit = semaphore.clone().acquire_owned().await;
                let Ok(permit) = permit else { break; };
                let state = forward_state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve_client(stream, peer, state).await {
                        tracing::debug!(peer = %peer, error = %err, "connection ended");
                    }
                });
            }
            res = accept_transparent(&transparent_listener) => {
                if let Some((stream, peer)) = res? {
                    if !is_client_ip_allowed(peer, client_access.as_ref()) {
                        log_blocked_client(peer);
                        continue;
                    }
                    let permit = semaphore.clone().acquire_owned().await;
                    let Ok(permit) = permit else { break; };
                    let state = transparent_state.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(err) = serve_transparent_client(stream, peer, state).await {
                            tracing::debug!(peer = %peer, error = %err, "transparent connection ended");
                        }
                    });
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    tracing::info!("shutdown signal received");
                } else {
                    tracing::info!("shutdown channel closed");
                }
                break;
            }
        }
    }

    Ok(())
}

fn notify_startup_ready(ready_tx: &mut Option<oneshot::Sender<std::result::Result<(), String>>>) {
    if let Some(tx) = ready_tx.take() {
        let _ = tx.send(Ok(()));
    }
}

fn notify_startup_error(
    ready_tx: &mut Option<oneshot::Sender<std::result::Result<(), String>>>,
    message: String,
) {
    if let Some(tx) = ready_tx.take() {
        let _ = tx.send(Err(message));
    }
}

fn is_client_ip_allowed(peer: SocketAddr, client_access: &ClientAccessConfig) -> bool {
    if !client_access.enforce_allowlist {
        return true;
    }

    let ip = normalize_client_ip(peer.ip());
    if ip.is_loopback() {
        return true;
    }

    client_access
        .allowed_client_ips
        .iter()
        .copied()
        .map(normalize_client_ip)
        .any(|allowed| allowed == ip)
}

fn log_blocked_client(peer: SocketAddr) {
    let ip = normalize_client_ip(peer.ip());
    tracing::warn!(
        peer = %peer,
        ip = %ip,
        "LAN_ACCESS_REQUEST ip={ip}"
    );
}

async fn accept_transparent(
    listener: &Option<TcpListener>,
) -> Result<Option<(TcpStream, SocketAddr)>> {
    match listener {
        Some(tl) => {
            let (stream, peer) = tl.accept().await?;
            Ok(Some((stream, peer)))
        }
        None => {
            std::future::pending::<()>().await;
            Ok(None)
        }
    }
}

fn build_client() -> Result<HttpClient> {
    let mut root_store = RootCertStore::empty();

    let roots = rustls_native_certs::load_native_certs();

    if let Some(err) = roots.errors.first() {
        tracing::warn!(error = %err, "error loading some native root certificates");
    }

    for cert in roots.certs {
        if let Err(err) = root_store.add(cert) {
            tracing::warn!(error = %err, "skipping invalid native root certificate");
        }
    }

    if root_store.is_empty() {
        tracing::error!("no valid root certificates loaded — upstream TLS will fail");
    }

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(https))
}

async fn transparent_upstream_request(
    req: hyper::Request<ProxyBody>,
    target: &ResolvedTarget,
) -> Result<hyper::Response<Incoming>> {
    let host = target
        .uri
        .host()
        .context("missing host in URI for transparent upstream")?;
    let port = target
        .uri
        .port_u16()
        .unwrap_or(if target.scheme == "https" { 443 } else { 80 });

    let addr = transparent::resolve_host(host, port).await?;
    let tcp_stream = transparent::connect_transparent(addr).await?;

    if target.scheme == "https" {
        let tls_config = transparent::build_upstream_tls_config()?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| anyhow::anyhow!("invalid SNI: {host}"))?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .context("transparent upstream TLS connect failed")?;
        let io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("transparent upstream HTTP/1 handshake failed")?;
        tokio::spawn(conn);
        sender
            .send_request(req)
            .await
            .context("transparent upstream request failed")
    } else {
        let io = TokioIo::new(tcp_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("transparent upstream HTTP/1 handshake failed")?;
        tokio::spawn(conn);
        sender
            .send_request(req)
            .await
            .context("transparent upstream request failed")
    }
}

async fn serve_client(stream: TcpStream, peer: SocketAddr, state: ProxyState) -> Result<()> {
    let io = TokioIo::new(stream);
    let ctx = RequestContext {
        default_scheme: "http",
        default_authority: None,
    };

    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let state = state.clone();
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_request(req, peer, state, ctx).await) }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    builder
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|err| anyhow::anyhow!("serve_connection failed: {err}"))?;

    Ok(())
}

async fn handle_request(
    req: hyper::Request<Incoming>,
    peer: SocketAddr,
    state: ProxyState,
    ctx: RequestContext,
) -> hyper::Response<ProxyBody> {
    if req.method() == Method::CONNECT && ctx.default_authority.is_none() {
        return handle_connect(req, peer, state);
    }

    let request_started_at = Instant::now();
    let request_id: Arc<str> =
        Arc::from(NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).to_string());
    let method_for_error = req.method().clone();
    let url_for_error = request_url_for_log(req.uri(), req.headers(), &ctx);
    let plugin = state.plugin.clone();

    match proxy_http(
        req,
        peer,
        state,
        ctx,
        request_id.clone(),
        request_started_at,
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(
                request_id = %request_id,
                peer = %peer,
                method = %method_for_error,
                url = %url_for_error,
                status = %StatusCode::BAD_GATEWAY,
                error = %err,
                "request failed"
            );
            emit_entry_log(
                plugin.as_ref(),
                json!({
                    "type": "entry",
                    "event": "upstream_error",
                    "request_id": request_id.as_ref(),
                    "peer": peer.to_string(),
                    "method": method_for_error.as_str(),
                    "url": url_for_error,
                    "status": StatusCode::BAD_GATEWAY.as_u16(),
                    "duration_ms": elapsed_millis(request_started_at),
                    "error": err.to_string()
                }),
            );
            text_response(StatusCode::BAD_GATEWAY, "bad gateway\n".to_string())
        }
    }
}

fn handle_connect(
    req: hyper::Request<Incoming>,
    peer: SocketAddr,
    state: ProxyState,
) -> hyper::Response<ProxyBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "CONNECT missing authority\n".to_string(),
        );
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    let authority_str = authority.to_string();
    let target_url = format!("https://{authority_str}/");
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).to_string();
    let on_upgrade = upgrade::on(req);

    if is_connect_target_blocked(&host, port) {
        tracing::warn!(
            peer = %peer,
            target = %authority_str,
            "CONNECT target blocked by policy"
        );
        return text_response(
            StatusCode::FORBIDDEN,
            "CONNECT target blocked by policy\n".to_string(),
        );
    }

    tracing::info!(peer = %peer, target = %authority_str, "CONNECT");

    let ca = state.ca.clone();
    let rules = state.rules.clone();
    let client = state.client.clone();
    let inspect = state.inspect.clone();
    let throttle = state.throttle.clone();
    let plugin = state.plugin.clone();
    let mitm_allowed = rules.is_mitm_allowed("https", &authority_str);
    let should_mitm = ca.is_some() && mitm_allowed;

    if !should_mitm {
        tracing::info!(
            peer = %peer,
            method = "CONNECT",
            url = %target_url,
            status = 200,
            encrypted = true,
            "tunnel"
        );
        emit_entry_log(
            plugin.as_ref(),
            json!({
                "type": "entry",
                "event": "tunnel",
                "request_id": request_id,
                "peer": peer.to_string(),
                "method": "CONNECT",
                "url": target_url,
                "status": 200,
                "encrypted": true
            }),
        );
    }

    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Some(ca) = ca
                    && mitm_allowed
                {
                    if let Err(err) = mitm_https(
                        upgraded,
                        peer,
                        &authority_str,
                        &host,
                        port,
                        ca,
                        rules,
                        client,
                        inspect,
                        throttle,
                        plugin,
                    )
                    .await
                    {
                        tracing::warn!(peer = %peer, target = %authority_str, error = %err, "MITM tunnel failed");
                    }
                } else if let Err(err) =
                    tunnel_tcp(upgraded, &authority_str, &host, port, throttle.as_ref()).await
                {
                    tracing::warn!(peer = %peer, target = %authority_str, error = %err, "TCP tunnel failed");
                }
            }
            Err(err) => {
                tracing::warn!(peer = %peer, target = %authority_str, error = %err, "upgrade failed");
            }
        }
    });

    hyper::Response::builder()
        .status(StatusCode::OK)
        .body(boxed_body(Full::new(Bytes::new())))
        .expect("response builder")
}

async fn tunnel_tcp(
    client_io: upgrade::Upgraded,
    authority: &str,
    host: &str,
    port: u16,
    throttle: &ThrottleConfig,
) -> Result<()> {
    let mut client_io = TokioIo::new(client_io);
    let upstream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed to connect upstream: {host}:{port}"))?;

    let throttle_active = throttle.is_active_for("https", authority);
    if !throttle_active {
        let mut upstream = upstream;
        let _ = copy_bidirectional(&mut client_io, &mut upstream)
            .await
            .context("tunnel copy_bidirectional failed")?;
        return Ok(());
    }

    if throttle.latency_ms > 0 {
        tokio::time::sleep(Duration::from_millis(throttle.latency_ms)).await;
    }

    if throttle.upstream_bytes_per_sec == 0 && throttle.downstream_bytes_per_sec == 0 {
        let mut upstream = upstream;
        let _ = copy_bidirectional(&mut client_io, &mut upstream)
            .await
            .context("tunnel copy_bidirectional failed")?;
        return Ok(());
    }

    tunnel_tcp_throttled(
        client_io,
        upstream,
        throttle.upstream_bytes_per_sec,
        throttle.downstream_bytes_per_sec,
    )
    .await?;
    Ok(())
}

async fn tunnel_tcp_throttled(
    client_io: TokioIo<upgrade::Upgraded>,
    upstream: TcpStream,
    upstream_bytes_per_sec: u64,
    downstream_bytes_per_sec: u64,
) -> Result<()> {
    let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);

    tokio::try_join!(
        copy_stream_with_rate(
            &mut client_reader,
            &mut upstream_writer,
            upstream_bytes_per_sec
        ),
        copy_stream_with_rate(
            &mut upstream_reader,
            &mut client_writer,
            downstream_bytes_per_sec
        ),
    )
    .context("tunnel throttled copy failed")?;
    Ok(())
}

async fn copy_stream_with_rate<R, W>(
    reader: &mut R,
    writer: &mut W,
    bytes_per_sec: u64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred: u64 = 0;
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(transferred);
        }

        writer.write_all(&buffer[..read]).await?;
        transferred = transferred.saturating_add(read as u64);

        if let Some(delay) = throttle_delay_for_transfer(read as u64, bytes_per_sec) {
            tokio::time::sleep(delay).await;
        }
    }
}

fn throttle_delay_for_transfer(bytes: u64, bytes_per_sec: u64) -> Option<Duration> {
    if bytes == 0 || bytes_per_sec == 0 {
        return None;
    }

    let nanos = (bytes as u128)
        .saturating_mul(1_000_000_000u128)
        .checked_div(bytes_per_sec as u128)
        .unwrap_or(0);
    if nanos == 0 {
        return None;
    }

    let nanos = nanos.min(u64::MAX as u128) as u64;
    Some(Duration::from_nanos(nanos))
}

async fn serve_transparent_client(
    stream: TcpStream,
    peer: SocketAddr,
    state: ProxyState,
) -> Result<()> {
    let mut peek_buf = [0u8; 1];
    stream
        .peek(&mut peek_buf)
        .await
        .context("failed to peek first byte on transparent connection")?;

    if peek_buf[0] == 0x16 {
        serve_transparent_https(stream, peer, state).await
    } else {
        serve_transparent_http(stream, peer, state).await
    }
}

async fn serve_transparent_https(
    stream: TcpStream,
    peer: SocketAddr,
    state: ProxyState,
) -> Result<()> {
    let ca = state
        .ca
        .as_ref()
        .context("transparent HTTPS requires CA to be loaded")?;

    let accepted = transparent::accept_tls_with_sni(stream, ca)
        .await
        .context("transparent SNI extraction failed")?;

    tracing::info!(peer = %peer, sni = %accepted.hostname, "transparent HTTPS");

    let authority = accepted.hostname;
    let io = TokioIo::new(accepted.tls_stream);
    let ctx = RequestContext {
        default_scheme: "https",
        default_authority: Some(authority),
    };

    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let state = state.clone();
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_request(req, peer, state, ctx).await) }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    builder
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|err| anyhow::anyhow!("serve_connection (transparent TLS) failed: {err}"))?;

    Ok(())
}

async fn serve_transparent_http(
    stream: TcpStream,
    peer: SocketAddr,
    state: ProxyState,
) -> Result<()> {
    tracing::info!(peer = %peer, "transparent HTTP");

    let io = TokioIo::new(stream);
    let ctx = RequestContext {
        default_scheme: "http",
        default_authority: None,
    };

    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let state = state.clone();
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_request(req, peer, state, ctx).await) }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    builder
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|err| anyhow::anyhow!("serve_connection (transparent HTTP) failed: {err}"))?;

    Ok(())
}

fn is_private_target(host: &str, port: u16) -> bool {
    if is_blocked_connect_host_literal(host) {
        return true;
    }

    match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs
            .into_iter()
            .any(|addr| is_blocked_connect_ip(addr.ip())),
        Err(err) => {
            tracing::debug!(target = %host, error = %err, "private target DNS lookup failed");
            false
        }
    }
}

fn is_connect_target_blocked(host: &str, port: u16) -> bool {
    connect_private_block_enabled() && is_private_target(host, port)
}

fn is_http_target_blocked(host: &str, port: u16) -> bool {
    http_private_block_enabled() && is_private_target(host, port)
}

fn connect_private_block_enabled() -> bool {
    parse_env_bool(
        std::env::var("CRAB_CONNECT_BLOCK_PRIVATE").ok().as_deref(),
        true,
    )
}

fn http_private_block_enabled() -> bool {
    parse_env_bool(
        std::env::var("CRAB_HTTP_BLOCK_PRIVATE").ok().as_deref(),
        true,
    )
}

fn upstream_request_timeout() -> Duration {
    let ms = parse_env_u64(
        std::env::var("CRAB_UPSTREAM_TIMEOUT_MS").ok().as_deref(),
        30_000,
    );
    Duration::from_millis(ms)
}

fn max_connections() -> usize {
    parse_env_u64(std::env::var("CRAB_MAX_CONNECTIONS").ok().as_deref(), 4096) as usize
}

fn upstream_san_sniff_enabled() -> bool {
    parse_env_bool(
        std::env::var("CRAB_SNIFF_UPSTREAM_CERT").ok().as_deref(),
        false,
    )
}

pub(super) fn parse_env_bool(raw: Option<&str>, default_value: bool) -> bool {
    match raw.map(str::trim) {
        None => default_value,
        Some(value)
            if value.eq_ignore_ascii_case("0")
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("off")
                || value.eq_ignore_ascii_case("no") =>
        {
            false
        }
        Some(_) => true,
    }
}

fn parse_env_u64(raw: Option<&str>, default_value: u64) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default_value)
}

fn plugin_hook_timeout() -> Duration {
    let ms = parse_env_u64(
        std::env::var("CRAB_PLUGIN_HOOK_TIMEOUT_MS").ok().as_deref(),
        1_500,
    );
    Duration::from_millis(ms)
}

fn unix_timestamp_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(u128::from(u64::MAX)) as u64,
        Err(_) => 0,
    }
}

fn run_plugin_hook_command(command: &str, payload: &[u8]) -> Result<()> {
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-lc")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn plugin hook command: {command}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload)
            .context("failed to write plugin payload")?;
    }

    let status = child.wait().context("failed to wait for plugin hook")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("plugin hook exited with status {status}");
    }
}

fn emit_entry_log(plugin: Option<&Arc<PluginRuntime>>, payload: serde_json::Value) {
    emit_structured_log(payload.clone());
    if let Some(plugin) = plugin {
        plugin.emit("entry", payload);
    }
}

fn http3_observer_enabled() -> bool {
    parse_env_bool(std::env::var("CRAB_HTTP3_OBSERVE").ok().as_deref(), false)
}

async fn run_http3_udp_observer(
    listen: &str,
    plugin: Option<Arc<PluginRuntime>>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("failed to bind HTTP/3 observer UDP socket: {listen}"))?;
    tracing::info!(listen = %listen, "HTTP/3 observer listening (UDP)");

    let mut buffer = vec![0u8; 2048];
    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buffer) => {
                let (len, peer) = recv.context("HTTP/3 observer recv failed")?;
                if len == 0 {
                    continue;
                }
                if let Some(version) = quic_initial_version(&buffer[..len]) {
                    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).to_string();
                    let payload = json!({
                        "type": "entry",
                        "event": "http3_quic_observed",
                        "request_id": request_id,
                        "peer": peer.to_string(),
                        "method": "QUIC",
                        "url": format!("quic://{peer}/"),
                        "udp_bytes": len as u64,
                        "quic_version": format!("0x{version:08x}")
                    });
                    emit_entry_log(plugin.as_ref(), payload);
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_ok() && *shutdown_rx.borrow() {
                    tracing::info!("HTTP/3 observer shutdown signal received");
                } else {
                    tracing::info!("HTTP/3 observer shutdown channel closed");
                }
                break;
            }
        }
    }
    Ok(())
}

fn quic_initial_version(packet: &[u8]) -> Option<u32> {
    if packet.len() < 5 {
        return None;
    }

    let first = packet[0];
    if first & 0x80 == 0 || first & 0x40 == 0 {
        return None;
    }

    let packet_type = (first & 0x30) >> 4;
    if packet_type != 0 {
        return None;
    }

    let version: [u8; 4] = packet[1..5].try_into().ok()?;
    Some(u32::from_be_bytes(version))
}

fn is_blocked_connect_host_literal(host: &str) -> bool {
    let normalized = host.trim().trim_end_matches('.');
    let lowercase = normalized.to_ascii_lowercase();
    if lowercase == "localhost" || lowercase.ends_with(".localhost") {
        return true;
    }

    normalized
        .parse::<IpAddr>()
        .is_ok_and(is_blocked_connect_ip)
}

fn is_blocked_connect_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_unspecified()
                || ipv4.is_multicast()
                || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_multicast()
                || ipv6.is_unique_local()
                || ipv6.is_unicast_link_local()
        }
    }
}

async fn mitm_https(
    upgraded: upgrade::Upgraded,
    peer: SocketAddr,
    authority: &str,
    host_for_cert: &str,
    port_for_cert: u16,
    ca: Arc<CertificateAuthority>,
    rules: Arc<Rules>,
    client: HttpClient,
    inspect: Arc<InspectConfig>,
    throttle: Arc<ThrottleConfig>,
    plugin: Option<Arc<PluginRuntime>>,
) -> Result<()> {
    let upstream_sans = if upstream_san_sniff_enabled() {
        sniff_upstream_subject_names(host_for_cert, port_for_cert).await
    } else {
        None
    };
    let tls_cfg = ca
        .server_config_for_host(host_for_cert, upstream_sans)
        .await
        .with_context(|| format!("failed to build cert for {host_for_cert}"))?;
    let acceptor = TlsAcceptor::from(tls_cfg);
    let tls_stream = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .context("tls accept failed")?;

    let io = TokioIo::new(tls_stream);
    let ctx = RequestContext {
        default_scheme: "https",
        default_authority: Some(authority.to_string()),
    };
    let state = ProxyState {
        client,
        rules,
        ca: Some(ca),
        inspect,
        throttle,
        plugin,
        transparent: false,
    };

    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let state = state.clone();
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_request(req, peer, state, ctx).await) }
    });

    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .preserve_header_case(true)
        .title_case_headers(true);
    builder
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|err| anyhow::anyhow!("serve_connection (mitm) failed: {err}"))?;

    Ok(())
}

async fn sniff_upstream_subject_names(host: &str, port: u16) -> Option<Vec<String>> {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
    const TLS_TIMEOUT: Duration = Duration::from_secs(3);

    let upstream_addr = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        transparent::resolve_host(host, port),
    )
    .await
    {
        Ok(Ok(addr)) => addr,
        Ok(Err(err)) => {
            tracing::debug!(host = %host, port, error = %err, "upstream SAN sniff DNS lookup failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(host = %host, port, "upstream SAN sniff DNS lookup timed out");
            return None;
        }
    };

    let upstream_tcp = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        transparent::connect_transparent(upstream_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            tracing::debug!(host = %host, port, error = %err, "upstream SAN sniff connect failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(host = %host, port, "upstream SAN sniff connect timed out");
            return None;
        }
    };

    let tls_config = match transparent::build_upstream_tls_config() {
        Ok(config) => config,
        Err(err) => {
            tracing::debug!(host = %host, port, error = %err, "upstream SAN sniff TLS config failed");
            return None;
        }
    };
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(name) => name,
        Err(_) => {
            tracing::debug!(host = %host, port, "upstream SAN sniff invalid SNI host");
            return None;
        }
    };

    let tls_stream = match tokio::time::timeout(
        TLS_TIMEOUT,
        connector.connect(server_name, upstream_tcp),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            tracing::debug!(host = %host, port, error = %err, "upstream SAN sniff TLS handshake failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(host = %host, port, "upstream SAN sniff TLS handshake timed out");
            return None;
        }
    };

    let peer_certs = match tls_stream.get_ref().1.peer_certificates() {
        Some(certs) if !certs.is_empty() => certs,
        _ => {
            tracing::debug!(host = %host, port, "upstream SAN sniff found no peer certificate");
            return None;
        }
    };

    let subject_names = parse_subject_names_from_leaf_cert(peer_certs[0].as_ref());
    if subject_names.is_empty() {
        tracing::debug!(host = %host, port, "upstream SAN sniff found no SAN/CN values");
        None
    } else {
        tracing::debug!(host = %host, port, count = subject_names.len(), "upstream SAN sniff succeeded");
        Some(subject_names)
    }
}

fn parse_subject_names_from_leaf_cert(leaf_cert_der: &[u8]) -> Vec<String> {
    let (_, cert) = match parse_x509_certificate(leaf_cert_der) {
        Ok(parsed) => parsed,
        Err(err) => {
            tracing::debug!(error = ?err, "failed to parse upstream leaf certificate");
            return Vec::new();
        }
    };

    let mut names: Vec<String> = Vec::new();

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for general_name in &san.value.general_names {
            if let Some(name) = general_name_to_subject_name(general_name) {
                push_unique_name(&mut names, name);
            }
        }
    }

    if names.is_empty() {
        for common_name in cert.subject().iter_common_name() {
            if let Ok(cn) = common_name.as_str()
                && let Some(name) = normalize_subject_name(cn)
            {
                push_unique_name(&mut names, name);
            }
        }
    }

    names
}

fn general_name_to_subject_name(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(value) => normalize_subject_name(value),
        GeneralName::IPAddress(raw) => match raw.len() {
            4 => {
                let bytes: [u8; 4] = (*raw).try_into().ok()?;
                Some(Ipv4Addr::from(bytes).to_string())
            }
            16 => {
                let bytes: [u8; 16] = (*raw).try_into().ok()?;
                Some(Ipv6Addr::from(bytes).to_string())
            }
            _ => None,
        },
        _ => None,
    }
}

fn normalize_subject_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    let normalized = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn push_unique_name(names: &mut Vec<String>, candidate: String) {
    if !names.iter().any(|name| name == &candidate) {
        names.push(candidate);
    }
}

async fn proxy_http(
    req: hyper::Request<Incoming>,
    peer: SocketAddr,
    state: ProxyState,
    ctx: RequestContext,
    request_id: Arc<str>,
    request_started_at: Instant,
) -> Result<hyper::Response<ProxyBody>> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let target = resolve_target(&parts.uri, &parts.headers, &ctx)?;
    let mut upstream_target = target.clone();
    let mut map_remote_applied: Option<(String, String)> = None;

    {
        let auth: http::uri::Authority = target
            .authority
            .parse()
            .context("failed to parse target authority")?;
        let host = auth.host();
        let port = auth
            .port_u16()
            .unwrap_or(if target.scheme == "https" { 443 } else { 80 });
        if is_http_target_blocked(host, port) {
            tracing::warn!(
                peer = %peer,
                target = %target.authority,
                "HTTP target blocked by policy"
            );
            return Ok(text_response(
                StatusCode::FORBIDDEN,
                "HTTP target blocked by policy\n".to_string(),
            ));
        }
    }

    let path_and_query = target
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let request_url: Arc<str> = Arc::from(format!(
        "{}://{}{}",
        target.scheme, target.authority, path_and_query
    ));
    let method_for_inspect: Arc<str> = Arc::from(method.as_str());

    tracing::debug!(
        peer = %peer,
        method = %method,
        url = %request_url,
        "request"
    );

    if let Some(resp) = maybe_handle_cert_portal(&method, &target, state.ca.as_deref()).await {
        let response_size_bytes = response_size_from_headers(resp.headers());
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %resp.status(),
            "cert_portal"
        );
        emit_entry_log(
            state.plugin.as_ref(),
            json!({
                "type": "entry",
                "event": "cert_portal",
                "request_id": request_id.as_ref(),
                "peer": peer.to_string(),
                "method": method.as_str(),
                "url": request_url.as_ref(),
                "status": resp.status().as_u16(),
                "duration_ms": elapsed_millis(request_started_at),
                "response_size_bytes": response_size_bytes
            }),
        );
        return Ok(resp);
    }

    let allowed = state
        .rules
        .is_allowed(&target.scheme, &target.authority, path_and_query);

    if allowed {
        let headers_b64 = encode_headers_for_log(&parts.headers);
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            headers_b64 = %headers_b64,
            "request_headers"
        );
        emit_structured_log(json!({
            "type": "meta",
            "event": "request_headers",
            "request_id": request_id.as_ref(),
            "peer": peer.to_string(),
            "method": method.as_str(),
            "url": request_url.as_ref(),
            "headers_b64": headers_b64
        }));
    }

    if allowed
        && let Some(rule) =
            state
                .rules
                .find_map_local(&target.scheme, &target.authority, path_and_query)
    {
        let mut resp = map_local_response(rule).await?;
        apply_status_rewrite(
            &state.rules,
            &target.scheme,
            &target.authority,
            path_and_query,
            &mut resp,
        );
        let map_local_status = resp.status();
        strip_hop_headers(resp.headers_mut());

        let headers_b64 = encode_headers_for_log(resp.headers());
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %map_local_status,
            headers_b64 = %headers_b64,
            "response_headers"
        );
        emit_structured_log(json!({
            "type": "meta",
            "event": "response_headers",
            "request_id": request_id.as_ref(),
            "peer": peer.to_string(),
            "method": method.as_str(),
            "url": request_url.as_ref(),
            "headers_b64": headers_b64,
            "status": map_local_status.as_u16()
        }));

        emit_map_local_body_preview(
            rule,
            &state.inspect,
            &request_id,
            peer,
            &method,
            &request_url,
            map_local_status,
        )
        .await;

        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %resp.status(),
            map_local = %rule.matcher.raw(),
            "map_local"
        );
        let response_size_bytes = response_size_from_headers(resp.headers());
        emit_entry_log(
            state.plugin.as_ref(),
            json!({
                "type": "entry",
                "event": "map_local",
                "request_id": request_id.as_ref(),
                "peer": peer.to_string(),
                "method": method.as_str(),
                "url": request_url.as_ref(),
                "status": resp.status().as_u16(),
                "map_local": rule.matcher.raw(),
                "duration_ms": elapsed_millis(request_started_at),
                "response_size_bytes": response_size_bytes
            }),
        );
        return Ok(maybe_apply_response_throttle(
            resp,
            &state.throttle,
            &target.scheme,
            &target.authority,
        )
        .await);
    }

    if allowed
        && let Some(rule) =
            state
                .rules
                .find_map_remote(&target.scheme, &target.authority, path_and_query)
    {
        upstream_target = rewrite_map_remote_target(&target, path_and_query, rule)?;
        let upstream_url = resolved_target_url(&upstream_target);
        map_remote_applied = Some((rule.matcher.raw().to_string(), upstream_url));
    }

    let inspect_req_meta = InspectMeta {
        request_id: request_id.clone(),
        direction: "request",
        peer,
        method: method_for_inspect.clone(),
        url: request_url.clone(),
        response_status: None,
    };
    let req_body = if allowed {
        maybe_inspect_body(body, &state.inspect, inspect_req_meta)
    } else {
        boxed_body(body)
    };

    let mut out_req = hyper::Request::new(req_body);
    *out_req.method_mut() = parts.method;
    *out_req.uri_mut() = upstream_target.uri.clone();
    *out_req.version_mut() = parts.version;
    *out_req.headers_mut() = parts.headers;
    strip_hop_headers(out_req.headers_mut());
    ensure_host_header(out_req.headers_mut(), &upstream_target.authority)?;
    out_req =
        maybe_apply_request_throttle(out_req, &state.throttle, &target.scheme, &target.authority);

    let timeout = upstream_request_timeout();
    let upstream_resp = if state.transparent {
        match tokio::time::timeout(
            timeout,
            transparent_upstream_request(out_req, &upstream_target),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Ok(text_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream request timed out\n".to_string(),
                ));
            }
        }
    } else {
        match tokio::time::timeout(timeout, state.client.request(out_req)).await {
            Ok(result) => result.context("upstream request failed")?,
            Err(_) => {
                return Ok(text_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream request timed out\n".to_string(),
                ));
            }
        }
    };
    let (mut resp_parts, resp_body) = upstream_resp.into_parts();

    strip_hop_headers(&mut resp_parts.headers);
    let upstream_status = resp_parts.status;
    if allowed {
        let headers_b64 = encode_headers_for_log(&resp_parts.headers);
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %upstream_status,
            headers_b64 = %headers_b64,
            "response_headers"
        );
        emit_structured_log(json!({
            "type": "meta",
            "event": "response_headers",
            "request_id": request_id.as_ref(),
            "peer": peer.to_string(),
            "method": method.as_str(),
            "url": request_url.as_ref(),
            "headers_b64": headers_b64,
            "status": upstream_status.as_u16()
        }));
    }

    let inspect_resp_meta = InspectMeta {
        request_id: request_id.clone(),
        direction: "response",
        peer,
        method: method_for_inspect,
        url: request_url.clone(),
        response_status: Some(upstream_status),
    };
    let out_body = if allowed {
        maybe_inspect_body(resp_body, &state.inspect, inspect_resp_meta)
    } else {
        boxed_body(resp_body)
    };

    let mut out_resp = hyper::Response::new(out_body);
    *out_resp.status_mut() = upstream_status;
    *out_resp.version_mut() = resp_parts.version;
    *out_resp.headers_mut() = resp_parts.headers;

    if allowed {
        apply_status_rewrite(
            &state.rules,
            &target.scheme,
            &target.authority,
            path_and_query,
            &mut out_resp,
        );

        let response_size_bytes = response_size_from_headers(out_resp.headers());
        if let Some((map_remote_matcher, map_remote_to)) = map_remote_applied.as_ref() {
            tracing::info!(
                peer = %peer,
                method = %method,
                url = %request_url,
                status = %out_resp.status(),
                map_remote = %map_remote_matcher,
                map_remote_to = %map_remote_to,
                "map_remote"
            );
            emit_entry_log(
                state.plugin.as_ref(),
                json!({
                    "type": "entry",
                    "event": "map_remote",
                    "request_id": request_id.as_ref(),
                    "peer": peer.to_string(),
                    "method": method.as_str(),
                    "url": request_url.as_ref(),
                    "status": out_resp.status().as_u16(),
                    "map_remote": map_remote_matcher,
                    "map_remote_to": map_remote_to,
                    "duration_ms": elapsed_millis(request_started_at),
                    "response_size_bytes": response_size_bytes
                }),
            );
        } else {
            tracing::info!(
                peer = %peer,
                method = %method,
                url = %request_url,
                status = %out_resp.status(),
                "upstream"
            );
            emit_entry_log(
                state.plugin.as_ref(),
                json!({
                    "type": "entry",
                    "event": "upstream",
                    "request_id": request_id.as_ref(),
                    "peer": peer.to_string(),
                    "method": method.as_str(),
                    "url": request_url.as_ref(),
                    "status": out_resp.status().as_u16(),
                    "duration_ms": elapsed_millis(request_started_at),
                    "response_size_bytes": response_size_bytes
                }),
            );
        }
    }

    Ok(
        maybe_apply_response_throttle(out_resp, &state.throttle, &target.scheme, &target.authority)
            .await,
    )
}

fn maybe_apply_request_throttle(
    mut req: hyper::Request<ProxyBody>,
    throttle: &ThrottleConfig,
    scheme: &str,
    authority: &str,
) -> hyper::Request<ProxyBody> {
    if !throttle.is_active_for(scheme, authority) || throttle.upstream_bytes_per_sec == 0 {
        return req;
    }

    let body = std::mem::replace(req.body_mut(), boxed_body(Full::new(Bytes::new())));
    *req.body_mut() = maybe_throttle_body_with_rate(body, throttle.upstream_bytes_per_sec);
    req
}

async fn maybe_apply_response_throttle(
    mut resp: hyper::Response<ProxyBody>,
    throttle: &ThrottleConfig,
    scheme: &str,
    authority: &str,
) -> hyper::Response<ProxyBody> {
    if !throttle.is_active_for(scheme, authority) {
        return resp;
    }

    if throttle.latency_ms > 0 {
        tokio::time::sleep(Duration::from_millis(throttle.latency_ms)).await;
    }

    if throttle.downstream_bytes_per_sec == 0 {
        return resp;
    }

    let body = std::mem::replace(resp.body_mut(), boxed_body(Full::new(Bytes::new())));
    *resp.body_mut() = maybe_throttle_body(body, throttle);
    resp
}

#[derive(Clone)]
struct ResolvedTarget {
    scheme: String,
    authority: String,
    uri: Uri,
}

fn resolve_target(uri: &Uri, headers: &HeaderMap, ctx: &RequestContext) -> Result<ResolvedTarget> {
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        return Ok(ResolvedTarget {
            scheme: scheme.to_string(),
            authority: authority.to_string(),
            uri: uri.clone(),
        });
    }

    let authority = if let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
        host.to_string()
    } else if let Some(a) = &ctx.default_authority {
        a.clone()
    } else {
        anyhow::bail!("missing Host header");
    };

    let mut full_builder = Uri::builder()
        .scheme(ctx.default_scheme)
        .authority(authority.as_str());
    full_builder = if let Some(path_and_query) = uri.path_and_query() {
        full_builder.path_and_query(path_and_query.clone())
    } else {
        full_builder.path_and_query("/")
    };
    let full = full_builder
        .build()
        .context("failed to build absolute URI")?;

    Ok(ResolvedTarget {
        scheme: ctx.default_scheme.to_string(),
        authority,
        uri: full,
    })
}

fn request_url_for_log(uri: &Uri, headers: &HeaderMap, ctx: &RequestContext) -> String {
    if let Ok(target) = resolve_target(uri, headers, ctx) {
        return resolved_target_url(&target);
    }
    uri.to_string()
}

fn resolved_target_url(target: &ResolvedTarget) -> String {
    let path_and_query = target
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    format!("{}://{}{}", target.scheme, target.authority, path_and_query)
}

fn rewrite_map_remote_target(
    original: &ResolvedTarget,
    original_path_and_query: &str,
    rule: &crate::rules::MapRemoteRule,
) -> Result<ResolvedTarget> {
    let matcher = rule.matcher.raw().trim();
    let suffix = if matcher.starts_with("http://") || matcher.starts_with("https://") {
        let full = resolved_target_url(original);
        full.strip_prefix(matcher)
            .ok_or_else(|| {
                anyhow::anyhow!("source URL does not match map_remote prefix '{}'", matcher)
            })?
            .to_string()
    } else if matcher.starts_with('/') {
        original_path_and_query
            .strip_prefix(matcher)
            .ok_or_else(|| anyhow::anyhow!("source path does not match map_remote prefix"))?
            .to_string()
    } else {
        let authority_and_path = format!("{}{}", original.authority, original_path_and_query);
        authority_and_path
            .strip_prefix(matcher)
            .ok_or_else(|| {
                anyhow::anyhow!("source authority/path does not match map_remote prefix")
            })?
            .to_string()
    };

    let destination = rule.destination.trim();
    let rewritten = format!("{destination}{suffix}");
    parse_absolute_target_url(&rewritten)
}

fn parse_absolute_target_url(raw_url: &str) -> Result<ResolvedTarget> {
    let parsed = raw_url
        .parse::<Uri>()
        .with_context(|| format!("invalid map_remote destination URL: {raw_url}"))?;
    let scheme = parsed
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("map_remote destination requires scheme"))?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        anyhow::bail!("map_remote destination scheme must be http or https");
    }
    let authority = parsed
        .authority()
        .ok_or_else(|| anyhow::anyhow!("map_remote destination requires authority"))?
        .to_string();
    let path_and_query = parsed
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let uri = Uri::builder()
        .scheme(scheme)
        .authority(authority.as_str())
        .path_and_query(path_and_query)
        .build()
        .context("failed to normalize map_remote destination URL")?;

    Ok(ResolvedTarget {
        scheme: scheme.to_string(),
        authority,
        uri,
    })
}

async fn map_local_response(
    rule: &crate::rules::MapLocalRule,
) -> Result<hyper::Response<ProxyBody>> {
    let mut resp = match &rule.source {
        MapSource::File(path) => {
            let file = tokio::fs::File::open(path)
                .await
                .with_context(|| format!("failed to read local file: {}", path.display()))?;
            let content_type = rule.content_type.clone().unwrap_or_else(|| {
                mime_guess::from_path(path)
                    .first_or_octet_stream()
                    .essence_str()
                    .to_string()
            });

            let content_length = file.metadata().await.ok().map(|m| m.len());
            let stream = ReaderStream::new(file).map(|chunk| chunk.map(Frame::data));
            let mut resp = hyper::Response::new(boxed_body(StreamBody::new(stream)));
            apply_content_headers(resp.headers_mut(), &content_type, content_length)?;
            resp
        }
        MapSource::Text(text) => {
            let content_type = rule
                .content_type
                .clone()
                .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());
            let bytes = Bytes::copy_from_slice(text.as_bytes());
            let content_length = bytes.len() as u64;
            let mut resp = hyper::Response::new(boxed_body(Full::new(bytes)));
            apply_content_headers(resp.headers_mut(), &content_type, Some(content_length))?;
            resp
        }
    };

    *resp.status_mut() = rule.status;
    resp.headers_mut().insert(
        HeaderName::from_static("x-crab-mitm"),
        HeaderValue::from_static("map_local"),
    );
    Ok(resp)
}

async fn emit_map_local_body_preview(
    rule: &crate::rules::MapLocalRule,
    inspect: &InspectConfig,
    request_id: &Arc<str>,
    peer: SocketAddr,
    method: &Method,
    request_url: &Arc<str>,
    status: StatusCode,
) {
    if !inspect.enabled {
        return;
    }

    let Ok((sample, body_bytes)) = map_local_body_sample(rule, inspect.sample_bytes).await else {
        return;
    };

    let sample_bytes = sample.len();
    let sample_b64 = base64::engine::general_purpose::STANDARD.encode(&sample);
    tracing::info!(
        request_id = %request_id,
        peer = %peer,
        method = %method,
        url = %request_url,
        direction = "response",
        response_status = status.as_u16(),
        body_bytes = body_bytes,
        sample_bytes = sample_bytes,
        sample_b64 = %sample_b64,
        outcome = "complete",
        error = "-",
        "body inspection"
    );
    emit_structured_log(json!({
        "type": "meta",
        "event": "body_inspection",
        "request_id": request_id.as_ref(),
        "peer": peer.to_string(),
        "method": method.as_str(),
        "url": request_url.as_ref(),
        "direction": "response",
        "response_status": status.as_u16(),
        "body_bytes": body_bytes,
        "sample_b64": sample_b64,
        "outcome": "complete",
        "error": serde_json::Value::Null
    }));
}

async fn map_local_body_sample(
    rule: &crate::rules::MapLocalRule,
    sample_limit: usize,
) -> Result<(Vec<u8>, u64)> {
    match &rule.source {
        MapSource::Text(text) => {
            let bytes = text.as_bytes();
            let take = bytes.len().min(sample_limit);
            Ok((bytes[..take].to_vec(), bytes.len() as u64))
        }
        MapSource::File(path) => {
            let mut file = tokio::fs::File::open(path)
                .await
                .with_context(|| format!("failed to read map_local sample: {}", path.display()))?;
            let body_bytes = file.metadata().await.ok().map(|m| m.len()).unwrap_or(0);

            if sample_limit == 0 {
                return Ok((Vec::new(), body_bytes));
            }

            let mut sample = vec![0u8; sample_limit];
            let mut offset = 0usize;
            while offset < sample_limit {
                let read = file.read(&mut sample[offset..]).await?;
                if read == 0 {
                    break;
                }
                offset += read;
            }
            sample.truncate(offset);
            Ok((sample, body_bytes.max(offset as u64)))
        }
    }
}

fn apply_status_rewrite<B>(
    rules: &Rules,
    scheme: &str,
    authority: &str,
    path_and_query: &str,
    resp: &mut hyper::Response<B>,
) {
    let current = resp.status();
    if let Some(new_status) = rules.rewrite_status(scheme, authority, path_and_query, current) {
        *resp.status_mut() = new_status;
        resp.headers_mut().insert(
            HeaderName::from_static("x-crab-mitm-status-rewrite"),
            HeaderValue::from_str(&format!("{current}->{new_status}"))
                .unwrap_or_else(|_| HeaderValue::from_static("applied")),
        );
    }
}

fn boxed_body<B>(body: B) -> ProxyBody
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: StdError + Send + Sync + 'static,
{
    body.map_err(|err| -> BoxError { Box::new(err) })
        .boxed_unsync()
}

fn ensure_host_header(headers: &mut HeaderMap, authority: &str) -> Result<()> {
    let v = HeaderValue::from_str(authority).context("invalid Host header")?;
    headers.insert(HOST, v);
    Ok(())
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let connection = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Some(val) = connection {
        for name in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            headers.remove(name);
        }
    }

    const HOP_BY_HOP: [&str; 10] = [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "http2-settings",
    ];
    for h in HOP_BY_HOP {
        headers.remove(h);
    }
}

fn elapsed_millis(started_at: Instant) -> u64 {
    started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn response_size_from_headers(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn emit_structured_log(payload: serde_json::Value) {
    let line = format!("CRAB_JSON {}", payload);
    tracing::info!("{}", line);

    let callback = STRUCTURED_LOG_CALLBACK
        .get()
        .and_then(|store| store.read().ok().and_then(|guard| guard.clone()));
    if let Some(callback) = callback {
        callback(line);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::rules::Matcher;
    use base64::Engine as _;

    use super::*;

    fn test_meta() -> InspectMeta {
        InspectMeta {
            request_id: Arc::from("test-request-1"),
            direction: "request",
            peer: "127.0.0.1:12345".parse().expect("socket addr"),
            method: Arc::from("POST"),
            url: Arc::from("http://example.com/upload"),
            response_status: None,
        }
    }

    #[test]
    fn escape_for_log_escapes_control_bytes() {
        let out = escape_for_log(b"A\n\t\x00");
        assert_eq!(out, "A\\n\\t\\x00");
    }

    #[test]
    fn inspector_respects_sample_limit() {
        let cfg = InspectConfig {
            enabled: true,
            sample_bytes: 4,
            spool: false,
            spool_dir: None,
            spool_max_bytes: 0,
        };

        let mut inspector = BodyInspector::new(&cfg, test_meta());
        inspector.observe(b"abcdefgh");

        assert_eq!(inspector.total_bytes, 8);
        assert_eq!(inspector.sample, b"abcd");
        assert!(inspector.sample_truncated);
    }

    #[test]
    fn inspector_spool_respects_max_bytes() {
        let dir = std::env::temp_dir().join("crab-mitm-test-spool");
        let _ = fs::remove_dir_all(&dir);

        let cfg = InspectConfig {
            enabled: true,
            sample_bytes: 0,
            spool: true,
            spool_dir: Some(dir.clone()),
            spool_max_bytes: 5,
        };

        let mut inspector = BodyInspector::new(&cfg, test_meta());
        let spool_path = inspector.spool_path.clone().expect("spool path");

        inspector.observe(b"abcdefgh");
        assert_eq!(inspector.spool_written, 5);
        assert!(inspector.spool_truncated);

        inspector.finish("complete", None);

        let size = fs::metadata(&spool_path).expect("spool metadata").len();
        assert_eq!(size, 5);

        let _ = fs::remove_file(spool_path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cert_portal_host_matching_is_case_insensitive() {
        assert!(is_cert_portal_host("crab-proxy.local"));
        assert!(is_cert_portal_host("CRAB-PROXY.INVALID"));
        assert!(is_cert_portal_host("proxy.crab"));
        assert!(!is_cert_portal_host("example.com"));
    }

    #[test]
    fn cert_portal_page_contains_platform_download_links() {
        let html = build_cert_portal_page("http://crab-proxy.local", Some("AA:BB:CC:DD:EE:FF"));
        assert!(html.contains("/android.crt"));
        assert!(html.contains("/ios.mobileconfig"));
        assert!(html.contains("/ca.pem"));
        assert!(html.contains("/ca.crl"));
        assert!(html.contains("SHA-256 Fingerprint"));
        assert!(html.contains("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn ios_mobileconfig_embeds_certificate_data() {
        let mobileconfig = build_ios_mobileconfig(&[1, 2, 3, 4]);
        assert!(mobileconfig.contains("<data>AQIDBA==</data>"));
        assert!(mobileconfig.contains("com.apple.security.root"));
        assert!(mobileconfig.contains("<key>PayloadUUID</key>"));
    }

    #[test]
    fn ios_mobileconfig_uuid_is_deterministic_per_certificate() {
        let a = build_ios_mobileconfig(&[1, 2, 3, 4]);
        let b = build_ios_mobileconfig(&[1, 2, 3, 4]);
        let c = build_ios_mobileconfig(&[5, 6, 7, 8]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn cert_fingerprint_is_uppercase_sha256_hex() {
        let fp = ca_cert_fingerprint_sha256(&[1, 2, 3, 4]);
        assert_eq!(
            fp,
            "9F:64:A7:47:E1:B9:7F:13:1F:AB:B6:B4:47:29:6C:9B:6F:02:01:E7:9F:B3:C5:35:6E:6C:77:E8:9B:6A:80:6A"
        );
    }

    #[test]
    fn header_encoding_roundtrips_text_form() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", HeaderValue::from_static("abc"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let encoded = encode_headers_for_log(&headers);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 decode");
        let text = String::from_utf8(decoded).expect("utf8");

        assert!(text.contains("x-test: abc"));
        assert!(text.contains("content-type: application/json"));
    }

    #[test]
    fn header_encoding_masks_sensitive_values() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer abc"));
        headers.insert("cookie", HeaderValue::from_static("sid=secret"));
        headers.insert("x-test", HeaderValue::from_static("ok"));

        let encoded = encode_headers_for_log(&headers);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 decode");
        let text = String::from_utf8(decoded).expect("utf8");

        assert!(text.contains("authorization: <redacted>"));
        assert!(text.contains("cookie: <redacted>"));
        assert!(text.contains("x-test: ok"));
    }

    #[test]
    fn connect_policy_blocks_private_addresses_and_localhost() {
        assert!(is_blocked_connect_host_literal("localhost"));
        assert!(is_blocked_connect_host_literal("127.0.0.1"));
        assert!(is_blocked_connect_host_literal("10.0.0.7"));
        assert!(is_blocked_connect_host_literal("192.168.1.10"));
        assert!(is_blocked_connect_host_literal("172.16.3.9"));
        assert!(is_blocked_connect_host_literal("169.254.1.2"));
        assert!(is_blocked_connect_host_literal("::1"));
        assert!(is_blocked_connect_host_literal("fc00::1"));
        assert!(is_blocked_connect_host_literal("fe80::1234"));
    }

    #[test]
    fn connect_policy_allows_public_addresses() {
        assert!(!is_blocked_connect_host_literal("1.1.1.1"));
        assert!(!is_blocked_connect_host_literal("8.8.8.8"));
        assert!(!is_blocked_connect_host_literal("2606:4700:4700::1111"));
        assert!(!is_blocked_connect_host_literal("example.com"));
    }

    #[test]
    fn parse_env_bool_supports_defaults_and_false_values() {
        assert!(parse_env_bool(None, true));
        assert!(!parse_env_bool(None, false));
        assert!(!parse_env_bool(Some("false"), true));
        assert!(!parse_env_bool(Some("0"), true));
        assert!(!parse_env_bool(Some("off"), true));
        assert!(!parse_env_bool(Some("no"), true));
        assert!(parse_env_bool(Some("true"), true));
        assert!(parse_env_bool(Some("true"), false));
    }

    #[test]
    fn parse_env_u64_supports_defaults_and_positive_numbers() {
        assert_eq!(parse_env_u64(None, 42), 42);
        assert_eq!(parse_env_u64(Some("1200"), 42), 1200);
        assert_eq!(parse_env_u64(Some(" 77 "), 42), 77);
        assert_eq!(parse_env_u64(Some("0"), 42), 42);
        assert_eq!(parse_env_u64(Some("-1"), 42), 42);
        assert_eq!(parse_env_u64(Some("abc"), 42), 42);
    }

    #[test]
    fn throttle_selected_hosts_match_subdomain_patterns() {
        let cfg = ThrottleConfig {
            enabled: true,
            latency_ms: 120,
            downstream_bytes_per_sec: 0,
            upstream_bytes_per_sec: 0,
            only_selected_hosts: true,
            selected_hosts: vec![AllowRule::new("*.example.com")],
        };

        assert!(cfg.is_active_for("https", "api.example.com:443"));
        assert!(!cfg.is_active_for("https", "example.net:443"));
    }

    #[test]
    fn throttle_selected_hosts_disabled_uses_global_scope() {
        let cfg = ThrottleConfig {
            enabled: true,
            latency_ms: 120,
            downstream_bytes_per_sec: 0,
            upstream_bytes_per_sec: 0,
            only_selected_hosts: false,
            selected_hosts: vec![],
        };

        assert!(cfg.is_active_for("https", "any-host.test:443"));
    }

    #[test]
    fn normalize_client_ip_converts_ipv4_mapped_ipv6() {
        let mapped: IpAddr = "::ffff:192.168.0.8"
            .parse()
            .expect("ipv4-mapped ipv6 parse");
        assert_eq!(
            normalize_client_ip(mapped),
            "192.168.0.8".parse::<IpAddr>().expect("ipv4 parse")
        );
    }

    #[test]
    fn rewrite_map_remote_target_rewrites_authority_path_prefix() {
        let original = ResolvedTarget {
            scheme: "https".to_string(),
            authority: "api.example.com".to_string(),
            uri: "https://api.example.com/v1/users?id=1"
                .parse()
                .expect("original uri"),
        };
        let rule = crate::rules::MapRemoteRule {
            matcher: Matcher::new("api.example.com/v1"),
            destination: "https://staging.example.com/v2".to_string(),
        };

        let rewritten = rewrite_map_remote_target(&original, "/v1/users?id=1", &rule)
            .expect("rewrite map_remote target");
        assert_eq!(
            resolved_target_url(&rewritten),
            "https://staging.example.com/v2/users?id=1"
        );
    }

    #[test]
    fn client_access_enforced_allows_loopback_without_explicit_rule() {
        let cfg = ClientAccessConfig {
            enforce_allowlist: true,
            allowed_client_ips: vec![],
        };
        let peer: SocketAddr = "127.0.0.1:50000".parse().expect("socket addr");
        assert!(is_client_ip_allowed(peer, &cfg));
    }

    #[test]
    fn client_access_enforced_blocks_unknown_lan_ip() {
        let cfg = ClientAccessConfig {
            enforce_allowlist: true,
            allowed_client_ips: vec!["192.168.0.99".parse().expect("allowed ip")],
        };
        let peer: SocketAddr = "192.168.0.20:50000".parse().expect("socket addr");
        assert!(!is_client_ip_allowed(peer, &cfg));
    }

    #[test]
    fn client_access_enforced_allows_configured_lan_ip() {
        let cfg = ClientAccessConfig {
            enforce_allowlist: true,
            allowed_client_ips: vec!["192.168.0.20".parse().expect("allowed ip")],
        };
        let peer: SocketAddr = "192.168.0.20:50000".parse().expect("socket addr");
        assert!(is_client_ip_allowed(peer, &cfg));
    }

    #[test]
    fn quic_initial_version_detects_initial_packets() {
        let packet = [0xC0u8, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(quic_initial_version(&packet), Some(1));
    }

    #[test]
    fn quic_initial_version_ignores_non_initial_or_short_packets() {
        assert_eq!(quic_initial_version(&[]), None);
        assert_eq!(quic_initial_version(&[0x40, 0, 0, 0, 1]), None);
        assert_eq!(quic_initial_version(&[0xD0, 0, 0, 0, 1]), None);
    }
}
