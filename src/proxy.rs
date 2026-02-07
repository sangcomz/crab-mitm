use std::convert::Infallible;
use std::error::Error as StdError;
use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine as _;
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body::{Body as HttpBody, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pin_project_lite::pin_project;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;

use crate::ca::CertificateAuthority;
use crate::rules::{MapSource, Rules};

static NEXT_SPOOL_FILE_ID: AtomicU64 = AtomicU64::new(1);

const PREVIEW_LOG_LIMIT_BYTES: usize = 512;
const CERT_PORTAL_HOSTS: [&str; 3] = ["crab-proxy.local", "crab-proxy.invalid", "proxy.crab"];

type BoxError = Box<dyn StdError + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, ProxyBody>;

#[derive(Clone, Debug)]
pub struct InspectConfig {
    pub enabled: bool,
    pub sample_bytes: usize,
    pub spool: bool,
    pub spool_dir: Option<PathBuf>,
    pub spool_max_bytes: u64,
}

#[derive(Clone)]
struct ProxyState {
    client: HttpClient,
    rules: Arc<Rules>,
    ca: Option<Arc<CertificateAuthority>>,
    inspect: Arc<InspectConfig>,
}

#[derive(Clone)]
struct RequestContext {
    default_scheme: &'static str,
    default_authority: Option<String>,
}

#[derive(Clone)]
struct InspectMeta {
    direction: &'static str,
    peer: SocketAddr,
    method: Method,
    url: String,
    response_status: Option<StatusCode>,
}

struct BodyInspector {
    meta: InspectMeta,
    sample: Vec<u8>,
    sample_limit: usize,
    sample_truncated: bool,
    total_bytes: u64,
    spool_file: Option<File>,
    spool_path: Option<PathBuf>,
    spool_max_bytes: u64,
    spool_written: u64,
    spool_truncated: bool,
    spool_error: Option<String>,
}

pin_project! {
    struct InspectableBody<B> {
        #[pin]
        inner: B,
        inspector: Option<BodyInspector>,
    }
}

impl<B> InspectableBody<B> {
    fn new(inner: B, inspector: BodyInspector) -> Self {
        Self {
            inner,
            inspector: Some(inspector),
        }
    }
}

impl<B> HttpBody for InspectableBody<B>
where
    B: HttpBody<Data = Bytes>,
    B::Error: StdError,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(inspector) = this.inspector.as_mut()
                {
                    inspector.observe(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                let error_message = err.to_string();
                if let Some(inspector) = this.inspector.take() {
                    inspector.finish("error", Some(error_message));
                }
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if let Some(inspector) = this.inspector.take() {
                    inspector.finish("complete", None);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl BodyInspector {
    fn new(cfg: &InspectConfig, meta: InspectMeta) -> Self {
        let mut inspector = Self {
            meta,
            sample: Vec::new(),
            sample_limit: cfg.sample_bytes,
            sample_truncated: false,
            total_bytes: 0,
            spool_file: None,
            spool_path: None,
            spool_max_bytes: cfg.spool_max_bytes,
            spool_written: 0,
            spool_truncated: false,
            spool_error: None,
        };

        if cfg.spool {
            match open_spool_file(cfg, inspector.meta.direction) {
                Ok((path, file)) => {
                    inspector.spool_path = Some(path);
                    inspector.spool_file = Some(file);
                }
                Err(err) => {
                    inspector.spool_error = Some(err.to_string());
                    tracing::warn!(
                        peer = %inspector.meta.peer,
                        method = %inspector.meta.method,
                        url = %inspector.meta.url,
                        direction = inspector.meta.direction,
                        error = %err,
                        "failed to open body spool file"
                    );
                }
            }
        }

        inspector
    }

    fn observe(&mut self, bytes: &[u8]) {
        self.total_bytes += bytes.len() as u64;

        if self.sample.len() < self.sample_limit {
            let remaining = self.sample_limit - self.sample.len();
            let take = remaining.min(bytes.len());
            self.sample.extend_from_slice(&bytes[..take]);
            if bytes.len() > take {
                self.sample_truncated = true;
            }
        } else if !bytes.is_empty() {
            self.sample_truncated = true;
        }

        if self.spool_file.is_some() {
            if self.spool_written >= self.spool_max_bytes {
                self.spool_truncated = true;
                return;
            }

            let remaining = (self.spool_max_bytes - self.spool_written) as usize;
            let write_len = remaining.min(bytes.len());

            if write_len > 0 {
                let write_result = self
                    .spool_file
                    .as_mut()
                    .expect("spool_file checked")
                    .write_all(&bytes[..write_len]);
                if let Err(err) = write_result {
                    self.spool_error = Some(err.to_string());
                    self.spool_file = None;
                    return;
                }
                self.spool_written += write_len as u64;
            }

            if bytes.len() > write_len {
                self.spool_truncated = true;
            }
        }
    }

    fn finish(mut self, outcome: &'static str, error: Option<String>) {
        if let Some(file) = self.spool_file.as_mut()
            && let Err(err) = file.flush()
            && self.spool_error.is_none()
        {
            self.spool_error = Some(err.to_string());
        }

        let preview_source_len = self.sample.len().min(PREVIEW_LOG_LIMIT_BYTES);
        let sample_preview = escape_for_log(&self.sample[..preview_source_len]);
        let sample_preview_truncated = self.sample.len() > PREVIEW_LOG_LIMIT_BYTES;
        let sample_b64 = base64::engine::general_purpose::STANDARD.encode(&self.sample);

        let spool_path = self
            .spool_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string());

        tracing::info!(
            peer = %self.meta.peer,
            method = %self.meta.method,
            url = %self.meta.url,
            direction = self.meta.direction,
            response_status = ?self.meta.response_status,
            body_bytes = self.total_bytes,
            sample_bytes = self.sample.len(),
            sample_truncated = self.sample_truncated,
            sample_preview = %sample_preview,
            sample_b64 = %sample_b64,
            sample_preview_truncated = sample_preview_truncated,
            spool_path = %spool_path,
            spool_bytes = self.spool_written,
            spool_truncated = self.spool_truncated,
            spool_error = %self.spool_error.as_deref().unwrap_or("-"),
            outcome = outcome,
            error = %error.as_deref().unwrap_or("-"),
            "body inspection"
        );
    }
}

pub async fn run(
    listen: &str,
    ca: Option<Arc<CertificateAuthority>>,
    rules: Arc<Rules>,
    inspect: Arc<InspectConfig>,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });

    run_with_shutdown(listen, ca, rules, inspect, shutdown_rx).await
}

pub async fn run_with_shutdown(
    listen: &str,
    ca: Option<Arc<CertificateAuthority>>,
    rules: Arc<Rules>,
    inspect: Arc<InspectConfig>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind: {listen}"))?;

    let client = build_client()?;
    let state = ProxyState {
        client,
        rules,
        ca,
        inspect,
    };

    tracing::info!(listen = %listen, "proxy listening");

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer) = res?;
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_client(stream, peer, state).await {
                        tracing::debug!(peer = %peer, error = %err, "connection ended");
                    }
                });
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

fn build_client() -> Result<HttpClient> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .context("failed to load native root certs")?
        .https_or_http()
        .enable_http1()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(https))
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

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, svc)
        .with_upgrades()
        .await
        .context("serve_connection failed")?;

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

    match proxy_http(req, peer, state, ctx).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(peer = %peer, error = %err, "request failed");
            text_response(StatusCode::BAD_GATEWAY, format!("bad gateway: {err}\n"))
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

    tracing::info!(peer = %peer, target = %authority_str, "CONNECT");

    let ca = state.ca.clone();
    let rules = state.rules.clone();
    let client = state.client.clone();
    let inspect = state.inspect.clone();

    let on_upgrade = upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Some(ca) = ca {
                    if let Err(err) = mitm_https(
                        upgraded,
                        peer,
                        &authority_str,
                        &host,
                        ca,
                        rules,
                        client,
                        inspect,
                    )
                    .await
                    {
                        tracing::warn!(peer = %peer, target = %authority_str, error = %err, "MITM tunnel failed");
                    }
                } else if let Err(err) = tunnel_tcp(upgraded, &host, port).await {
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

async fn tunnel_tcp(client_io: upgrade::Upgraded, host: &str, port: u16) -> Result<()> {
    let mut client_io = TokioIo::new(client_io);
    let mut upstream = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed to connect upstream: {host}:{port}"))?;
    let _ = copy_bidirectional(&mut client_io, &mut upstream)
        .await
        .context("tunnel copy_bidirectional failed")?;
    Ok(())
}

async fn mitm_https(
    upgraded: upgrade::Upgraded,
    peer: SocketAddr,
    authority: &str,
    host_for_cert: &str,
    ca: Arc<CertificateAuthority>,
    rules: Arc<Rules>,
    client: HttpClient,
    inspect: Arc<InspectConfig>,
) -> Result<()> {
    let tls_cfg = ca
        .server_config_for_host(host_for_cert)
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
    };

    let svc = service_fn(move |req: hyper::Request<Incoming>| {
        let state = state.clone();
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle_request(req, peer, state, ctx).await) }
    });

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, svc)
        .with_upgrades()
        .await
        .context("serve_connection (mitm) failed")?;

    Ok(())
}

async fn proxy_http(
    req: hyper::Request<Incoming>,
    peer: SocketAddr,
    state: ProxyState,
    ctx: RequestContext,
) -> Result<hyper::Response<ProxyBody>> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let target = resolve_target(&parts.uri, &parts.headers, &ctx)?;

    let path_and_query = target
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let request_url = format!("{}://{}{}", target.scheme, target.authority, path_and_query);

    tracing::debug!(
        peer = %peer,
        method = %method,
        url = %request_url,
        "request"
    );

    if let Some(resp) = maybe_handle_cert_portal(&method, &target, state.ca.as_deref()) {
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %resp.status(),
            "cert_portal"
        );
        return Ok(resp);
    }

    let allowed = state
        .rules
        .is_allowed(&target.scheme, &target.authority, path_and_query);

    if allowed {
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            headers_b64 = %encode_headers_for_log(&parts.headers),
            "request_headers"
        );
    }

    if allowed && let Some(rule) =
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
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %resp.status(),
            map_local = %rule.matcher.raw(),
            "map_local"
        );
        return Ok(resp);
    }

    let inspect_req_meta = InspectMeta {
        direction: "request",
        peer,
        method: method.clone(),
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
    *out_req.uri_mut() = target.uri.clone();
    *out_req.version_mut() = parts.version;
    *out_req.headers_mut() = parts.headers;
    strip_hop_headers(out_req.headers_mut());
    ensure_host_header(out_req.headers_mut(), &target.authority)?;

    let upstream_resp = state
        .client
        .request(out_req)
        .await
        .context("upstream request failed")?;
    let (mut resp_parts, resp_body) = upstream_resp.into_parts();

    strip_hop_headers(&mut resp_parts.headers);
    let upstream_status = resp_parts.status;
    if allowed {
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %upstream_status,
            headers_b64 = %encode_headers_for_log(&resp_parts.headers),
            "response_headers"
        );
    }

    let inspect_resp_meta = InspectMeta {
        direction: "response",
        peer,
        method: method.clone(),
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

        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %out_resp.status(),
            "upstream"
        );
    }

    Ok(out_resp)
}

struct ResolvedTarget {
    scheme: String,
    authority: String,
    uri: Uri,
}

fn resolve_target(uri: &Uri, headers: &HeaderMap, ctx: &RequestContext) -> Result<ResolvedTarget> {
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        let scheme = scheme.to_string();
        let authority = authority.to_string();
        let full: Uri = format!("{scheme}://{authority}{path_and_query}")
            .parse()
            .context("failed to parse absolute URI")?;
        return Ok(ResolvedTarget {
            scheme,
            authority,
            uri: full,
        });
    }

    let authority = if let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
        host.to_string()
    } else if let Some(a) = &ctx.default_authority {
        a.clone()
    } else {
        anyhow::bail!("missing Host header");
    };

    let scheme = ctx.default_scheme.to_string();
    let full: Uri = format!("{scheme}://{authority}{path_and_query}")
        .parse()
        .context("failed to build absolute URI")?;

    Ok(ResolvedTarget {
        scheme,
        authority,
        uri: full,
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
            let bytes = Bytes::from(text.clone());
            let mut resp = hyper::Response::new(boxed_body(Full::new(bytes.clone())));
            apply_content_headers(resp.headers_mut(), &content_type, Some(bytes.len() as u64))?;
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

fn maybe_inspect_body<B>(body: B, cfg: &InspectConfig, meta: InspectMeta) -> ProxyBody
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: StdError + Send + Sync + 'static,
{
    if cfg.enabled {
        boxed_body(InspectableBody::new(body, BodyInspector::new(cfg, meta)))
    } else {
        boxed_body(body)
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

fn maybe_handle_cert_portal(
    method: &Method,
    target: &ResolvedTarget,
    ca: Option<&CertificateAuthority>,
) -> Option<hyper::Response<ProxyBody>> {
    if target.scheme != "http" {
        return None;
    }

    let host = target.uri.host()?;
    if !is_cert_portal_host(host) {
        return None;
    }

    if *method != Method::GET && *method != Method::HEAD {
        return Some(maybe_head_response(
            method,
            text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "only GET/HEAD is supported for cert portal\n".to_string(),
            ),
        ));
    }

    let path = target.uri.path();
    let base_url = format!("http://{}", target.authority);

    match path {
        "/" | "/index.html" => Some(maybe_head_response(
            method,
            html_response(
                StatusCode::OK,
                build_cert_portal_page(&base_url, ca.is_some()),
            ),
        )),
        "/ca.pem" => {
            let Some(ca) = ca else {
                return Some(maybe_head_response(
                    method,
                    text_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CA is not loaded. Configure CA in the desktop app first.\n".to_string(),
                    ),
                ));
            };
            let mut resp = bytes_response(
                StatusCode::OK,
                "application/x-pem-file",
                Bytes::from(ca.ca_cert_pem().to_string()),
            );
            resp.headers_mut().insert(
                http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"crab-proxy-ca.pem\""),
            );
            Some(maybe_head_response(method, resp))
        }
        "/android.crt" | "/ca.der" => {
            let Some(ca) = ca else {
                return Some(maybe_head_response(
                    method,
                    text_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CA is not loaded. Configure CA in the desktop app first.\n".to_string(),
                    ),
                ));
            };
            let mut resp = bytes_response(
                StatusCode::OK,
                "application/x-x509-ca-cert",
                Bytes::copy_from_slice(ca.ca_cert_der()),
            );
            resp.headers_mut().insert(
                http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"crab-proxy-ca.crt\""),
            );
            Some(maybe_head_response(method, resp))
        }
        "/ios.mobileconfig" => {
            let Some(ca) = ca else {
                return Some(maybe_head_response(
                    method,
                    text_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "CA is not loaded. Configure CA in the desktop app first.\n".to_string(),
                    ),
                ));
            };
            let mobileconfig = build_ios_mobileconfig(ca.ca_cert_der());
            let mut resp = bytes_response(
                StatusCode::OK,
                "application/x-apple-aspen-config",
                Bytes::from(mobileconfig),
            );
            resp.headers_mut().insert(
                http::header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"crab-proxy-ca.mobileconfig\""),
            );
            Some(maybe_head_response(method, resp))
        }
        _ => Some(maybe_head_response(
            method,
            text_response(
                StatusCode::NOT_FOUND,
                "cert portal path not found\n".to_string(),
            ),
        )),
    }
}

fn is_cert_portal_host(host: &str) -> bool {
    CERT_PORTAL_HOSTS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(host))
}

fn build_cert_portal_page(base_url: &str, has_ca: bool) -> String {
    let ca_section = if has_ca {
        format!(
            r#"
<div class="card">
  <h2>Install Certificate</h2>
  <p><b>Android:</b> download and install <a href="{base}/android.crt">android.crt</a></p>
  <p><b>iOS:</b> download and install <a href="{base}/ios.mobileconfig">ios.mobileconfig</a></p>
  <p><b>Raw PEM:</b> <a href="{base}/ca.pem">ca.pem</a></p>
  <p class="note">iOS requires extra trust step:
  Settings &gt; General &gt; About &gt; Certificate Trust Settings.</p>
</div>
"#,
            base = base_url
        )
    } else {
        r#"
<div class="card">
  <h2>CA Not Loaded</h2>
  <p>The proxy is running, but no CA certificate is configured yet.</p>
  <p>Load or generate CA files from the desktop app first.</p>
</div>
"#
        .to_string()
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Crab Proxy Cert Portal</title>
  <style>
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #e9f2ff;
      background: linear-gradient(135deg, #06203a 0%, #0d3a33 100%);
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 16px;
    }}
    .wrap {{
      width: min(760px, 100%);
    }}
    .title {{
      font-size: 30px;
      font-weight: 700;
      margin-bottom: 8px;
    }}
    .subtitle {{
      color: #b8cee8;
      margin-bottom: 16px;
    }}
    .card {{
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 16px;
      background: rgba(8, 14, 24, 0.35);
      padding: 16px;
      backdrop-filter: blur(8px);
    }}
    h2 {{
      margin-top: 0;
      font-size: 20px;
    }}
    p {{
      line-height: 1.5;
      margin: 8px 0;
    }}
    a {{
      color: #88d9ff;
      text-decoration: none;
    }}
    .note {{
      color: #d6e8ff;
      opacity: 0.9;
      font-size: 14px;
      margin-top: 12px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">Crab Proxy Certificate Portal</div>
    <div class="subtitle">Open this page from a phone browser while HTTP proxy is enabled.</div>
    {ca_section}
  </div>
</body>
</html>"#
    )
}

fn build_ios_mobileconfig(ca_der: &[u8]) -> String {
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(ca_der);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>crab-proxy-ca.cer</string>
      <key>PayloadContent</key>
      <data>{cert_b64}</data>
      <key>PayloadDescription</key>
      <string>Installs Crab Proxy root certificate.</string>
      <key>PayloadDisplayName</key>
      <string>Crab Proxy Root CA</string>
      <key>PayloadIdentifier</key>
      <string>com.crabproxy.ca.root</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>8891AB7E-3E52-47F4-8A0A-9A4A6D4FAF11</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Install this profile to trust Crab Proxy for HTTPS inspection.</string>
  <key>PayloadDisplayName</key>
  <string>Crab Proxy CA</string>
  <key>PayloadIdentifier</key>
  <string>com.crabproxy.ca.profile</string>
  <key>PayloadOrganization</key>
  <string>Crab Proxy</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>778E1AF7-EB28-4B8D-92A0-0295A53D5C72</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>"#
    )
}

fn maybe_head_response(
    method: &Method,
    mut resp: hyper::Response<ProxyBody>,
) -> hyper::Response<ProxyBody> {
    if *method == Method::HEAD {
        *resp.body_mut() = boxed_body(Full::new(Bytes::new()));
    }
    resp
}

fn text_response(status: StatusCode, body: String) -> hyper::Response<ProxyBody> {
    let bytes = Bytes::from(body);
    let mut resp = hyper::Response::new(boxed_body(Full::new(bytes.clone())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("content-length"),
    );
    resp
}

fn html_response(status: StatusCode, html: String) -> hyper::Response<ProxyBody> {
    let bytes = Bytes::from(html);
    let mut resp = hyper::Response::new(boxed_body(Full::new(bytes.clone())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("content-length"),
    );
    resp
}

fn bytes_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> hyper::Response<ProxyBody> {
    let mut resp = hyper::Response::new(boxed_body(Full::new(body.clone())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    resp.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).expect("content-length"),
    );
    resp
}

fn apply_content_headers(
    headers: &mut HeaderMap,
    content_type: &str,
    content_length: Option<u64>,
) -> Result<()> {
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).context("invalid content_type")?,
    );

    if let Some(len) = content_length {
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&len.to_string()).context("invalid content-length")?,
        );
    }

    Ok(())
}

fn open_spool_file(cfg: &InspectConfig, direction: &str) -> std::io::Result<(PathBuf, File)> {
    let dir = cfg.spool_dir.clone().unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&dir)?;

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let id = NEXT_SPOOL_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("crab-mitm-{direction}-{now_millis}-{id}.bin"));
    let file = File::create(&path)?;

    Ok((path, file))
}

fn escape_for_log(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        for escaped in std::ascii::escape_default(*byte) {
            out.push(char::from(escaped));
        }
    }
    out
}

fn encode_headers_for_log(headers: &HeaderMap) -> String {
    let mut plain = String::new();
    for (name, value) in headers {
        plain.push_str(name.as_str());
        plain.push_str(": ");
        plain.push_str(value.to_str().unwrap_or("<non-utf8>"));
        plain.push('\n');
    }
    base64::engine::general_purpose::STANDARD.encode(plain.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn test_meta() -> InspectMeta {
        InspectMeta {
            direction: "request",
            peer: "127.0.0.1:12345".parse().expect("socket addr"),
            method: Method::POST,
            url: "http://example.com/upload".to_string(),
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
        let html = build_cert_portal_page("http://crab-proxy.local", true);
        assert!(html.contains("/android.crt"));
        assert!(html.contains("/ios.mobileconfig"));
        assert!(html.contains("/ca.pem"));
    }

    #[test]
    fn ios_mobileconfig_embeds_certificate_data() {
        let mobileconfig = build_ios_mobileconfig(&[1, 2, 3, 4]);
        assert!(mobileconfig.contains("<data>AQIDBA==</data>"));
        assert!(mobileconfig.contains("com.apple.security.root"));
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
}
