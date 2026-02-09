use std::convert::Infallible;
use std::error::Error as StdError;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
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
use serde_json::json;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::io::ReaderStream;

use crate::ca::CertificateAuthority;
use crate::rules::{MapSource, Rules};

mod cert_portal;
mod inspect;
mod response;

use cert_portal::maybe_handle_cert_portal;
use inspect::{InspectMeta, encode_headers_for_log, maybe_inspect_body};
use response::{apply_content_headers, text_response};

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
        .enable_http2()
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

    match proxy_http(req, peer, state, ctx).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(peer = %peer, error = %err, "request failed");
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

fn is_connect_target_blocked(host: &str, port: u16) -> bool {
    if !connect_private_block_enabled() {
        return false;
    }

    if is_blocked_connect_host_literal(host) {
        return true;
    }

    match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs
            .into_iter()
            .any(|addr| is_blocked_connect_ip(addr.ip())),
        Err(err) => {
            tracing::debug!(target = %host, error = %err, "CONNECT target DNS lookup failed");
            false
        }
    }
}

fn connect_private_block_enabled() -> bool {
    parse_env_bool_default_true(std::env::var("CRAB_CONNECT_BLOCK_PRIVATE").ok().as_deref())
}

fn parse_env_bool_default_true(raw: Option<&str>) -> bool {
    match raw.map(str::trim) {
        None => true,
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
    let request_url: Arc<str> = Arc::from(format!(
        "{}://{}{}",
        target.scheme, target.authority, path_and_query
    ));
    let method_for_inspect: Arc<str> = Arc::from(method.as_str());
    let request_id: Arc<str> = Arc::from(NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).to_string());

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
        emit_structured_log(json!({
            "type": "entry",
            "event": "cert_portal",
            "request_id": request_id.as_ref(),
            "peer": peer.to_string(),
            "method": method.as_str(),
            "url": request_url.as_ref(),
            "status": resp.status().as_u16()
        }));
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
        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %resp.status(),
            map_local = %rule.matcher.raw(),
            "map_local"
        );
        emit_structured_log(json!({
            "type": "entry",
            "event": "map_local",
            "request_id": request_id.as_ref(),
            "peer": peer.to_string(),
            "method": method.as_str(),
            "url": request_url.as_ref(),
            "status": resp.status().as_u16(),
            "map_local": rule.matcher.raw()
        }));
        return Ok(resp);
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

        tracing::info!(
            peer = %peer,
            method = %method,
            url = %request_url,
            status = %out_resp.status(),
            "upstream"
        );
        emit_structured_log(json!({
            "type": "entry",
            "event": "upstream",
            "request_id": request_id.as_ref(),
            "peer": peer.to_string(),
            "method": method.as_str(),
            "url": request_url.as_ref(),
            "status": out_resp.status().as_u16()
        }));
    }

    Ok(out_resp)
}

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

fn emit_structured_log(payload: serde_json::Value) {
    tracing::info!("CRAB_JSON {}", payload);
}

#[cfg(test)]
mod tests {
    use std::fs;

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
    fn parse_env_bool_default_true_supports_false_values() {
        assert!(parse_env_bool_default_true(None));
        assert!(!parse_env_bool_default_true(Some("false")));
        assert!(!parse_env_bool_default_true(Some("0")));
        assert!(!parse_env_bool_default_true(Some("off")));
        assert!(!parse_env_bool_default_true(Some("no")));
        assert!(parse_env_bool_default_true(Some("true")));
    }
}
