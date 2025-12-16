use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::ca::CertificateAuthority;
use crate::rules::{MapSource, Rules};

type BoxBody = Full<Bytes>;
type HttpClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody>;

#[derive(Clone)]
struct ProxyState {
    client: HttpClient,
    rules: Arc<Rules>,
    ca: Option<Arc<CertificateAuthority>>,
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
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to bind: {listen}"))?;

    let client = build_client()?;
    let state = ProxyState { client, rules, ca };

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
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received");
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
) -> hyper::Response<BoxBody> {
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
) -> hyper::Response<BoxBody> {
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

    let on_upgrade = upgrade::on(req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Some(ca) = ca {
                    if let Err(err) =
                        mitm_https(upgraded, peer, &authority_str, &host, ca, rules, client).await
                    {
                        tracing::warn!(peer = %peer, target = %authority_str, error = %err, "MITM tunnel failed");
                    }
                } else {
                    if let Err(err) = tunnel_tcp(upgraded, &host, port).await {
                        tracing::warn!(peer = %peer, target = %authority_str, error = %err, "TCP tunnel failed");
                    }
                }
            }
            Err(err) => {
                tracing::warn!(peer = %peer, target = %authority_str, error = %err, "upgrade failed");
            }
        }
    });

    hyper::Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
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
) -> Result<hyper::Response<BoxBody>> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let target = resolve_target(&parts.uri, &parts.headers, &ctx)?;

    let path_and_query = target
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    tracing::debug!(
        peer = %peer,
        method = %method,
        url = %format!("{}://{}{}", target.scheme, target.authority, path_and_query),
        "request"
    );

    if let Some(rule) =
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
            url = %format!("{}://{}{}", target.scheme, target.authority, path_and_query),
            status = %resp.status(),
            map_local = %rule.matcher.raw(),
            "map_local"
        );
        return Ok(resp);
    }

    let body_bytes = body.collect().await?.to_bytes();

    let mut out_req = hyper::Request::new(Full::new(body_bytes));
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
    let resp_bytes = resp_body.collect().await?.to_bytes();

    strip_hop_headers(&mut resp_parts.headers);
    let mut out_resp = hyper::Response::new(Full::new(resp_bytes));
    *out_resp.status_mut() = resp_parts.status;
    *out_resp.version_mut() = resp_parts.version;
    *out_resp.headers_mut() = resp_parts.headers;

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
        url = %format!("{}://{}{}", target.scheme, target.authority, path_and_query),
        status = %out_resp.status(),
        "upstream"
    );

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

async fn map_local_response(rule: &crate::rules::MapLocalRule) -> Result<hyper::Response<BoxBody>> {
    let (bytes, content_type) = match &rule.source {
        MapSource::File(path) => {
            let data = tokio::fs::read(path)
                .await
                .with_context(|| format!("failed to read local file: {}", path.display()))?;
            let ct = rule.content_type.clone().unwrap_or_else(|| {
                mime_guess::from_path(path)
                    .first_or_octet_stream()
                    .essence_str()
                    .to_string()
            });
            (Bytes::from(data), ct)
        }
        MapSource::Text(text) => {
            let ct = rule
                .content_type
                .clone()
                .unwrap_or_else(|| "text/plain; charset=utf-8".to_string());
            (Bytes::from(text.clone()), ct)
        }
    };

    let mut resp = hyper::Response::new(Full::new(bytes.clone()));
    *resp.status_mut() = rule.status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type).context("invalid content_type")?,
    );
    resp.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).expect("content-length"),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-crab-mitm"),
        HeaderValue::from_static("map_local"),
    );
    Ok(resp)
}

fn apply_status_rewrite(
    rules: &Rules,
    scheme: &str,
    authority: &str,
    path_and_query: &str,
    resp: &mut hyper::Response<BoxBody>,
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

fn text_response(status: StatusCode, body: String) -> hyper::Response<BoxBody> {
    let bytes = Bytes::from(body);
    let mut resp = hyper::Response::new(Full::new(bytes.clone()));
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
