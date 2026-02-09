use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::HeaderValue;
use http::{HeaderMap, Method, StatusCode};
use http_body_util::Full;

use super::{ProxyBody, boxed_body};

pub(super) fn maybe_head_response(
    method: &Method,
    mut resp: hyper::Response<ProxyBody>,
) -> hyper::Response<ProxyBody> {
    if *method == Method::HEAD {
        *resp.body_mut() = boxed_body(Full::new(Bytes::new()));
    }
    resp
}

pub(super) fn text_response(status: StatusCode, body: String) -> hyper::Response<ProxyBody> {
    owned_bytes_response(status, "text/plain; charset=utf-8", Bytes::from(body))
}

pub(super) fn html_response(status: StatusCode, html: String) -> hyper::Response<ProxyBody> {
    owned_bytes_response(status, "text/html; charset=utf-8", Bytes::from(html))
}

pub(super) fn bytes_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> hyper::Response<ProxyBody> {
    owned_bytes_response(status, content_type, body)
}

fn owned_bytes_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
) -> hyper::Response<ProxyBody> {
    let content_length = body.len();
    let mut resp = hyper::Response::new(boxed_body(Full::new(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    resp.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).expect("content-length"),
    );
    resp
}

pub(super) fn apply_content_headers(
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
