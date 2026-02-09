use std::fmt::Write as _;

use base64::Engine as _;
use bytes::Bytes;
use http::header::HeaderValue;
use http::{Method, StatusCode};
use sha2::{Digest, Sha256};

use crate::ca::CertificateAuthority;

use super::ResolvedTarget;
use super::response::{bytes_response, html_response, maybe_head_response, text_response};

const CERT_PORTAL_HOSTS: [&str; 3] = ["crab-proxy.local", "crab-proxy.invalid", "proxy.crab"];

pub(super) fn maybe_handle_cert_portal(
    method: &Method,
    target: &ResolvedTarget,
    ca: Option<&CertificateAuthority>,
) -> Option<hyper::Response<super::ProxyBody>> {
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
        "/" | "/index.html" => {
            let fingerprint_sha256 =
                ca.map(|authority| ca_cert_fingerprint_sha256(authority.ca_cert_der()));
            Some(maybe_head_response(
                method,
                html_response(
                    StatusCode::OK,
                    build_cert_portal_page(&base_url, fingerprint_sha256.as_deref()),
                ),
            ))
        }
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

pub(super) fn is_cert_portal_host(host: &str) -> bool {
    CERT_PORTAL_HOSTS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(host))
}

pub(super) fn build_cert_portal_page(base_url: &str, fingerprint_sha256: Option<&str>) -> String {
    let ca_section = if let Some(fingerprint_sha256) = fingerprint_sha256 {
        format!(
            r#"
<div class="card">
  <h2>Install Certificate</h2>
  <p><b>Android:</b> download and install <a href="{base}/android.crt">android.crt</a></p>
  <p><b>iOS:</b> download and install <a href="{base}/ios.mobileconfig">ios.mobileconfig</a></p>
  <p><b>Raw PEM:</b> <a href="{base}/ca.pem">ca.pem</a></p>
  <p class="fingerprint"><b>SHA-256 Fingerprint:</b><br /><code>{fingerprint}</code></p>
  <p class="note">iOS requires extra trust step:
  Settings &gt; General &gt; About &gt; Certificate Trust Settings.</p>
</div>
"#,
            base = base_url,
            fingerprint = fingerprint_sha256
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
    .fingerprint {{
      margin-top: 12px;
      font-size: 14px;
      line-height: 1.7;
    }}
    .fingerprint code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      word-break: break-all;
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

pub(super) fn build_ios_mobileconfig(ca_der: &[u8]) -> String {
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(ca_der);
    let cert_payload_uuid = mobileconfig_payload_uuid(ca_der, "cert-payload");
    let profile_payload_uuid = mobileconfig_payload_uuid(ca_der, "profile-payload");
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
      <string>{cert_payload_uuid}</string>
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
  <string>{profile_payload_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>"#
    )
}

pub(super) fn ca_cert_fingerprint_sha256(ca_der: &[u8]) -> String {
    let digest = Sha256::digest(ca_der);
    let mut out = String::with_capacity((digest.len() * 3) - 1);
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        write!(&mut out, "{:02X}", byte).expect("fingerprint formatting");
    }
    out
}

fn mobileconfig_payload_uuid(ca_der: &[u8], purpose: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ca_der);
    hasher.update([0u8]);
    hasher.update(purpose.as_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Deterministic RFC 4122 UUID (v5-like layout) derived from cert fingerprint.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_uuid(bytes)
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
