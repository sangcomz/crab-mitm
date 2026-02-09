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

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use http_body::{Body as HttpBody, Frame, SizeHint};
use pin_project_lite::pin_project;
use serde_json::json;

use super::{InspectConfig, ProxyBody, boxed_body};

static NEXT_SPOOL_FILE_ID: AtomicU64 = AtomicU64::new(1);

const PREVIEW_LOG_LIMIT_BYTES: usize = 512;

#[derive(Clone)]
pub(super) struct InspectMeta {
    pub(super) direction: &'static str,
    pub(super) peer: SocketAddr,
    pub(super) method: Arc<str>,
    pub(super) url: Arc<str>,
    pub(super) response_status: Option<StatusCode>,
}

pub(super) struct BodyInspector {
    pub(super) meta: InspectMeta,
    pub(super) sample: Vec<u8>,
    pub(super) sample_limit: usize,
    pub(super) sample_truncated: bool,
    pub(super) total_bytes: u64,
    pub(super) spool_writer: Option<SpoolWriter>,
    pub(super) spool_path: Option<PathBuf>,
    pub(super) spool_max_bytes: u64,
    pub(super) spool_written: u64,
    pub(super) spool_truncated: bool,
    pub(super) spool_error: Option<String>,
}

pub(super) struct SpoolWriter {
    tx: std::sync::mpsc::Sender<Vec<u8>>,
    join: std::thread::JoinHandle<std::io::Result<()>>,
}

pin_project! {
    pub(super) struct InspectableBody<B> {
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
    pub(super) fn new(cfg: &InspectConfig, meta: InspectMeta) -> Self {
        let mut inspector = Self {
            meta,
            sample: Vec::with_capacity(cfg.sample_bytes.min(64 * 1024)),
            sample_limit: cfg.sample_bytes,
            sample_truncated: false,
            total_bytes: 0,
            spool_writer: None,
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
                    match spawn_spool_writer(file) {
                        Ok(writer) => {
                            inspector.spool_writer = Some(writer);
                        }
                        Err(err) => {
                            inspector.spool_error = Some(err.to_string());
                        }
                    }
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

    pub(super) fn observe(&mut self, bytes: &[u8]) {
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

        if let Some(writer) = self.spool_writer.as_ref() {
            if self.spool_written >= self.spool_max_bytes {
                self.spool_truncated = true;
                return;
            }

            let remaining = (self.spool_max_bytes - self.spool_written) as usize;
            let write_len = remaining.min(bytes.len());

            if write_len > 0 {
                if writer.tx.send(bytes[..write_len].to_vec()).is_err() {
                    self.spool_error = Some("spool writer channel closed".to_string());
                    self.spool_writer = None;
                    return;
                }
                self.spool_written += write_len as u64;
            }

            if bytes.len() > write_len {
                self.spool_truncated = true;
            }
        }
    }

    pub(super) fn finish(mut self, outcome: &'static str, error: Option<String>) {
        if let Some(writer) = self.spool_writer.take() {
            let SpoolWriter { tx, join } = writer;
            drop(tx);
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    if self.spool_error.is_none() {
                        self.spool_error = Some(err.to_string());
                    }
                }
                Err(_) => {
                    if self.spool_error.is_none() {
                        self.spool_error = Some("spool writer thread panicked".to_string());
                    }
                }
            }
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
        tracing::info!(
            "CRAB_JSON {}",
            json!({
                "type": "meta",
                "event": "body_inspection",
                "peer": self.meta.peer.to_string(),
                "method": self.meta.method.as_ref(),
                "url": self.meta.url.as_ref(),
                "direction": self.meta.direction,
                "response_status": self.meta.response_status.map(|status| status.as_u16()),
                "body_bytes": self.total_bytes,
                "sample_b64": sample_b64,
                "outcome": outcome,
                "error": error
            })
        );
    }
}

pub(super) fn maybe_inspect_body<B>(body: B, cfg: &InspectConfig, meta: InspectMeta) -> ProxyBody
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

pub(super) fn escape_for_log(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        for escaped in std::ascii::escape_default(*byte) {
            out.push(char::from(escaped));
        }
    }
    out
}

pub(super) fn encode_headers_for_log(headers: &HeaderMap) -> String {
    let mask_sensitive = should_mask_sensitive_headers();
    let estimated_capacity = headers.iter().fold(0usize, |acc, (name, value)| {
        let value_len = value.to_str().map_or(12, |v| v.len());
        acc + name.as_str().len() + value_len + 3
    });
    let mut plain = String::with_capacity(estimated_capacity);
    for (name, value) in headers {
        plain.push_str(name.as_str());
        plain.push_str(": ");
        if mask_sensitive && is_sensitive_header(name.as_str()) {
            plain.push_str("<redacted>");
        } else {
            plain.push_str(value.to_str().unwrap_or("<non-utf8>"));
        }
        plain.push('\n');
    }
    base64::engine::general_purpose::STANDARD.encode(plain.as_bytes())
}

fn spawn_spool_writer(mut file: File) -> std::io::Result<SpoolWriter> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let join = std::thread::Builder::new()
        .name("crab-mitm-spool-writer".to_string())
        .spawn(move || -> std::io::Result<()> {
            while let Ok(chunk) = rx.recv() {
                file.write_all(&chunk)?;
            }
            file.flush()?;
            Ok(())
        })?;
    Ok(SpoolWriter { tx, join })
}

fn should_mask_sensitive_headers() -> bool {
    parse_env_bool_default_true(std::env::var("CRAB_MASK_SENSITIVE_HEADERS").ok().as_deref())
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

fn is_sensitive_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("set-cookie")
        || name.eq_ignore_ascii_case("x-api-key")
        || name.eq_ignore_ascii_case("x-auth-token")
}

fn open_spool_file(cfg: &InspectConfig, direction: &str) -> std::io::Result<(PathBuf, File)> {
    let dir = cfg.spool_dir.clone().unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&dir)?;
    set_spool_dir_permissions(&dir)?;

    let now_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let id = NEXT_SPOOL_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("crab-mitm-{direction}-{now_millis}-{id}.bin"));
    let file = create_private_spool_file(&path)?;

    Ok((path, file))
}

fn set_spool_dir_permissions(path: &PathBuf) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_spool_file(path: &PathBuf) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        return OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path);
    }

    #[cfg(not(unix))]
    {
        File::create(path)
    }
}
