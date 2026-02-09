use std::ffi::{CStr, CString, c_char, c_void};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock, RwLock};

use anyhow::{Context, Result};
use http::StatusCode;
use tokio::sync::watch;

use crate::ca::{self, CertificateAuthority};
use crate::proxy::{self, InspectConfig};
use crate::rules::{AllowRule, MapLocalRule, MapSource, Matcher, Rules, StatusRewriteRule};

const CRAB_OK: i32 = 0;
const CRAB_ERR_INVALID_ARG: i32 = 1;
const CRAB_ERR_STATE: i32 = 2;
const CRAB_ERR_IO: i32 = 3;
const CRAB_ERR_CA: i32 = 4;
const CRAB_ERR_INTERNAL: i32 = 255;

pub struct CrabProxyHandle {
    runtime: tokio::runtime::Runtime,
    listen_addr: Mutex<String>,
    ca: Mutex<Option<Arc<CertificateAuthority>>>,
    rules: Mutex<Rules>,
    inspect: Mutex<InspectConfig>,
    shutdown_tx: Mutex<Option<watch::Sender<bool>>>,
    task: Mutex<Option<tokio::task::JoinHandle<Result<()>>>>,
    running: Arc<AtomicBool>,
}

#[repr(C)]
pub struct CrabResult {
    pub code: i32,
    pub message: *mut c_char,
}

type CrabLogCallback =
    Option<extern "C" fn(user_data: *mut c_void, level: u8, message: *const c_char)>;

#[derive(Clone, Copy)]
struct LogCallback {
    func: extern "C" fn(user_data: *mut c_void, level: u8, message: *const c_char),
    // Raw pointer is stored as integer to avoid manually asserting Send/Sync for *mut c_void.
    user_data: usize,
}

impl LogCallback {
    fn user_data_ptr(self) -> *mut c_void {
        self.user_data as *mut c_void
    }
}

static LOG_CALLBACK: OnceLock<RwLock<Option<LogCallback>>> = OnceLock::new();
static LOG_INIT: Once = Once::new();
static MAP_LOCAL_ALLOWED_ROOTS: OnceLock<Vec<PathBuf>> = OnceLock::new();
const CALLBACK_BUFFER_LIMIT_BYTES: usize = 1024 * 1024;

thread_local! {
    static CALLBACK_LINE_BUFFER: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn ok_result() -> CrabResult {
    CrabResult {
        code: CRAB_OK,
        message: std::ptr::null_mut(),
    }
}

fn err_result(code: i32, msg: &str) -> CrabResult {
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("unknown error").expect("cstring"));
    CrabResult {
        code,
        message: c.into_raw(),
    }
}

fn lock_err(name: &str) -> CrabResult {
    err_result(CRAB_ERR_INTERNAL, &format!("{name} lock poisoned"))
}

macro_rules! ffi_entry {
    ($body:block) => {{
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> CrabResult { $body }));
        result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
    }};
}

macro_rules! ffi_try {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(result) => return result,
        }
    };
}

macro_rules! ffi_with_handle {
    ($handle:expr, $h:ident, $body:block) => {{
        let $h = ffi_try!(handle_ref($handle));
        $body
    }};
}

macro_rules! ffi_with_stopped_handle {
    ($handle:expr, $h:ident, $body:block) => {{
        ffi_with_handle!($handle, $h, {
            ffi_try!(ensure_not_running($h));
            $body
        })
    }};
}

macro_rules! ffi_lock {
    ($mutex:expr, $name:literal) => {
        match $mutex.lock() {
            Ok(guard) => guard,
            Err(_) => return lock_err($name),
        }
    };
}

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned(),
    )
}

unsafe fn require_cstr(ptr: *const c_char, name: &str) -> Result<String, CrabResult> {
    if ptr.is_null() {
        return Err(err_result(
            CRAB_ERR_INVALID_ARG,
            &format!("{name} must not be null"),
        ));
    }
    Ok(unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned())
}

fn handle_ref<'a>(handle: *mut CrabProxyHandle) -> Result<&'a CrabProxyHandle, CrabResult> {
    match unsafe { handle.as_ref() } {
        Some(h) => Ok(h),
        None => Err(err_result(CRAB_ERR_INVALID_ARG, "null handle")),
    }
}

fn ensure_not_running(handle: &CrabProxyHandle) -> Result<(), CrabResult> {
    if handle.running.load(Ordering::SeqCst) {
        Err(err_result(CRAB_ERR_STATE, "proxy is running"))
    } else {
        Ok(())
    }
}

fn parse_status_code(raw: u16, arg_name: &str) -> Result<StatusCode, CrabResult> {
    StatusCode::from_u16(raw).map_err(|_| {
        err_result(
            CRAB_ERR_INVALID_ARG,
            &format!("{arg_name} must be a valid HTTP status code"),
        )
    })
}

fn map_local_allowed_roots() -> &'static [PathBuf] {
    MAP_LOCAL_ALLOWED_ROOTS
        .get_or_init(compute_map_local_allowed_roots)
        .as_slice()
}

fn compute_map_local_allowed_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(value) = std::env::var_os("CRAB_MAP_LOCAL_ALLOWED_ROOTS") {
        for raw in std::env::split_paths(&value) {
            if let Some(canonical) = canonical_root(&raw) {
                roots.push(canonical);
            }
        }
        if !roots.is_empty() {
            return roots;
        }
    }

    if let Ok(cwd) = std::env::current_dir()
        && let Some(canonical) = canonical_root(&cwd)
    {
        roots.push(canonical);
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
        && let Some(canonical) = canonical_root(&home)
    {
        roots.push(canonical);
    }
    if let Some(canonical) = canonical_root(&std::env::temp_dir()) {
        roots.push(canonical);
    }

    roots.sort();
    roots.dedup();
    roots
}

fn canonical_root(path: &Path) -> Option<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(canonical) => Some(canonical),
        Err(_) if path.is_absolute() => Some(path.to_path_buf()),
        Err(_) => None,
    }
}

fn validate_map_local_file_path(raw_path: &str) -> Result<PathBuf, CrabResult> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err(err_result(
            CRAB_ERR_INVALID_ARG,
            "file_path must not be empty",
        ));
    }

    let path = PathBuf::from(trimmed);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(err_result(
            CRAB_ERR_INVALID_ARG,
            "file_path must not contain parent-directory traversals",
        ));
    }

    let absolute = if path.is_absolute() {
        path
    } else {
        let cwd = std::env::current_dir().map_err(|err| {
            err_result(
                CRAB_ERR_IO,
                &format!("failed to resolve current directory: {err}"),
            )
        })?;
        cwd.join(path)
    };

    let canonical = std::fs::canonicalize(&absolute).map_err(|err| {
        err_result(
            CRAB_ERR_INVALID_ARG,
            &format!("file_path must reference an existing file: {err}"),
        )
    })?;

    let metadata = std::fs::metadata(&canonical).map_err(|err| {
        err_result(
            CRAB_ERR_IO,
            &format!("failed to read file metadata for map_local: {err}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(err_result(
            CRAB_ERR_INVALID_ARG,
            "file_path must reference a regular file",
        ));
    }

    if !map_local_allowed_roots()
        .iter()
        .any(|allowed_root| canonical.starts_with(allowed_root))
    {
        return Err(err_result(
            CRAB_ERR_INVALID_ARG,
            "file_path is outside allowed map_local roots; set CRAB_MAP_LOCAL_ALLOWED_ROOTS to permit it",
        ));
    }

    Ok(canonical)
}

fn runtime_worker_threads() -> usize {
    let available = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(4);
    parse_runtime_worker_threads(
        std::env::var("CRAB_TOKIO_WORKER_THREADS").ok().as_deref(),
        available,
    )
}

fn parse_runtime_worker_threads(raw: Option<&str>, available: usize) -> usize {
    const MAX_WORKER_THREADS: usize = 32;

    let default_threads = available.clamp(1, MAX_WORKER_THREADS);
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.clamp(1, MAX_WORKER_THREADS))
        .unwrap_or(default_threads)
}

fn stop_inner(handle: &CrabProxyHandle) -> Result<()> {
    if !handle.running.load(Ordering::SeqCst) {
        return Ok(());
    }

    if let Ok(mut shutdown_tx_guard) = handle.shutdown_tx.lock() {
        if let Some(shutdown_tx) = shutdown_tx_guard.take() {
            let _ = shutdown_tx.send(true);
        }
    }

    let join = handle
        .task
        .lock()
        .map_err(|_| anyhow::anyhow!("task lock poisoned"))?
        .take();

    if let Some(task) = join {
        let join_out = handle
            .runtime
            .block_on(task)
            .context("failed to join proxy task")?;
        join_out?;
    }

    handle.running.store(false, Ordering::SeqCst);
    Ok(())
}

fn init_tracing_once() {
    LOG_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(CallbackWriter)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

fn log_callback_store() -> &'static RwLock<Option<LogCallback>> {
    LOG_CALLBACK.get_or_init(|| RwLock::new(None))
}

fn infer_level(line: &str) -> u8 {
    if line.contains("ERROR") {
        4
    } else if line.contains("WARN") {
        3
    } else if line.contains("DEBUG") {
        1
    } else if line.contains("TRACE") {
        0
    } else {
        2
    }
}

fn infer_level_bytes(line: &[u8]) -> u8 {
    std::str::from_utf8(line).map_or(2, infer_level)
}

fn trim_log_line_end(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    &buf[..end]
}

fn emit_log_callback_line(cb: LogCallback, raw_line: &[u8]) {
    let trimmed = trim_log_line_end(raw_line);
    if trimmed.is_empty() {
        return;
    }

    if let Ok(c_msg) = CString::new(trimmed) {
        (cb.func)(cb.user_data_ptr(), infer_level_bytes(trimmed), c_msg.as_ptr());
        return;
    }

    let fallback = String::from_utf8_lossy(trimmed);
    if let Ok(c_msg) = CString::new(fallback.as_bytes()) {
        (cb.func)(
            cb.user_data_ptr(),
            infer_level(fallback.as_ref()),
            c_msg.as_ptr(),
        );
    }
}

struct CallbackWriter;

impl std::io::Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(guard) = log_callback_store().read()
            && let Some(cb) = *guard
        {
            let mut completed_lines: Vec<Vec<u8>> = Vec::new();
            CALLBACK_LINE_BUFFER.with(|line_buffer| {
                let mut line_buffer = line_buffer.borrow_mut();
                line_buffer.extend_from_slice(buf);

                while let Some(pos) = line_buffer.iter().position(|byte| *byte == b'\n') {
                    completed_lines.push(line_buffer.drain(..=pos).collect());
                }

                if line_buffer.len() > CALLBACK_BUFFER_LIMIT_BYTES {
                    completed_lines.push(std::mem::take(&mut *line_buffer));
                }
            });

            // Keep the read lock held while invoking callback so callback teardown
            // (`crab_set_log_callback(nil, nil)`) waits for in-flight calls.
            for line in completed_lines {
                emit_log_callback_line(cb, &line);
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Ok(guard) = log_callback_store().read()
            && let Some(cb) = *guard
        {
            let trailing = CALLBACK_LINE_BUFFER.with(|line_buffer| {
                let mut line_buffer = line_buffer.borrow_mut();
                if line_buffer.is_empty() {
                    None
                } else {
                    Some(std::mem::take(&mut *line_buffer))
                }
            });

            if let Some(line) = trailing {
                emit_log_callback_line(cb, &line);
            }
        }

        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CallbackWriter {
    type Writer = CallbackWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CallbackWriter
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_set_log_callback(callback: CrabLogCallback, user_data: *mut c_void) {
    init_tracing_once();
    if let Ok(mut guard) = log_callback_store().write() {
        *guard = callback.map(|func| LogCallback {
            func,
            user_data: user_data as usize,
        });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_create(
    out_handle: *mut *mut CrabProxyHandle,
    listen_addr: *const c_char,
) -> CrabResult {
    ffi_entry!({
        if out_handle.is_null() {
            return err_result(CRAB_ERR_INVALID_ARG, "out_handle must not be null");
        }

        let listen =
            unsafe { cstr_to_string(listen_addr) }.unwrap_or_else(|| "127.0.0.1:8080".to_string());

        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(runtime_worker_threads())
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                return err_result(
                    CRAB_ERR_INTERNAL,
                    &format!("failed to create runtime: {err}"),
                );
            }
        };

        let handle = CrabProxyHandle {
            runtime,
            listen_addr: Mutex::new(listen),
            ca: Mutex::new(None),
            rules: Mutex::new(Rules::default()),
            inspect: Mutex::new(InspectConfig {
                enabled: false,
                sample_bytes: 16 * 1024,
                spool: false,
                spool_dir: None,
                spool_max_bytes: 100 * 1024 * 1024,
            }),
            shutdown_tx: Mutex::new(None),
            task: Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
        };

        let boxed = Box::new(handle);
        unsafe {
            *out_handle = Box::into_raw(boxed);
        }
        ok_result()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_set_listen_addr(
    handle: *mut CrabProxyHandle,
    listen_addr: *const c_char,
) -> CrabResult {
    ffi_entry!({
        ffi_with_handle!(handle, h, {
            if h.running.load(Ordering::SeqCst) {
                return err_result(CRAB_ERR_STATE, "proxy is running");
            }

            let listen = ffi_try!(unsafe { require_cstr(listen_addr, "listen_addr") });
            let mut guard = ffi_lock!(h.listen_addr, "listen_addr");
            *guard = listen;
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_set_port(handle: *mut CrabProxyHandle, port: u16) -> CrabResult {
    ffi_entry!({
        if port == 0 {
            return err_result(CRAB_ERR_INVALID_ARG, "port must be > 0");
        }

        ffi_with_handle!(handle, h, {
            if h.running.load(Ordering::SeqCst) {
                return err_result(CRAB_ERR_STATE, "proxy is running");
            }

            let mut guard = ffi_lock!(h.listen_addr, "listen_addr");
            let host = guard
                .rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| "127.0.0.1".to_string());
            *guard = format!("{host}:{port}");
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_load_ca(
    handle: *mut CrabProxyHandle,
    cert_path: *const c_char,
    key_path: *const c_char,
) -> CrabResult {
    ffi_entry!({
        ffi_with_handle!(handle, h, {
            let cert = ffi_try!(unsafe { require_cstr(cert_path, "cert_path") });
            let key = ffi_try!(unsafe { require_cstr(key_path, "key_path") });

            match CertificateAuthority::from_pem_files(cert.as_ref(), key.as_ref()) {
                Ok(ca) => {
                    let mut guard = ffi_lock!(h.ca, "ca");
                    *guard = Some(Arc::new(ca));
                    ok_result()
                }
                Err(err) => err_result(CRAB_ERR_CA, &format!("{err:#}")),
            }
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_set_inspect_enabled(
    handle: *mut CrabProxyHandle,
    enabled: bool,
) -> CrabResult {
    ffi_entry!({
        ffi_with_handle!(handle, h, {
            let mut guard = ffi_lock!(h.inspect, "inspect");
            guard.enabled = enabled;
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_clear(handle: *mut CrabProxyHandle) -> CrabResult {
    ffi_entry!({
        ffi_with_stopped_handle!(handle, h, {
            let mut guard = ffi_lock!(h.rules, "rules");
            guard.allowlist.clear();
            guard.map_local.clear();
            guard.status_rewrite.clear();
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_allow(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
) -> CrabResult {
    ffi_entry!({
        ffi_with_stopped_handle!(handle, h, {
            let matcher = ffi_try!(unsafe { require_cstr(matcher, "matcher") });
            let matcher = matcher.trim();
            if matcher.is_empty() {
                return err_result(CRAB_ERR_INVALID_ARG, "matcher must not be empty");
            }

            let mut guard = ffi_lock!(h.rules, "rules");
            guard.allowlist.push(AllowRule::new(matcher));
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_map_local_file(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
    file_path: *const c_char,
    status_code: u16,
    content_type: *const c_char,
) -> CrabResult {
    ffi_entry!({
        ffi_with_stopped_handle!(handle, h, {
            let matcher = ffi_try!(unsafe { require_cstr(matcher, "matcher") });
            let file_path = ffi_try!(unsafe { require_cstr(file_path, "file_path") });
            let file_path = ffi_try!(validate_map_local_file_path(&file_path));
            let status = ffi_try!(parse_status_code(status_code, "status_code"));
            let content_type = unsafe { cstr_to_string(content_type) };

            let mut guard = ffi_lock!(h.rules, "rules");
            guard.map_local.push(MapLocalRule {
                matcher: Matcher::new(matcher),
                source: MapSource::File(file_path),
                status,
                content_type,
            });
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_map_local_text(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
    text: *const c_char,
    status_code: u16,
    content_type: *const c_char,
) -> CrabResult {
    ffi_entry!({
        ffi_with_stopped_handle!(handle, h, {
            let matcher = ffi_try!(unsafe { require_cstr(matcher, "matcher") });
            let text = ffi_try!(unsafe { require_cstr(text, "text") });
            let status = ffi_try!(parse_status_code(status_code, "status_code"));
            let content_type = unsafe { cstr_to_string(content_type) };

            let mut guard = ffi_lock!(h.rules, "rules");
            guard.map_local.push(MapLocalRule {
                matcher: Matcher::new(matcher),
                source: MapSource::Text(text),
                status,
                content_type,
            });
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_status_rewrite(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
    from_status_code: i32,
    to_status_code: u16,
) -> CrabResult {
    ffi_entry!({
        ffi_with_stopped_handle!(handle, h, {
            let matcher = ffi_try!(unsafe { require_cstr(matcher, "matcher") });
            let to_status = ffi_try!(parse_status_code(to_status_code, "to_status_code"));
            let from_status = if from_status_code < 0 {
                None
            } else {
                let raw = match u16::try_from(from_status_code) {
                    Ok(v) => v,
                    Err(_) => {
                        return err_result(
                            CRAB_ERR_INVALID_ARG,
                            "from_status_code must be negative (any) or valid HTTP status",
                        );
                    }
                };
                Some(ffi_try!(parse_status_code(raw, "from_status_code")))
            };

            let mut guard = ffi_lock!(h.rules, "rules");
            guard.status_rewrite.push(StatusRewriteRule {
                matcher: Matcher::new(matcher),
                from: from_status,
                to: to_status,
            });
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_start(handle: *mut CrabProxyHandle) -> CrabResult {
    ffi_entry!({
        ffi_with_handle!(handle, h, {
            if h.running.load(Ordering::SeqCst) {
                return err_result(CRAB_ERR_STATE, "proxy is already running");
            }

            // Reap previous task if it exists.
            let prior_task = {
                let mut guard = ffi_lock!(h.task, "task");
                guard.take()
            };
            if let Some(task) = prior_task {
                let _ = h.runtime.block_on(task);
            }

            let listen = ffi_lock!(h.listen_addr, "listen_addr").clone();
            let ca = ffi_lock!(h.ca, "ca").clone();
            let rules = Arc::new(ffi_lock!(h.rules, "rules").clone());
            let inspect = Arc::new(ffi_lock!(h.inspect, "inspect").clone());

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            {
                let mut guard = ffi_lock!(h.shutdown_tx, "shutdown_tx");
                *guard = Some(shutdown_tx);
            }

            let running = h.running.clone();
            running.store(true, Ordering::SeqCst);

            let task = h.runtime.spawn(async move {
                let result =
                    proxy::run_with_shutdown(&listen, ca, rules, inspect, shutdown_rx).await;
                running.store(false, Ordering::SeqCst);
                result
            });

            let mut guard = ffi_lock!(h.task, "task");
            *guard = Some(task);
            ok_result()
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_stop(handle: *mut CrabProxyHandle) -> CrabResult {
    ffi_entry!({
        ffi_with_handle!(handle, h, {
            match stop_inner(h) {
                Ok(()) => ok_result(),
                Err(err) => err_result(CRAB_ERR_IO, &format!("{err:#}")),
            }
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_is_running(handle: *const CrabProxyHandle) -> bool {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match unsafe { handle.as_ref() } {
            Some(h) => h,
            None => return false,
        };
        h.running.load(Ordering::SeqCst)
    }));

    result.unwrap_or(false)
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_destroy(handle: *mut CrabProxyHandle) {
    if handle.is_null() {
        return;
    }

    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let boxed = unsafe { Box::from_raw(handle) };
        let _ = stop_inner(&boxed);
        drop(boxed);
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_ca_generate(
    common_name: *const c_char,
    days: u32,
    out_cert: *const c_char,
    out_key: *const c_char,
) -> CrabResult {
    ffi_entry!({
        let common_name = ffi_try!(unsafe { require_cstr(common_name, "common_name") });
        let out_cert = PathBuf::from(ffi_try!(unsafe { require_cstr(out_cert, "out_cert") }));
        let out_key = PathBuf::from(ffi_try!(unsafe { require_cstr(out_key, "out_key") }));

        match ca::generate_ca_to_files(&common_name, days, &out_cert, &out_key) {
            Ok(()) => ok_result(),
            Err(err) => err_result(CRAB_ERR_CA, &format!("{err:#}")),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct OwnedHandle(*mut CrabProxyHandle);

    impl OwnedHandle {
        fn raw(&self) -> *mut CrabProxyHandle {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            crab_proxy_destroy(self.0);
        }
    }

    fn crab_result_to_owned(result: CrabResult) -> (i32, String) {
        let message = if result.message.is_null() {
            String::new()
        } else {
            let message = unsafe { CStr::from_ptr(result.message) }
                .to_string_lossy()
                .into_owned();
            crab_free_string(result.message);
            message
        };
        (result.code, message)
    }

    fn assert_ok(result: CrabResult) {
        let (code, message) = crab_result_to_owned(result);
        assert_eq!(code, CRAB_OK, "unexpected error: {message}");
    }

    fn create_handle(listen_addr: Option<&str>) -> OwnedHandle {
        let mut raw: *mut CrabProxyHandle = std::ptr::null_mut();
        let listen_cstr = listen_addr.map(|s| CString::new(s).expect("listen cstring"));
        let listen_ptr = listen_cstr
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr());
        assert_ok(crab_proxy_create(&mut raw, listen_ptr));
        assert!(!raw.is_null(), "create returned null handle");
        OwnedHandle(raw)
    }

    fn choose_free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    fn unique_temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("crab-mitm-{prefix}-{nanos}-{suffix}"))
    }

    fn parse_c_header_error_codes() -> HashMap<String, i32> {
        let header_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include/crab_mitm.h");
        let content = fs::read_to_string(&header_path).expect("read crab_mitm.h");
        let mut in_enum = false;
        let mut codes = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("enum {") {
                in_enum = true;
                continue;
            }
            if in_enum && line.starts_with("};") {
                break;
            }
            if !in_enum || line.is_empty() || line.starts_with("/*") {
                continue;
            }

            let line = line.trim_end_matches(',');
            if let Some((name, raw_value)) = line.split_once('=') {
                let name = name.trim().to_string();
                let value = raw_value
                    .trim()
                    .parse::<i32>()
                    .unwrap_or_else(|_| panic!("invalid enum value in header: {line}"));
                codes.insert(name, value);
            }
        }

        assert!(
            !codes.is_empty(),
            "failed to parse any error codes from header"
        );
        codes
    }

    #[test]
    fn ffi_create_rejects_null_out_handle() {
        let (code, message) =
            crab_result_to_owned(crab_proxy_create(std::ptr::null_mut(), std::ptr::null()));
        assert_eq!(code, CRAB_ERR_INVALID_ARG);
        assert!(message.contains("out_handle"));
    }

    #[test]
    fn ffi_create_and_destroy_roundtrip() {
        let handle = create_handle(None);
        assert!(!crab_proxy_is_running(handle.raw()));
    }

    #[test]
    fn ffi_set_port_rejects_zero() {
        let handle = create_handle(None);
        let (code, message) = crab_result_to_owned(crab_proxy_set_port(handle.raw(), 0));
        assert_eq!(code, CRAB_ERR_INVALID_ARG);
        assert!(message.contains("port"));
    }

    #[test]
    fn ffi_map_local_file_rejects_parent_traversal() {
        let handle = create_handle(None);
        let matcher = CString::new("example.com/*").expect("matcher cstring");
        let file_path = CString::new("../etc/passwd").expect("file path cstring");
        let (code, message) = crab_result_to_owned(crab_proxy_rules_add_map_local_file(
            handle.raw(),
            matcher.as_ptr(),
            file_path.as_ptr(),
            200,
            std::ptr::null(),
        ));
        assert_eq!(code, CRAB_ERR_INVALID_ARG);
        assert!(message.contains("parent-directory"));
    }

    #[test]
    fn ffi_map_local_file_accepts_existing_file_in_allowed_roots() {
        let handle = create_handle(None);
        let path = unique_temp_path("ffi-map-local", "ok.txt");
        fs::write(&path, b"ok").expect("write temp file");

        let matcher = CString::new("example.com/*").expect("matcher cstring");
        let file_path = CString::new(path.display().to_string()).expect("file path cstring");
        let (code, message) = crab_result_to_owned(crab_proxy_rules_add_map_local_file(
            handle.raw(),
            matcher.as_ptr(),
            file_path.as_ptr(),
            200,
            std::ptr::null(),
        ));
        let _ = fs::remove_file(&path);

        assert_eq!(
            code, CRAB_OK,
            "expected map_local file rule success: {message}"
        );
    }

    #[test]
    fn ffi_rejects_rule_changes_while_running() {
        let listen = format!("127.0.0.1:{}", choose_free_port());
        let handle = create_handle(Some(&listen));
        assert_ok(crab_proxy_start(handle.raw()));

        let matcher = CString::new("example.com/*").expect("matcher cstring");
        let (code, message) =
            crab_result_to_owned(crab_proxy_rules_add_allow(handle.raw(), matcher.as_ptr()));
        assert_eq!(code, CRAB_ERR_STATE);
        assert!(message.contains("running"));

        assert_ok(crab_proxy_stop(handle.raw()));
    }

    #[test]
    fn ffi_error_codes_match_c_header() {
        let codes = parse_c_header_error_codes();
        assert_eq!(codes.get("CRAB_OK"), Some(&CRAB_OK));
        assert_eq!(
            codes.get("CRAB_ERR_INVALID_ARG"),
            Some(&CRAB_ERR_INVALID_ARG)
        );
        assert_eq!(codes.get("CRAB_ERR_STATE"), Some(&CRAB_ERR_STATE));
        assert_eq!(codes.get("CRAB_ERR_IO"), Some(&CRAB_ERR_IO));
        assert_eq!(codes.get("CRAB_ERR_CA"), Some(&CRAB_ERR_CA));
        assert_eq!(codes.get("CRAB_ERR_INTERNAL"), Some(&CRAB_ERR_INTERNAL));
    }

    #[test]
    fn runtime_worker_threads_defaults_to_available_parallelism() {
        assert_eq!(parse_runtime_worker_threads(None, 12), 12);
        assert_eq!(parse_runtime_worker_threads(None, 0), 1);
    }

    #[test]
    fn runtime_worker_threads_honors_valid_env_override() {
        assert_eq!(parse_runtime_worker_threads(Some("6"), 12), 6);
        assert_eq!(parse_runtime_worker_threads(Some(" 2 "), 12), 2);
    }

    #[test]
    fn runtime_worker_threads_rejects_invalid_values() {
        assert_eq!(parse_runtime_worker_threads(Some("0"), 8), 8);
        assert_eq!(parse_runtime_worker_threads(Some("-1"), 8), 8);
        assert_eq!(parse_runtime_worker_threads(Some("abc"), 8), 8);
    }
}
