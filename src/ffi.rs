use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
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

struct CallbackWriter;

impl std::io::Write for CallbackWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(guard) = log_callback_store().read()
            && let Some(cb) = *guard
        {
            let msg = String::from_utf8_lossy(buf);
            let trimmed = msg.trim_end();
            if !trimmed.is_empty() {
                if let Ok(c_msg) = CString::new(trimmed) {
                    // Keep the read lock held while invoking callback so callback teardown
                    // (`crab_set_log_callback(nil, nil)`) waits for in-flight calls.
                    (cb.func)(cb.user_data_ptr(), infer_level(trimmed), c_msg.as_ptr());
                }
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out_handle.is_null() {
            return err_result(CRAB_ERR_INVALID_ARG, "out_handle must not be null");
        }

        let listen =
            unsafe { cstr_to_string(listen_addr) }.unwrap_or_else(|| "127.0.0.1:8080".to_string());

        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
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
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_set_listen_addr(
    handle: *mut CrabProxyHandle,
    listen_addr: *const c_char,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };

        if h.running.load(Ordering::SeqCst) {
            return err_result(CRAB_ERR_STATE, "proxy is running");
        }

        let listen = match unsafe { require_cstr(listen_addr, "listen_addr") } {
            Ok(s) => s,
            Err(r) => return r,
        };

        match h.listen_addr.lock() {
            Ok(mut guard) => {
                *guard = listen;
                ok_result()
            }
            Err(_) => lock_err("listen_addr"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_set_port(handle: *mut CrabProxyHandle, port: u16) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if port == 0 {
            return err_result(CRAB_ERR_INVALID_ARG, "port must be > 0");
        }

        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };

        if h.running.load(Ordering::SeqCst) {
            return err_result(CRAB_ERR_STATE, "proxy is running");
        }

        match h.listen_addr.lock() {
            Ok(mut guard) => {
                let host = guard
                    .rsplit_once(':')
                    .map(|(h, _)| h.to_string())
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                *guard = format!("{host}:{port}");
                ok_result()
            }
            Err(_) => lock_err("listen_addr"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_load_ca(
    handle: *mut CrabProxyHandle,
    cert_path: *const c_char,
    key_path: *const c_char,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };

        let cert = match unsafe { require_cstr(cert_path, "cert_path") } {
            Ok(s) => s,
            Err(r) => return r,
        };
        let key = match unsafe { require_cstr(key_path, "key_path") } {
            Ok(s) => s,
            Err(r) => return r,
        };

        match CertificateAuthority::from_pem_files(cert.as_ref(), key.as_ref()) {
            Ok(ca) => match h.ca.lock() {
                Ok(mut guard) => {
                    *guard = Some(Arc::new(ca));
                    ok_result()
                }
                Err(_) => lock_err("ca"),
            },
            Err(err) => err_result(CRAB_ERR_CA, &format!("{err:#}")),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_set_inspect_enabled(
    handle: *mut CrabProxyHandle,
    enabled: bool,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };

        match h.inspect.lock() {
            Ok(mut guard) => {
                guard.enabled = enabled;
                ok_result()
            }
            Err(_) => lock_err("inspect"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_clear(handle: *mut CrabProxyHandle) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if let Err(r) = ensure_not_running(h) {
            return r;
        }

        match h.rules.lock() {
            Ok(mut guard) => {
                guard.allowlist.clear();
                guard.map_local.clear();
                guard.status_rewrite.clear();
                ok_result()
            }
            Err(_) => lock_err("rules"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_allow(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if let Err(r) = ensure_not_running(h) {
            return r;
        }

        let matcher = match unsafe { require_cstr(matcher, "matcher") } {
            Ok(v) => v,
            Err(r) => return r,
        };

        let matcher = matcher.trim();
        if matcher.is_empty() {
            return err_result(CRAB_ERR_INVALID_ARG, "matcher must not be empty");
        }

        match h.rules.lock() {
            Ok(mut guard) => {
                guard.allowlist.push(AllowRule::new(matcher));
                ok_result()
            }
            Err(_) => lock_err("rules"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_map_local_file(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
    file_path: *const c_char,
    status_code: u16,
    content_type: *const c_char,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if let Err(r) = ensure_not_running(h) {
            return r;
        }

        let matcher = match unsafe { require_cstr(matcher, "matcher") } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let file_path = match unsafe { require_cstr(file_path, "file_path") } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let status = match parse_status_code(status_code, "status_code") {
            Ok(v) => v,
            Err(r) => return r,
        };
        let content_type = unsafe { cstr_to_string(content_type) };

        match h.rules.lock() {
            Ok(mut guard) => {
                guard.map_local.push(MapLocalRule {
                    matcher: Matcher::new(matcher),
                    source: MapSource::File(PathBuf::from(file_path)),
                    status,
                    content_type,
                });
                ok_result()
            }
            Err(_) => lock_err("rules"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_map_local_text(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
    text: *const c_char,
    status_code: u16,
    content_type: *const c_char,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if let Err(r) = ensure_not_running(h) {
            return r;
        }

        let matcher = match unsafe { require_cstr(matcher, "matcher") } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let text = match unsafe { require_cstr(text, "text") } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let status = match parse_status_code(status_code, "status_code") {
            Ok(v) => v,
            Err(r) => return r,
        };
        let content_type = unsafe { cstr_to_string(content_type) };

        match h.rules.lock() {
            Ok(mut guard) => {
                guard.map_local.push(MapLocalRule {
                    matcher: Matcher::new(matcher),
                    source: MapSource::Text(text),
                    status,
                    content_type,
                });
                ok_result()
            }
            Err(_) => lock_err("rules"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_rules_add_status_rewrite(
    handle: *mut CrabProxyHandle,
    matcher: *const c_char,
    from_status_code: i32,
    to_status_code: u16,
) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if let Err(r) = ensure_not_running(h) {
            return r;
        }

        let matcher = match unsafe { require_cstr(matcher, "matcher") } {
            Ok(v) => v,
            Err(r) => return r,
        };
        let to_status = match parse_status_code(to_status_code, "to_status_code") {
            Ok(v) => v,
            Err(r) => return r,
        };
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
            match parse_status_code(raw, "from_status_code") {
                Ok(v) => Some(v),
                Err(r) => return r,
            }
        };

        match h.rules.lock() {
            Ok(mut guard) => {
                guard.status_rewrite.push(StatusRewriteRule {
                    matcher: Matcher::new(matcher),
                    from: from_status,
                    to: to_status,
                });
                ok_result()
            }
            Err(_) => lock_err("rules"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_start(handle: *mut CrabProxyHandle) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };

        if h.running.load(Ordering::SeqCst) {
            return err_result(CRAB_ERR_STATE, "proxy is already running");
        }

        // Reap previous task if it exists.
        let prior_task = match h.task.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => return lock_err("task"),
        };
        if let Some(task) = prior_task {
            let _ = h.runtime.block_on(task);
        }

        let listen = match h.listen_addr.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return lock_err("listen_addr"),
        };
        let ca = match h.ca.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return lock_err("ca"),
        };
        let rules = match h.rules.lock() {
            Ok(guard) => Arc::new(guard.clone()),
            Err(_) => return lock_err("rules"),
        };
        let inspect = match h.inspect.lock() {
            Ok(guard) => Arc::new(guard.clone()),
            Err(_) => return lock_err("inspect"),
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        match h.shutdown_tx.lock() {
            Ok(mut guard) => {
                *guard = Some(shutdown_tx);
            }
            Err(_) => return lock_err("shutdown_tx"),
        }

        let running = h.running.clone();
        running.store(true, Ordering::SeqCst);

        let task = h.runtime.spawn(async move {
            let result = proxy::run_with_shutdown(&listen, ca, rules, inspect, shutdown_rx).await;
            running.store(false, Ordering::SeqCst);
            result
        });

        match h.task.lock() {
            Ok(mut guard) => {
                *guard = Some(task);
                ok_result()
            }
            Err(_) => lock_err("task"),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn crab_proxy_stop(handle: *mut CrabProxyHandle) -> CrabResult {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let h = match handle_ref(handle) {
            Ok(h) => h,
            Err(r) => return r,
        };

        match stop_inner(h) {
            Ok(()) => ok_result(),
            Err(err) => err_result(CRAB_ERR_IO, &format!("{err:#}")),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let common_name = match unsafe { require_cstr(common_name, "common_name") } {
            Ok(s) => s,
            Err(r) => return r,
        };
        let out_cert = match unsafe { require_cstr(out_cert, "out_cert") } {
            Ok(s) => PathBuf::from(s),
            Err(r) => return r,
        };
        let out_key = match unsafe { require_cstr(out_key, "out_key") } {
            Ok(s) => PathBuf::from(s),
            Err(r) => return r,
        };

        match ca::generate_ca_to_files(&common_name, days, &out_cert, &out_key) {
            Ok(()) => ok_result(),
            Err(err) => err_result(CRAB_ERR_CA, &format!("{err:#}")),
        }
    }));

    result.unwrap_or_else(|_| err_result(CRAB_ERR_INTERNAL, "internal panic"))
}
