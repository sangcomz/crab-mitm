use std::collections::HashMap;
use std::error::Error as StdError;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(1);

type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

struct ParsedHttp {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct ProxyProcess {
    child: Child,
}

impl ProxyProcess {
    fn spawn(args: &[String]) -> io::Result<Self> {
        let bin = discover_binary_path()?;

        let child = Command::new(bin)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        Ok(Self { child })
    }

    fn wait_ready(&mut self, addr: SocketAddr, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if TcpStream::connect(addr).is_ok() {
                return Ok(());
            }

            if let Some(status) = self.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "proxy exited before ready: {status}"
                )));
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("proxy did not become ready at {addr}"),
                ));
            }

            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn streams_large_body_and_spools_files() -> TestResult {
    let spool_dir = create_temp_dir("crab-mitm-it-spool")?;
    let (upstream_addr, req_rx, upstream_thread) = start_echo_upstream_server()?;

    let proxy_addr = choose_free_addr()?;
    let args = vec![
        "run".to_string(),
        "--listen".to_string(),
        proxy_addr.to_string(),
        "--inspect-body".to_string(),
        "--inspect-sample-bytes".to_string(),
        "64".to_string(),
        "--inspect-spool".to_string(),
        "--inspect-spool-dir".to_string(),
        spool_dir.display().to_string(),
        "--inspect-spool-max-bytes".to_string(),
        "131072".to_string(),
    ];

    let mut proxy = ProxyProcess::spawn(&args)?;
    proxy.wait_ready(proxy_addr, Duration::from_secs(10))?;

    let mut body = Vec::with_capacity(300_000);
    for i in 0..300_000usize {
        body.push((i % 251) as u8);
    }

    let absolute_url = format!("http://{upstream_addr}/echo");
    let response = send_proxy_request(
        proxy_addr,
        "POST",
        &absolute_url,
        &upstream_addr.to_string(),
        &body,
    )?;

    assert_eq!(response.status, 200);
    assert_eq!(response.body, body);

    let upstream_received = req_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|err| io::Error::new(io::ErrorKind::TimedOut, format!("upstream recv: {err}")))?;
    assert_eq!(upstream_received, body);

    let server_result = upstream_thread
        .join()
        .map_err(|_| io::Error::other("upstream thread panicked"))?;
    server_result?;

    thread::sleep(Duration::from_millis(200));

    let mut request_sizes = Vec::new();
    let mut response_sizes = Vec::new();
    for entry in fs::read_dir(&spool_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let size = entry.metadata()?.len();

        if file_name.contains("-request-") {
            request_sizes.push(size);
        }
        if file_name.contains("-response-") {
            response_sizes.push(size);
        }
    }

    assert!(
        !request_sizes.is_empty(),
        "expected at least one request spool file"
    );
    assert!(
        !response_sizes.is_empty(),
        "expected at least one response spool file"
    );

    for size in request_sizes.into_iter().chain(response_sizes.into_iter()) {
        assert!(size > 0, "spool file should not be empty");
        assert!(size <= 131_072, "spool file exceeded max size: {size}");
    }

    fs::remove_dir_all(&spool_dir)?;
    Ok(())
}

#[test]
fn applies_map_local_and_status_rewrite_via_cli() -> TestResult {
    let temp_dir = create_temp_dir("crab-mitm-it-map")?;
    let local_file = temp_dir.join("local.txt");
    fs::write(&local_file, b"LOCAL-INTEGRATION\n")?;

    let proxy_addr = choose_free_addr()?;
    let map_arg = format!("example.com/={}", local_file.display());
    let rewrite_arg = "example.com/=200:418".to_string();

    let args = vec![
        "run".to_string(),
        "--listen".to_string(),
        proxy_addr.to_string(),
        "--map".to_string(),
        map_arg,
        "--rewrite-status".to_string(),
        rewrite_arg,
    ];

    let mut proxy = ProxyProcess::spawn(&args)?;
    proxy.wait_ready(proxy_addr, Duration::from_secs(10))?;

    let response = send_proxy_request(
        proxy_addr,
        "GET",
        "http://example.com/health",
        "example.com",
        &[],
    )?;

    assert_eq!(response.status, 418);
    assert_eq!(response.body, b"LOCAL-INTEGRATION\n");
    assert_eq!(
        response.headers.get("x-crab-mitm").map(|v| v.as_str()),
        Some("map_local")
    );
    assert!(
        response.headers.contains_key("x-crab-mitm-status-rewrite"),
        "status rewrite header should exist"
    );

    fs::remove_dir_all(temp_dir)?;
    Ok(())
}

fn send_proxy_request(
    proxy_addr: SocketAddr,
    method: &str,
    absolute_url: &str,
    host: &str,
    body: &[u8],
) -> io::Result<ParsedHttp> {
    let mut stream = TcpStream::connect(proxy_addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    let request = format!(
        "{method} {absolute_url} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;

    read_http_response(&mut stream)
}

fn start_echo_upstream_server() -> io::Result<(
    SocketAddr,
    mpsc::Receiver<Vec<u8>>,
    thread::JoinHandle<io::Result<()>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let handle = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;

        let request = read_http_request(&mut stream)?;
        tx.send(request.body.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "failed to send body"))?;

        write_http_response(&mut stream, 200, &request.body)
    });

    Ok((addr, rx, handle))
}

fn read_http_request(stream: &mut TcpStream) -> io::Result<ParsedHttp> {
    read_http_message(stream, true)
}

fn read_http_response(stream: &mut TcpStream) -> io::Result<ParsedHttp> {
    read_http_message(stream, false)
}

fn read_http_message(stream: &mut TcpStream, is_request: bool) -> io::Result<ParsedHttp> {
    let mut buffer = Vec::new();
    let mut tmp = [0u8; 8192];

    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before headers",
            ));
        }
        buffer.extend_from_slice(&tmp[..n]);

        if let Some(pos) = find_subsequence(&buffer, b"\r\n\r\n") {
            break pos;
        }

        if buffer.len() > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    };

    let (head, body_start) = buffer.split_at(header_end + 4);
    let head_text = String::from_utf8_lossy(head);
    let mut lines = head_text.split("\r\n");
    let start_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing start line"))?;

    let status = if is_request {
        if start_line.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty request line",
            ));
        }
        0
    } else {
        let mut parts = start_line.split_whitespace();
        let _http = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing http version"))?;
        let code = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing status code"))?
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid status code"))?;
        code
    };

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = body_start.to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before full body",
            ));
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);

    Ok(ParsedHttp {
        status,
        headers,
        body,
    })
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        418 => "I'm a teapot",
        _ => "OK",
    };

    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    stream.write_all(headers.as_bytes())?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok(())
}

fn choose_free_addr() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn create_temp_dir(prefix: &str) -> io::Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("{prefix}-{now}-{id}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn discover_binary_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_crab-mitm")
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_crab_mitm"))
        .map(PathBuf::from)
    {
        return Ok(path);
    }

    let fallback = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "crab-mitm.exe"
        } else {
            "crab-mitm"
        });

    if fallback.exists() {
        return Ok(fallback);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "could not locate crab-mitm binary for integration test",
    ))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
