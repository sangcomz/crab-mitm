use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::LazyConfigAcceptor;

const EXCLUDE_PORT_START: u16 = 50000;
const EXCLUDE_PORT_END: u16 = 50099;
const EXCLUDE_PORT_COUNT: u16 = EXCLUDE_PORT_END - EXCLUDE_PORT_START + 1;

static PORT_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
pub struct TransparentConfig {
    pub enabled: bool,
    pub listen_port: u16,
}

impl Default for TransparentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_port: 8889,
        }
    }
}

/// Result of extracting SNI from a TLS ClientHello.
/// Contains the hostname and the TLS stream ready for HTTP serving.
pub struct SniAccepted {
    pub hostname: String,
    pub tls_stream: TlsStream<TcpStream>,
}

/// Extract SNI hostname from a TLS ClientHello, generate a cert via the CA,
/// complete the TLS handshake, and return the decrypted stream.
pub async fn accept_tls_with_sni(
    stream: TcpStream,
    ca: &crate::ca::CertificateAuthority,
) -> Result<SniAccepted> {
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    tokio::pin!(acceptor);

    let start = acceptor
        .as_mut()
        .await
        .context("TLS ClientHello read failed")?;

    let client_hello = start.client_hello();
    let hostname = client_hello
        .server_name()
        .context("no SNI in TLS ClientHello")?
        .to_string();

    let tls_cfg = ca
        .server_config_for_host(&hostname)
        .await
        .with_context(|| format!("failed to build cert for {hostname}"))?;

    let tls_stream = start
        .into_stream(tls_cfg)
        .await
        .context("transparent TLS handshake failed")?;

    Ok(SniAccepted {
        hostname,
        tls_stream,
    })
}

fn next_exclude_port() -> u16 {
    let index = PORT_COUNTER.fetch_add(1, Ordering::Relaxed) as u16 % EXCLUDE_PORT_COUNT;
    EXCLUDE_PORT_START + index
}

/// Connect to an upstream server using a source port in the exclude range
/// (50000-50099) so that pf redirect rules don't catch our own connections.
pub async fn connect_transparent(addr: SocketAddr) -> Result<TcpStream> {
    const MAX_RETRIES: usize = 10;

    for attempt in 0..MAX_RETRIES {
        let port = next_exclude_port();
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        let local_addr: SocketAddr = if addr.is_ipv4() {
            ([0, 0, 0, 0], port).into()
        } else {
            ([0, 0, 0, 0, 0, 0, 0, 0], port).into()
        };

        match socket.bind(local_addr) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AddrInUse && attempt < MAX_RETRIES - 1 => {
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to bind exclude port {port} for transparent upstream")
                });
            }
        }

        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse && attempt < MAX_RETRIES - 1 => {
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("transparent upstream connect to {addr} failed (port {port})")
                });
            }
        }
    }

    anyhow::bail!("exhausted exclude port retries connecting to {addr}");
}

/// Resolve hostname:port to a SocketAddr.
pub async fn resolve_host(host: &str, port: u16) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("DNS lookup failed for {host}:{port}"))?
        .collect();

    addrs
        .into_iter()
        .next()
        .with_context(|| format!("no addresses found for {host}:{port}"))
}

/// Build a TLS client config for connecting upstream (transparent mode).
pub fn build_upstream_tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let roots = rustls_native_certs::load_native_certs();
    let mut root_store = rustls::RootCertStore::empty();
    for cert in roots.certs {
        let _ = root_store.add(cert);
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_port_round_robin() {
        let base = PORT_COUNTER.load(Ordering::Relaxed) as u16 % EXCLUDE_PORT_COUNT;
        let p1 = next_exclude_port();
        let p2 = next_exclude_port();
        assert_eq!(p1, EXCLUDE_PORT_START + base);
        assert_eq!(p2, EXCLUDE_PORT_START + (base + 1) % EXCLUDE_PORT_COUNT);
    }

    #[test]
    fn exclude_port_stays_in_range() {
        for _ in 0..200 {
            let port = next_exclude_port();
            assert!(port >= EXCLUDE_PORT_START);
            assert!(port <= EXCLUDE_PORT_END);
        }
    }
}
