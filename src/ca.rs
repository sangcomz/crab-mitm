use std::io::BufReader;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result};
use lru::LruCache;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::Mutex as AsyncMutex;

pub fn generate_ca_to_files(
    common_name: &str,
    days: u32,
    out_cert: &Path,
    out_key: &Path,
) -> Result<()> {
    let key_pair = rcgen::KeyPair::generate().context("failed to generate CA key pair")?;

    let mut params = rcgen::CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(days as i64);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    let cert = params
        .self_signed(&key_pair)
        .context("failed to self-sign CA certificate")?;

    std::fs::write(out_cert, cert.pem())
        .with_context(|| format!("failed to write {}", out_cert.display()))?;
    write_private_key_pem(out_key, &key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", out_key.display()))?;

    Ok(())
}

fn write_private_key_pem(path: &Path, pem: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(pem.as_bytes())?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, pem)
    }
}

pub struct CertificateAuthority {
    signer: AsyncMutex<Signer>,
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    cache: AsyncMutex<LruCache<String, CachedServerConfig>>,
    cache_ttl: StdDuration,
}

struct Signer {
    issuer_cert: rcgen::Certificate,
    issuer_key: rcgen::KeyPair,
}

struct CachedServerConfig {
    config: Arc<ServerConfig>,
    expires_at: Instant,
}

impl CertificateAuthority {
    pub fn from_pem_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("failed to read CA cert: {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("failed to read CA key: {}", key_path.display()))?;

        let ca_cert_der = load_first_cert_der(&cert_pem)
            .with_context(|| format!("failed to parse CA cert PEM: {}", cert_path.display()))?;

        let issuer_key =
            rcgen::KeyPair::from_pem(&key_pem).context("failed to parse CA private key (PEM)")?;
        let issuer_params = rcgen::CertificateParams::from_ca_cert_pem(&cert_pem)
            .context("failed to parse CA certificate (PEM)")?;
        let issuer_cert = issuer_params
            .self_signed(&issuer_key)
            .context("failed to build CA signer certificate (internal)")?;

        Ok(Self {
            signer: AsyncMutex::new(Signer {
                issuer_cert,
                issuer_key,
            }),
            ca_cert_pem: cert_pem,
            ca_cert_der,
            cache: AsyncMutex::new(LruCache::new(
                NonZeroUsize::new(2048).expect("non-zero cert cache size"),
            )),
            cache_ttl: parse_leaf_cache_ttl(),
        })
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> &[u8] {
        self.ca_cert_der.as_ref()
    }

    pub async fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = normalize_host(host);
        let now = Instant::now();
        {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(&host) {
                if cached.expires_at > now {
                    return Ok(cached.config.clone());
                }
            }
            if cache.peek(&host).is_some() {
                cache.pop(&host);
            }
        }

        let built = Arc::new(self.build_server_config(&host).await?);
        let expires_at = next_cache_expiry(self.cache_ttl);

        let mut cache = self.cache.lock().await;
        if let Some(existing) = cache.get(&host)
            && existing.expires_at > Instant::now()
        {
            return Ok(existing.config.clone());
        }
        if cache.peek(&host).is_some() {
            cache.pop(&host);
        }
        cache.put(
            host,
            CachedServerConfig {
                config: built.clone(),
                expires_at,
            },
        );
        Ok(built)
    }

    async fn build_server_config(&self, host: &str) -> Result<ServerConfig> {
        let leaf_key = rcgen::KeyPair::generate().context("failed to generate leaf key pair")?;

        let mut leaf_params = rcgen::CertificateParams::new([host.to_string()])
            .context("failed to build leaf params")?;
        leaf_params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
        leaf_params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(365);
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_cert = {
            let signer = self.signer.lock().await;
            leaf_params
                .signed_by(&leaf_key, &signer.issuer_cert, &signer.issuer_key)
                .context("failed to sign leaf certificate")?
        };

        let chain = vec![leaf_cert.der().clone(), self.ca_cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("failed to build rustls ServerConfig")?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(cfg)
    }
}

fn load_first_cert_der(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let mut certs = rustls_pemfile::certs(&mut reader);
    let first = certs
        .next()
        .transpose()
        .context("failed to read cert PEM")?
        .context("no certificate found")?;
    Ok(first)
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_leaf_cache_ttl() -> StdDuration {
    parse_leaf_cache_ttl_value(
        std::env::var("CRAB_LEAF_CERT_CACHE_TTL_SECS")
            .ok()
            .as_deref(),
    )
}

fn parse_leaf_cache_ttl_value(raw: Option<&str>) -> StdDuration {
    const DEFAULT_SECS: u64 = 6 * 60 * 60;

    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(StdDuration::from_secs)
        .unwrap_or_else(|| StdDuration::from_secs(DEFAULT_SECS))
}

fn next_cache_expiry(ttl: StdDuration) -> Instant {
    Instant::now().checked_add(ttl).unwrap_or_else(Instant::now)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("crab-mitm-{prefix}-{nanos}"))
    }

    #[test]
    fn parse_leaf_cache_ttl_value_accepts_positive_seconds() {
        assert_eq!(
            parse_leaf_cache_ttl_value(Some("60")),
            StdDuration::from_secs(60)
        );
        assert_eq!(
            parse_leaf_cache_ttl_value(Some(" 120 ")),
            StdDuration::from_secs(120)
        );
    }

    #[test]
    fn parse_leaf_cache_ttl_value_falls_back_on_invalid_input() {
        let default_ttl = StdDuration::from_secs(6 * 60 * 60);
        assert_eq!(parse_leaf_cache_ttl_value(None), default_ttl);
        assert_eq!(parse_leaf_cache_ttl_value(Some("0")), default_ttl);
        assert_eq!(parse_leaf_cache_ttl_value(Some("-1")), default_ttl);
        assert_eq!(parse_leaf_cache_ttl_value(Some("abc")), default_ttl);
    }

    #[tokio::test]
    async fn generated_leaf_config_advertises_h2_and_http11() {
        let dir = unique_temp_dir("ca-alpn");
        fs::create_dir_all(&dir).expect("create temp dir");
        let cert = dir.join("ca.crt.pem");
        let key = dir.join("ca.key.pem");

        generate_ca_to_files("CrabProxy Test CA", 7, &cert, &key).expect("generate test CA");
        let ca = CertificateAuthority::from_pem_files(&cert, &key).expect("load test CA");
        let server_cfg = ca
            .server_config_for_host("example.com")
            .await
            .expect("server config");

        assert!(
            server_cfg
                .alpn_protocols
                .iter()
                .any(|v| v.as_slice() == b"h2")
        );
        assert!(
            server_cfg
                .alpn_protocols
                .iter()
                .any(|v| v.as_slice() == b"http/1.1")
        );

        let _ = fs::remove_file(cert);
        let _ = fs::remove_file(key);
        let _ = fs::remove_dir_all(dir);
    }
}
