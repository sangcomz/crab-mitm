use std::collections::HashSet;
use std::io::BufReader;
use std::io::Write;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result};
use lru::LruCache;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum CaKeyAlgorithm {
    #[default]
    EcdsaP256,
    Rsa2048,
    Rsa4096,
}

impl CaKeyAlgorithm {
    pub fn from_ffi(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::EcdsaP256),
            1 => Some(Self::Rsa2048),
            2 => Some(Self::Rsa4096),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeafKeyAlgorithm {
    EcdsaP256,
    Rsa2048,
    Rsa4096,
}

pub fn generate_ca_to_files(
    common_name: &str,
    days: u32,
    out_cert: &Path,
    out_key: &Path,
) -> Result<()> {
    generate_ca_to_files_with_algorithm(
        common_name,
        days,
        out_cert,
        out_key,
        CaKeyAlgorithm::default(),
    )
}

pub fn generate_ca_to_files_with_algorithm(
    common_name: &str,
    days: u32,
    out_cert: &Path,
    out_key: &Path,
    key_algorithm: CaKeyAlgorithm,
) -> Result<()> {
    let key_pair = generate_ca_key_pair(key_algorithm).context("failed to generate CA key pair")?;

    let mut params = rcgen::CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
    params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(days as i64);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
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
    leaf_key_algorithm: LeafKeyAlgorithm,
    crl_distribution_urls: Vec<String>,
    ocsp_staple_der: Option<Vec<u8>>,
    cache: AsyncMutex<LruCache<String, CachedServerConfig>>,
    cache_ttl: StdDuration,
    next_crl_number: AtomicU64,
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
        let leaf_key_algorithm = leaf_key_algorithm_for_issuer_key(&ca_cert_der, &issuer_key);
        let crl_distribution_urls = parse_crl_distribution_urls(
            std::env::var("CRAB_CRL_DISTRIBUTION_URLS").ok().as_deref(),
        );
        let ocsp_staple_der =
            load_ocsp_staple_der(std::env::var("CRAB_OCSP_STAPLE_DER").ok().as_deref())?;

        Ok(Self {
            signer: AsyncMutex::new(Signer {
                issuer_cert,
                issuer_key,
            }),
            ca_cert_pem: cert_pem,
            ca_cert_der,
            leaf_key_algorithm,
            crl_distribution_urls,
            ocsp_staple_der,
            cache: AsyncMutex::new(LruCache::new(
                NonZeroUsize::new(2048).expect("non-zero cert cache size"),
            )),
            cache_ttl: parse_leaf_cache_ttl(),
            next_crl_number: AtomicU64::new(1),
        })
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn ca_cert_der(&self) -> &[u8] {
        self.ca_cert_der.as_ref()
    }

    pub async fn generate_crl_der(&self) -> Result<Vec<u8>> {
        let this_update = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
        let next_update = this_update + TimeDuration::days(7);
        let crl_number = self.next_crl_number.fetch_add(1, Ordering::Relaxed);
        let params = rcgen::CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: rcgen::SerialNumber::from(crl_number.max(1)),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let crl = {
            let signer = self.signer.lock().await;
            params
                .signed_by(&signer.issuer_cert, &signer.issuer_key)
                .context("failed to sign CRL")?
        };

        Ok(crl.der().as_ref().to_vec())
    }

    pub async fn server_config_for_host(
        &self,
        host: &str,
        upstream_sans: Option<Vec<String>>,
    ) -> Result<Arc<ServerConfig>> {
        let host = normalize_host(host);
        let subject_alt_names = normalize_subject_alt_names(&host, upstream_sans);
        let cache_key = cache_key(&host, &subject_alt_names);
        let now = Instant::now();
        {
            let mut cache = self.cache.lock().await;
            if let Some(cached) = cache.get(&cache_key) {
                if cached.expires_at > now {
                    return Ok(cached.config.clone());
                }
            }
            if cache.peek(&cache_key).is_some() {
                cache.pop(&cache_key);
            }
        }

        let built = Arc::new(self.build_server_config(&host, &subject_alt_names).await?);
        let expires_at = next_cache_expiry(self.cache_ttl);

        let mut cache = self.cache.lock().await;
        if let Some(existing) = cache.get(&cache_key)
            && existing.expires_at > Instant::now()
        {
            return Ok(existing.config.clone());
        }
        if cache.peek(&cache_key).is_some() {
            cache.pop(&cache_key);
        }
        cache.put(
            cache_key,
            CachedServerConfig {
                config: built.clone(),
                expires_at,
            },
        );
        Ok(built)
    }

    async fn build_server_config(
        &self,
        host: &str,
        subject_alt_names: &[String],
    ) -> Result<ServerConfig> {
        let leaf_key = generate_leaf_key_pair(self.leaf_key_algorithm)
            .context("failed to generate leaf key pair")?;

        let mut leaf_params = rcgen::CertificateParams::new(subject_alt_names.to_vec())
            .context("failed to build leaf params")?;
        leaf_params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
        leaf_params.not_after = OffsetDateTime::now_utc() + TimeDuration::days(365);
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.key_usages = leaf_key_usages(self.leaf_key_algorithm);
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        if !self.crl_distribution_urls.is_empty() {
            leaf_params.crl_distribution_points = vec![rcgen::CrlDistributionPoint {
                uris: self.crl_distribution_urls.clone(),
            }];
        }

        let leaf_cert = {
            let signer = self.signer.lock().await;
            leaf_params
                .signed_by(&leaf_key, &signer.issuer_cert, &signer.issuer_key)
                .context("failed to sign leaf certificate")?
        };

        let chain = vec![leaf_cert.der().clone(), self.ca_cert_der.clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut cfg = if let Some(ocsp_der) = self.ocsp_staple_der.clone() {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert_with_ocsp(chain, key, ocsp_der)
                .context("failed to build rustls ServerConfig (with OCSP)")?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .context("failed to build rustls ServerConfig")?
        };
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(cfg)
    }
}

fn generate_ca_key_pair(key_algorithm: CaKeyAlgorithm) -> Result<rcgen::KeyPair> {
    match key_algorithm {
        CaKeyAlgorithm::EcdsaP256 => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
        CaKeyAlgorithm::Rsa2048 => {
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        }
        CaKeyAlgorithm::Rsa4096 => {
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_4096)
        }
    }
    .context("unsupported key algorithm")
}

fn generate_leaf_key_pair(algorithm: LeafKeyAlgorithm) -> Result<rcgen::KeyPair> {
    match algorithm {
        LeafKeyAlgorithm::EcdsaP256 => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
        LeafKeyAlgorithm::Rsa2048 => {
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
        }
        LeafKeyAlgorithm::Rsa4096 => {
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_4096)
        }
    }
    .context("unsupported leaf key algorithm")
}

fn leaf_key_algorithm_for_issuer_key(
    ca_cert_der: &CertificateDer<'static>,
    issuer_key: &rcgen::KeyPair,
) -> LeafKeyAlgorithm {
    if !is_rsa_signature_algorithm(issuer_key.algorithm()) {
        return LeafKeyAlgorithm::EcdsaP256;
    }

    let parsed = x509_parser::parse_x509_certificate(ca_cert_der.as_ref());
    if let Ok((_, cert)) = parsed
        && let Ok(key) = cert.public_key().parsed()
    {
        let bits = key.key_size();
        if bits >= 4096 {
            return LeafKeyAlgorithm::Rsa4096;
        }
    }

    LeafKeyAlgorithm::Rsa2048
}

fn is_rsa_signature_algorithm(alg: &'static rcgen::SignatureAlgorithm) -> bool {
    std::ptr::eq(alg, &rcgen::PKCS_RSA_SHA256)
        || std::ptr::eq(alg, &rcgen::PKCS_RSA_SHA384)
        || std::ptr::eq(alg, &rcgen::PKCS_RSA_SHA512)
}

fn leaf_key_usages(algorithm: LeafKeyAlgorithm) -> Vec<rcgen::KeyUsagePurpose> {
    match algorithm {
        LeafKeyAlgorithm::EcdsaP256 => vec![rcgen::KeyUsagePurpose::DigitalSignature],
        LeafKeyAlgorithm::Rsa2048 | LeafKeyAlgorithm::Rsa4096 => vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ],
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

fn normalize_subject_alt_names(host: &str, upstream_sans: Option<Vec<String>>) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    if !host.is_empty() && seen.insert(host.to_string()) {
        names.push(host.to_string());
    }

    if let Some(upstream_sans) = upstream_sans {
        for raw_name in upstream_sans {
            let Some(name) = normalize_subject_alt_name(&raw_name) else {
                continue;
            };
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
    }

    if names.is_empty() {
        names.push("localhost".to_string());
    }

    names
}

fn normalize_subject_alt_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Some(ip.to_string());
    }

    let dns = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if dns.is_empty() { None } else { Some(dns) }
}

fn cache_key(host: &str, subject_alt_names: &[String]) -> String {
    if subject_alt_names.len() == 1 && subject_alt_names.first().is_some_and(|name| name == host) {
        return host.to_string();
    }

    format!("{host}|{}", subject_alt_names.join(","))
}

fn parse_crl_distribution_urls(raw: Option<&str>) -> Vec<String> {
    const DEFAULT_URL: &str = "http://crab-proxy.local/ca.crl";

    let mut urls = raw
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    if urls.is_empty() {
        urls.push(DEFAULT_URL.to_string());
    }
    urls
}

fn load_ocsp_staple_der(raw_path: Option<&str>) -> Result<Option<Vec<u8>>> {
    let Some(path) = raw_path.map(str::trim).filter(|path| !path.is_empty()) else {
        return Ok(None);
    };

    let der = std::fs::read(path)
        .with_context(|| format!("failed to read OCSP staple DER file: {path}"))?;
    Ok(Some(der))
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

    #[test]
    fn parse_crl_distribution_urls_uses_default_when_empty() {
        assert_eq!(
            parse_crl_distribution_urls(None),
            vec!["http://crab-proxy.local/ca.crl".to_string()]
        );
        assert_eq!(
            parse_crl_distribution_urls(Some("  ")),
            vec!["http://crab-proxy.local/ca.crl".to_string()]
        );
    }

    #[test]
    fn parse_crl_distribution_urls_splits_and_trims() {
        assert_eq!(
            parse_crl_distribution_urls(Some("http://a.example/crl, https://b.example/crl.pem ,")),
            vec![
                "http://a.example/crl".to_string(),
                "https://b.example/crl.pem".to_string()
            ]
        );
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
            .server_config_for_host("example.com", None)
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

    #[tokio::test]
    async fn generated_crl_der_is_not_empty() {
        let dir = unique_temp_dir("ca-crl");
        fs::create_dir_all(&dir).expect("create temp dir");
        let cert = dir.join("ca.crt.pem");
        let key = dir.join("ca.key.pem");

        generate_ca_to_files("CrabProxy Test CA", 7, &cert, &key).expect("generate test CA");
        let ca = CertificateAuthority::from_pem_files(&cert, &key).expect("load test CA");
        let crl_der = ca.generate_crl_der().await.expect("generate CRL");

        assert!(!crl_der.is_empty());

        let _ = fs::remove_file(cert);
        let _ = fs::remove_file(key);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn normalize_subject_alt_names_keeps_host_and_deduplicates() {
        let result = normalize_subject_alt_names(
            "example.com",
            Some(vec![
                "example.com".to_string(),
                "EXAMPLE.com.".to_string(),
                "api.example.com".to_string(),
                "192.168.0.1".to_string(),
                " ".to_string(),
            ]),
        );

        assert_eq!(
            result,
            vec![
                "example.com".to_string(),
                "api.example.com".to_string(),
                "192.168.0.1".to_string()
            ]
        );
    }
}
