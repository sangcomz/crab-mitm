use std::collections::HashMap;
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

pub fn generate_ca_to_files(
    common_name: &str,
    days: u32,
    out_cert: &Path,
    out_key: &Path,
) -> Result<()> {
    let key_pair = rcgen::KeyPair::generate().context("failed to generate CA key pair")?;

    let mut params = rcgen::CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(days as i64);
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
    std::fs::write(out_key, key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", out_key.display()))?;

    Ok(())
}

pub struct CertificateAuthority {
    signer: Mutex<Signer>,
    ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    cache: tokio::sync::RwLock<HashMap<String, Arc<ServerConfig>>>,
}

struct Signer {
    issuer_cert: rcgen::Certificate,
    issuer_key: rcgen::KeyPair,
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
            signer: Mutex::new(Signer {
                issuer_cert,
                issuer_key,
            }),
            ca_cert_pem: cert_pem,
            ca_cert_der,
            cache: tokio::sync::RwLock::new(HashMap::new()),
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

        if let Some(cfg) = self.cache.read().await.get(&host).cloned() {
            return Ok(cfg);
        }

        let cfg = Arc::new(self.build_server_config(&host)?);
        self.cache.write().await.insert(host, cfg.clone());
        Ok(cfg)
    }

    fn build_server_config(&self, host: &str) -> Result<ServerConfig> {
        let leaf_key = rcgen::KeyPair::generate().context("failed to generate leaf key pair")?;

        let mut leaf_params = rcgen::CertificateParams::new([host.to_string()])
            .context("failed to build leaf params")?;
        leaf_params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        leaf_params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
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
            let signer = self.signer.lock().expect("poisoned CA signer lock");
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
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
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
