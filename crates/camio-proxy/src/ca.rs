//! Camio's TLS-interception certificate authority.
//!
//! When TLS interception is on, the proxy terminates the browser's TLS so the
//! plaintext request/response can be inspected, then re-originates the real
//! request through the fingerprint-matched engine. To terminate TLS it presents
//! a leaf certificate for the requested host, signed by **Camio's own local CA**
//! that the operator has explicitly imported into the browser/OS trust store.
//!
//! This is the honest, opt-in trade Burp and mitmproxy make: interception is
//! only possible because the operator chose to trust this CA, and the resulting
//! exchanges are tagged [`Source::Proxy`](camio_core::Source::Proxy) —
//! *fingerprint-changing* — so they are never confused with organic,
//! fingerprint-true browser capture.
//!
//! The CA key never leaves the operator's machine and is written `0600`.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Errors from the certificate authority.
#[derive(Debug)]
pub enum CaError {
    Rcgen(rcgen::Error),
    Tls(rustls::Error),
    Io(std::io::Error),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaError::Rcgen(e) => write!(f, "certificate generation: {e}"),
            CaError::Tls(e) => write!(f, "TLS configuration: {e}"),
            CaError::Io(e) => write!(f, "CA storage: {e}"),
        }
    }
}

impl std::error::Error for CaError {}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        CaError::Rcgen(e)
    }
}
impl From<rustls::Error> for CaError {
    fn from(e: rustls::Error) -> Self {
        CaError::Tls(e)
    }
}
impl From<std::io::Error> for CaError {
    fn from(e: std::io::Error) -> Self {
        CaError::Io(e)
    }
}

/// Default CA common name. Deliberately generic and non-attributable: the leaf
/// certs the proxy presents inherit this issuer, so a neutral name means an
/// inspected certificate chain doesn't announce "Camio" or "MITM proxy". Set
/// your own with [`CertAuthority::load_or_create_named`] to match the environment
/// you are authorized to test in.
pub const DEFAULT_CA_COMMON_NAME: &str = "Internal Root CA";

/// A local certificate authority that mints per-host leaf certificates on demand
/// and caches a ready rustls [`ServerConfig`] per host.
pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_cert_pem: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// Generate a brand-new in-memory CA (not persisted) with the default
    /// neutral name. Useful for tests and ephemeral sessions.
    pub fn generate() -> Result<Self, CaError> {
        Self::generate_named(DEFAULT_CA_COMMON_NAME)
    }

    /// Generate a brand-new in-memory CA with a chosen common name.
    pub fn generate_named(common_name: &str) -> Result<Self, CaError> {
        let ca_key = KeyPair::generate()?;
        let params = ca_params(common_name)?;
        let ca_cert = params.self_signed(&ca_key)?;
        let ca_cert_pem = ca_cert.pem();
        let issuer = Issuer::new(params, ca_key);
        Ok(Self::from_parts(issuer, ca_cert_pem))
    }

    /// Load the CA from `dir/camio-ca.pem` + `dir/camio-ca.key`, generating and
    /// persisting a fresh one (key written `0600`) if they are absent, using the
    /// default neutral name. Reusing the same CA across runs is what lets the
    /// operator import it into the browser once.
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        Self::load_or_create_named(dir, DEFAULT_CA_COMMON_NAME)
    }

    /// Like [`load_or_create`](Self::load_or_create) but sets the CA common name
    /// when a fresh CA is generated (an existing CA on disk keeps its name). A
    /// neutral or environment-matching name makes the intercept harder to spot
    /// from the certificate chain.
    pub fn load_or_create_named(dir: impl AsRef<Path>, common_name: &str) -> Result<Self, CaError> {
        let dir = dir.as_ref();
        let cert_path = dir.join("camio-ca.pem");
        let key_path = dir.join("camio-ca.key");
        if cert_path.exists() && key_path.exists() {
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let key_pem = std::fs::read_to_string(&key_path)?;
            let ca_key = KeyPair::from_pem(&key_pem)?;
            let issuer = Issuer::from_ca_cert_pem(&cert_pem, ca_key)?;
            return Ok(Self::from_parts(issuer, cert_pem));
        }

        std::fs::create_dir_all(dir)?;
        let ca_key = KeyPair::generate()?;
        let params = ca_params(common_name)?;
        let ca_cert = params.self_signed(&ca_key)?;
        let cert_pem = ca_cert.pem();
        let key_pem = ca_key.serialize_pem();
        std::fs::write(&cert_path, &cert_pem)?;
        write_private(&key_path, key_pem.as_bytes())?;
        let issuer = Issuer::new(params, ca_key);
        Ok(Self::from_parts(issuer, cert_pem))
    }

    fn from_parts(issuer: Issuer<'static, KeyPair>, ca_cert_pem: String) -> Self {
        CertAuthority {
            issuer,
            ca_cert_pem,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            configs: Mutex::new(HashMap::new()),
        }
    }

    /// The CA certificate in PEM form — hand this to the operator to import into
    /// their browser/OS trust store.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// A rustls server config presenting a freshly minted leaf for `host`,
    /// cached so repeat connections to the same host reuse it.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        if let Some(cfg) = self
            .configs
            .lock()
            .expect("CA config cache poisoned")
            .get(host)
        {
            return Ok(cfg.clone());
        }
        let cfg = Arc::new(self.build_config(host)?);
        self.configs
            .lock()
            .expect("CA config cache poisoned")
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }

    fn build_config(&self, host: &str) -> Result<ServerConfig, CaError> {
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // ~90-day leaf validity, like a modern public cert — not a telltale window.
        let (not_before, not_after) = validity_window(90);
        params.not_before = not_before;
        params.not_after = not_after;
        let leaf = params.signed_by(&leaf_key, &self.issuer)?;

        let cert_der: CertificateDer<'static> = leaf.der().clone();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(CaError::Tls)?
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;
        // Advertise HTTP/1.1 explicitly: the proxy reads HTTP/1.1 inside the
        // tunnel, and the real HTTP/2 fingerprint is reproduced by the matched
        // engine toward the target.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(cfg)
    }
}

/// CA certificate parameters: a CA-capable, cert-signing root. The common name
/// is caller-chosen (default neutral) and no organization is set, so the issuer
/// carries no product branding for a target to fingerprint.
fn ca_params(common_name: &str) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // A realistic root-CA validity window (~10 years), not rcgen's default
    // 1975→4096 — which would flag the cert as a test/MITM root to any inspector.
    let (not_before, not_after) = validity_window(3650);
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

/// A validity window of `[now - 1 day, now + days]`, so a minted certificate
/// looks like an ordinary modern cert rather than carrying a telltale window.
fn validity_window(days: i64) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = time::OffsetDateTime::now_utc();
    (
        now - time::Duration::days(1),
        now + time::Duration::days(days),
    )
}

/// Write a private key file with `0600` permissions on Unix.
fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ca_and_leaf_config() {
        let ca = CertAuthority::generate().expect("generate CA");
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        let cfg1 = ca.server_config("example.com").expect("leaf config");
        let cfg2 = ca.server_config("example.com").expect("cached config");
        // Same host returns the cached Arc.
        assert!(Arc::ptr_eq(&cfg1, &cfg2));
        let _other = ca.server_config("other.test").expect("second host");
    }

    #[test]
    fn persists_and_reloads_same_ca() {
        let dir = std::env::temp_dir().join(format!("camio-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca1 = CertAuthority::load_or_create(&dir).expect("create");
        let pem1 = ca1.ca_cert_pem().to_string();
        let ca2 = CertAuthority::load_or_create(&dir).expect("reload");
        assert_eq!(pem1, ca2.ca_cert_pem(), "reloaded CA must be identical");
        // The reloaded issuer can still mint leaves.
        ca2.server_config("reload.test").expect("mint after reload");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
