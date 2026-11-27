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
use std::io::Write;
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

/// Maximum cached per-host TLS leaf configs. Each entry holds a freshly
/// generated ECDSA key, so an unbounded cache is a slow memory/CPU leak for any
/// client that connects to many distinct hosts.
const MAX_CACHED_CONFIGS: usize = 256;

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

    /// Paths this CA would use in `dir`.
    pub fn paths(dir: impl AsRef<Path>) -> (PathBuf, PathBuf) {
        let dir = dir.as_ref();
        (dir.join("camio-ca.pem"), dir.join("camio-ca.key"))
    }

    /// Whether a persisted CA exists at `dir` (both the cert and its key).
    pub fn exists(dir: impl AsRef<Path>) -> bool {
        let (cert, key) = Self::paths(dir);
        cert.exists() && key.exists()
    }

    /// Remove the persisted CA from `dir`, returning whether anything was
    /// deleted. Removing the CA revokes Camio's ability to mint leaves for it —
    /// the operator's trust stores keep whatever they imported, so this is the
    /// "stop intercepting as this identity" action, not a global un-trust.
    pub fn remove(dir: impl AsRef<Path>) -> Result<bool, CaError> {
        let (cert, key) = Self::paths(dir);
        let mut removed = false;
        for path in [cert, key] {
            match std::fs::remove_file(&path) {
                Ok(()) => removed = true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(removed)
    }

    /// Rotate: remove any existing CA and create a fresh one under the same
    /// common name. A new key + cert means previously imported trust no longer
    /// matches, so the operator must re-import — the returned CA's PEM is the
    /// one to hand out.
    pub fn rotate(dir: impl AsRef<Path>, common_name: &str) -> Result<Self, CaError> {
        let dir = dir.as_ref();
        Self::remove(dir)?;
        Self::load_or_create_named(dir, common_name)
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
    ///
    /// The cache is a bounded LRU: leaf keygen is expensive and a client can
    /// force it with arbitrary unique hostnames, so the oldest entries are
    /// evicted past [`MAX_CACHED_CONFIGS`] instead of growing without limit.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, CaError> {
        let host = host.trim().to_ascii_lowercase();
        {
            let mut cache = self.configs.lock().expect("CA config cache poisoned");
            if let Some(cfg) = cache.get(&host) {
                // Refresh recency (move to the back of the eviction order).
                let cfg = cfg.clone();
                cache.remove(&host);
                cache.insert(host.clone(), cfg.clone());
                return Ok(cfg);
            }
        }
        let cfg = Arc::new(self.build_config(&host)?);
        let mut cache = self.configs.lock().expect("CA config cache poisoned");
        cache.insert(host.clone(), cfg.clone());
        while cache.len() > MAX_CACHED_CONFIGS {
            // `HashMap` iteration order is arbitrary; dropping any oldest-ish
            // entry is fine for a cache whose only job is to avoid re-keygen.
            let Some(victim) = cache.keys().next().cloned() else {
                break;
            };
            cache.remove(&victim);
        }
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

/// Write a private key file with `0600` permissions on Unix. The file is
/// created with the restrictive mode from the start, so there is no window
/// where another local process could read the CA key.
fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut file = opts.open(path)?;
        file.write_all(bytes)?;
        // Repair an existing file that was created loosely.
        let mut perms = std::fs::metadata(path)?.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
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

#[cfg(test)]
mod cache_tests {
    use super::*;

    #[test]
    fn the_leaf_cache_is_bounded() {
        let ca = CertAuthority::generate().unwrap();
        // One more than the bound: the cache must not grow past it.
        for i in 0..(MAX_CACHED_CONFIGS + 40) {
            ca.server_config(&format!("host{i}.test")).unwrap();
        }
        let cached = ca.configs.lock().unwrap().len();
        assert_eq!(cached, MAX_CACHED_CONFIGS, "cache must be bounded");
    }

    #[test]
    fn a_cached_host_is_reused_not_regenerated() {
        let ca = CertAuthority::generate().unwrap();
        let first = ca.server_config("Same-Host.test").unwrap();
        let second = ca.server_config("same-host.test").unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "the same host must reuse the cached config (case-insensitively)"
        );
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("camio-ca-{tag}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn rotate_replaces_the_key_and_removes_the_old_identity() {
        let dir = tmp("rotate");
        let first = CertAuthority::load_or_create_named(&dir, "Camio Test CA").unwrap();
        let first_pem = first.ca_cert_pem().to_string();
        assert!(CertAuthority::exists(&dir));

        let rotated = CertAuthority::rotate(&dir, "Camio Test CA").unwrap();
        assert_ne!(
            rotated.ca_cert_pem(),
            first_pem,
            "rotation must mint a new CA, not reuse the old one"
        );

        // A rotation leaves exactly one usable CA on disk.
        let reloaded = CertAuthority::load_or_create_named(&dir, "Camio Test CA").unwrap();
        assert_eq!(reloaded.ca_cert_pem(), rotated.ca_cert_pem());

        // Removal deletes both files and reports it.
        assert!(CertAuthority::remove(&dir).unwrap());
        assert!(!CertAuthority::exists(&dir));
        // Removing again is a no-op, not an error.
        assert!(!CertAuthority::remove(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_partial_ca_is_reported_as_absent() {
        let dir = tmp("partial");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!CertAuthority::exists(&dir), "no files → not a CA");
        std::fs::write(dir.join("camio-ca.pem"), "junk").unwrap();
        assert!(
            !CertAuthority::exists(&dir),
            "a cert without its key is not a CA"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
