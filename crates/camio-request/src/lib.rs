//! `camio-request` — the fingerprint-matched request engine (plan §13 item 4).
//!
//! Tool-originated traffic (Replay, Automate, Scanner, MCP) must **not** revert
//! to a stock Rust TLS stack, whose JA3/JA4 is itself a flaggable tell
//! (plan §6.2). This crate sends such traffic through a BoringSSL-based client
//! whose TLS and HTTP/2 fingerprint is derived from — and pinned to — the same
//! [`FingerprintProfile`](camio_core::FingerprintProfile) the managed browser
//! uses, so browser and tool share one fingerprint (plan §6.3).
//!
//! * [`FingerprintSpec`] — the derived impersonation target (pure data).
//! * [`RequestEngine`] — the trait all senders implement.
//! * [`DryRunEngine`] — a no-network engine (prepares + stamps requests) that is
//!   always available and honestly reports `is_fingerprint_matched() == false`.
//! * The real impersonating backend ([`impersonate::ImpersonatingEngine`]) is
//!   compiled with the default `impersonate` feature.
//!
//! **Parity is measured, not asserted** (plan §6.3): building from the profile
//! *targets* parity; the Phase-0 parity suite must confirm it against JA3/JA4/
//! HTTP-2 reflection endpoints.

pub mod engine;
pub mod spec;

#[cfg(feature = "impersonate")]
pub mod impersonate;

pub use engine::{
    host_header_value, order_headers, prepare_request, DryRunEngine, RequestEngine, RequestError,
};
pub use spec::{BrowserFamily, FingerprintSpec, Http2Fingerprint};

use camio_core::FingerprintProfile;

/// Build the best available *sending* engine for a profile.
///
/// With the `impersonate` feature (default) this is the BoringSSL-backed
/// [`impersonate::ImpersonatingEngine`], which reproduces the browser's
/// fingerprint. Without it, there is no network backend and this returns
/// [`RequestError::Unavailable`] — the caller can still use [`DryRunEngine`].
pub fn matched_engine(
    profile: &FingerprintProfile,
) -> Result<Box<dyn RequestEngine>, RequestError> {
    let spec = FingerprintSpec::from_profile(profile);
    #[cfg(feature = "impersonate")]
    {
        let engine = impersonate::ImpersonatingEngine::new(spec)?;
        Ok(Box::new(engine))
    }
    #[cfg(not(feature = "impersonate"))]
    {
        let _ = &spec;
        Err(RequestError::Unavailable(
            "built without the `impersonate` feature; use DryRunEngine".into(),
        ))
    }
}

/// Build a [`DryRunEngine`] for a profile (always available).
pub fn dry_run_engine(profile: &FingerprintProfile) -> DryRunEngine {
    DryRunEngine::new(FingerprintSpec::from_profile(profile))
}
