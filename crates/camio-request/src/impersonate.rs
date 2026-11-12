//! The real fingerprint-matched backend: a BoringSSL-based HTTP client whose
//! TLS/JA3/JA4 and HTTP/2 fingerprint impersonates the browser (plan §6.2).
//!
//! Built on [`wreq`] (the maintained successor to the `rquest` crate the plan
//! names) with `wreq-util` emulation presets. The emulation preset is chosen
//! from the profile's Firefox major version; Camoufox can be newer than the
//! newest available preset, in which case the newest is used and the gap is
//! surfaced as a parity note (plan §6.3: **stale = detectable**, so we never
//! hide it).
//!
//! Header order and casing are preserved on the wire via `wreq`'s
//! `OrigHeaderMap` (plan §6.1 item 3): we send exactly the headers
//! [`prepare_request`](crate::engine::prepare_request) produced, in order, and
//! disable the client's own default-header injection.

use crate::engine::{prepare_request, RequestEngine, RequestError};
use crate::spec::FingerprintSpec;
use camio_core::{
    Body as CoreBody, HeaderList, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Source,
    Timings,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wreq::header::OrigHeaderMap;
use wreq::redirect::Policy;
use wreq::{Client, Method, Version};
use wreq_util::{Emulation, Profile};

/// A sending engine that reproduces the browser's fingerprint.
pub struct ImpersonatingEngine {
    spec: FingerprintSpec,
    rt: tokio::runtime::Runtime,
    client: Client,
    /// The emulation preset actually applied (e.g. `firefox/151`), which can lag
    /// the browser's real version.
    preset_label: String,
    /// True when the preset version matches the browser major exactly.
    exact_preset: bool,
}

impl ImpersonatingEngine {
    pub fn new(spec: FingerprintSpec) -> Result<Self, RequestError> {
        let (profile, preset_major) = pick_firefox_emulation(spec.major_version);
        let exact_preset = preset_major == spec.major_version;
        let preset_label = format!("firefox/{preset_major}");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| RequestError::Unavailable(format!("tokio runtime: {e}")))?;

        let client = rt
            .block_on(async {
                Client::builder()
                    .emulation(profile)
                    // Camio controls redirects (in-scope-only policy lives above
                    // the engine, plan §9): capture the 3xx, don't auto-follow.
                    .redirect(Policy::none())
                    .connect_timeout(Duration::from_secs(15))
                    .timeout(Duration::from_secs(30))
                    .build()
            })
            .map_err(|e| RequestError::Transport(format!("building client: {e}")))?;

        Ok(ImpersonatingEngine {
            spec,
            rt,
            client,
            preset_label,
            exact_preset,
        })
    }

    async fn send_async(
        &self,
        req: HttpRequest,
        source: Source,
    ) -> Result<HttpExchange, RequestError> {
        let prepared = prepare_request(req, &self.spec);

        let method = Method::from_bytes(prepared.method.as_bytes())
            .map_err(|e| RequestError::Transport(format!("invalid method: {e}")))?;

        let mut rb = self
            .client
            .request(method, prepared.url.as_str())
            // We supply the exact header set and order ourselves; don't let the
            // client inject or reorder its own default headers.
            .default_headers(false);

        // Preserve exact order + casing via OrigHeaderMap (plan §6.1 item 3).
        let mut orig = OrigHeaderMap::new();
        for h in prepared.headers.iter() {
            rb = rb.header(h.name.as_str(), h.value.as_str());
            // Pass an owned String (case-preserving) so the wire casing + order
            // are reproduced; &str would require a 'static lifetime here.
            orig.insert(h.name.clone());
        }
        rb = rb.orig_headers(orig);

        if !prepared.body.is_empty() {
            rb = rb.body(prepared.body.0.clone());
        }

        let started_at_ms = now_ms();
        let t0 = Instant::now();
        let resp = rb
            .send()
            .await
            .map_err(|e| RequestError::Transport(e.to_string()))?;

        let status = resp.status().as_u16();
        let reason = resp.status().canonical_reason().map(|s| s.to_string());
        let version = map_version(resp.version());

        let mut headers = HeaderList::new();
        for (name, value) in resp.headers().iter() {
            headers.push(
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            );
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| RequestError::Transport(format!("reading body: {e}")))?;
        let roundtrip_ms = t0.elapsed().as_millis() as i64;

        let response = HttpResponse {
            status,
            version,
            reason,
            headers,
            body: CoreBody::from_bytes(body.to_vec()),
        };

        let mut ex = HttpExchange::new(prepared, source).with_response(response);
        ex.fingerprint_used = Some(self.spec.profile_name.clone());
        ex.timings = Some(Timings {
            started_at_ms,
            roundtrip_ms,
        });
        ex.created_at_ms = started_at_ms;
        Ok(ex)
    }
}

impl RequestEngine for ImpersonatingEngine {
    fn label(&self) -> String {
        format!("wreq BoringSSL impersonating {}", self.preset_label)
    }

    fn is_fingerprint_matched(&self) -> bool {
        true
    }

    fn spec(&self) -> &FingerprintSpec {
        &self.spec
    }

    fn parity_note(&self) -> Option<String> {
        if self.exact_preset {
            None
        } else {
            Some(format!(
                "impersonation preset {} approximates Camoufox {}; measure JA3/JA4/H2 parity before relying on it (plan §6.3)",
                self.preset_label, self.spec.major_version
            ))
        }
    }

    fn send(&self, req: HttpRequest, source: Source) -> Result<HttpExchange, RequestError> {
        // Bridge the async client into Camio's synchronous call sites.
        self.rt.block_on(self.send_async(req, source))
    }
}

/// Pick the newest emulation preset not exceeding the browser major version.
/// Returns the preset and its version. A browser newer than every preset (e.g.
/// Camoufox 158 vs. newest preset 151) maps to the newest.
fn pick_firefox_emulation(major: u32) -> (Profile, u32) {
    match major {
        0..=116 => (Emulation::Firefox109, 109),
        117..=127 => (Emulation::Firefox117, 117),
        128..=132 => (Emulation::Firefox128, 128),
        133..=134 => (Emulation::Firefox133, 133),
        135 => (Emulation::Firefox135, 135),
        136..=138 => (Emulation::Firefox136, 136),
        139..=141 => (Emulation::Firefox139, 139),
        142 => (Emulation::Firefox142, 142),
        143 => (Emulation::Firefox143, 143),
        144 => (Emulation::Firefox144, 144),
        145 => (Emulation::Firefox145, 145),
        146 => (Emulation::Firefox146, 146),
        147 => (Emulation::Firefox147, 147),
        148 => (Emulation::Firefox148, 148),
        149 => (Emulation::Firefox149, 149),
        150 => (Emulation::Firefox150, 150),
        _ => (Emulation::Firefox151, 151),
    }
}

fn map_version(v: Version) -> HttpVersion {
    match v {
        Version::HTTP_10 => HttpVersion::Http10,
        Version::HTTP_2 => HttpVersion::H2,
        Version::HTTP_3 => HttpVersion::H3,
        _ => HttpVersion::Http11,
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camoufox_158_maps_to_newest_preset() {
        let (_, v) = pick_firefox_emulation(158);
        assert_eq!(v, 151);
    }

    #[test]
    fn exact_preset_when_version_available() {
        let (_, v) = pick_firefox_emulation(135);
        assert_eq!(v, 135);
    }

    #[test]
    fn older_than_all_presets_maps_to_oldest() {
        let (_, v) = pick_firefox_emulation(100);
        assert_eq!(v, 109);
    }
}
