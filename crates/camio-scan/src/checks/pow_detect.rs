//! Proof-of-work anti-bot wall detection (plan §8 "Scan & crawl": automated
//! discovery of attack-surface context).
//!
//! Companion to [`super::captcha_detect`]: where that spots CAPTCHA widgets,
//! this spots **proof-of-work** interstitials — the server makes the client
//! burn CPU on a hash puzzle before the real page loads. The dominant one in
//! 2024–2026 is **Anubis** (Xe Iaso's anti-scraper, now on many forges, wikis
//! and mirrors), alongside **mCaptcha** and generic hashcash gates.
//!
//! This check is **passive**: it reads the captured HTML/headers and reports an
//! informational finding naming the system. Unlike a CAPTCHA, a PoW wall is
//! solvable without a human or a third-party service — Camio's own
//! `camio-automate::pow` solver can answer it — so the finding points the
//! operator straight at that path.

use crate::checks::{finding, is_html};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};

/// The proof-of-work systems detectable from a captured response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowSystem {
    /// Anubis (Xe Iaso) — SHA-256 hashcash interstitial.
    Anubis,
    /// mCaptcha — SHA-256 proof-of-work widget.
    MCaptcha,
    /// A generic hashcash/PoW gate (a challenge+difficulty pattern without a
    /// recognized vendor fingerprint).
    GenericHashcash,
}

impl PowSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            PowSystem::Anubis => "Anubis",
            PowSystem::MCaptcha => "mCaptcha",
            PowSystem::GenericHashcash => "generic hashcash PoW",
        }
    }

    pub fn solver_hint(self) -> &'static str {
        match self {
            PowSystem::Anubis => {
                "Solvable locally with no human: parse the challenge JSON and run `camio-automate::pow::parse_anubis` + `solve`, then submit the nonce."
            }
            PowSystem::MCaptcha | PowSystem::GenericHashcash => {
                "SHA-256 proof-of-work — solvable locally via `camio-automate::pow::solve` (SHA-256 leading-zero difficulty). No human or third-party service needed."
            }
        }
    }
}

/// Detect every proof-of-work system visible in a response body + its headers.
pub fn detect(body: &str, server_header: Option<&str>, powered_by: Option<&str>) -> Vec<PowSystem> {
    let mut hits = Vec::new();
    let add = |hits: &mut Vec<PowSystem>, s: PowSystem| {
        if !hits.contains(&s) {
            hits.push(s);
        }
    };

    // Anubis: a distinctive script path / id / meta and the "Making sure you're
    // not a bot" interstitial copy. The `/.within.website/` path prefix and the
    // `anubis_challenge` id are its strongest tells.
    if body.contains("/.within.website/x/cmd/anubis/")
        || body.contains("id=\"anubis_challenge\"")
        || body.contains("anubis_version")
        || body.contains("Making sure you're not a bot")
        || server_header.map(|h| h.contains("Anubis")).unwrap_or(false)
    {
        add(&mut hits, PowSystem::Anubis);
    }

    // mCaptcha: its widget script and container class.
    if body.contains("mcaptcha") || body.contains("m-captcha") {
        add(&mut hits, PowSystem::MCaptcha);
    }

    // Generic hashcash: a page that references a proof-of-work with a challenge
    // and a difficulty but no recognized vendor. Deliberately conservative — it
    // needs BOTH a proof-of-work phrase AND a difficulty/challenge token, so a
    // page merely discussing the concept doesn't trip it.
    let powered_hashcash = powered_by
        .map(|h| h.to_ascii_lowercase().contains("hashcash"))
        .unwrap_or(false);
    let has_pow_phrase = body.contains("proof-of-work")
        || body.contains("proof of work")
        || body.contains("powChallenge")
        || body.contains("pow_challenge");
    let has_difficulty = body.contains("difficulty") || body.contains("\"challenge\"");
    if hits.is_empty() && (powered_hashcash || (has_pow_phrase && has_difficulty)) {
        add(&mut hits, PowSystem::GenericHashcash);
    }

    hits
}

/// Passive proof-of-work wall detector.
pub struct PowChallengePresence;

impl PassiveCheck for PowChallengePresence {
    fn id(&self) -> &'static str {
        "pow-challenge-presence"
    }

    fn title(&self) -> &'static str {
        "Proof-of-work challenge present"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn check(&self, ex: &HttpExchange) -> Vec<Finding> {
        let Some(resp) = &ex.response else {
            return Vec::new();
        };
        if !is_html(resp) {
            return Vec::new();
        }
        let body = resp.body.as_text();
        let server = resp.headers.get("Server");
        let powered_by = resp.headers.get("X-Powered-By");
        let hits = detect(&body, server, powered_by);
        if hits.is_empty() {
            return Vec::new();
        }

        let names = hits
            .iter()
            .map(|s| format!("`{}`", s.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let hints = hits
            .iter()
            .map(|s| format!("- **{}**: {}", s.as_str(), s.solver_hint()))
            .collect::<Vec<_>>()
            .join("\n");
        vec![finding(
            "Proof-of-work challenge present",
            Severity::Info,
            Confidence::Firm,
            format!(
                "Detected proof-of-work anti-bot wall(s): {names}. Unlike a CAPTCHA, this is pure computation — no human needed.\n\n{hints}\n\nNo requests were sent to produce this finding; it was read from the already-captured response."
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn html_exchange(body: &str, headers: &[(&str, &str)]) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        for (k, v) in headers {
            h.push(*k, *v);
        }
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(HttpRequest::get("https://git.example.test/"), Source::Scanner)
            .with_response(resp)
    }

    #[test]
    fn detects_anubis_by_script_path() {
        let body = r#"<html><head><script src="/.within.website/x/cmd/anubis/static/js/main.mjs"></script></head>
            <body><h1>Making sure you're not a bot</h1></body></html>"#;
        assert!(detect(body, None, None).contains(&PowSystem::Anubis));
    }

    #[test]
    fn detects_anubis_by_server_header() {
        assert!(detect("<html></html>", Some("Anubis"), None).contains(&PowSystem::Anubis));
    }

    #[test]
    fn detects_mcaptcha() {
        let body = r#"<div class="m-captcha"></div><script src="/mcaptcha/widget.js"></script>"#;
        assert!(detect(body, None, None).contains(&PowSystem::MCaptcha));
    }

    #[test]
    fn detects_generic_hashcash_conservatively() {
        // Needs both the PoW phrase AND a difficulty/challenge token.
        let yes = r#"<script>var pow_challenge = {"challenge":"abc","difficulty":4}</script>
                     <p>Complete the proof-of-work to continue.</p>"#;
        assert!(detect(yes, None, None).contains(&PowSystem::GenericHashcash));

        // Prose mention alone must NOT trip it.
        let no = "<p>We use proof of work to deter bots.</p>";
        assert!(detect(no, None, None).is_empty());
    }

    #[test]
    fn powered_by_hashcash_header_triggers() {
        assert!(detect("<html></html>", None, Some("hashcash/1.0"))
            .contains(&PowSystem::GenericHashcash));
    }

    #[test]
    fn vendor_hit_suppresses_generic() {
        // An Anubis page that also says "proof-of-work" + difficulty must be
        // reported as Anubis only, not double-counted as generic.
        let body = r#"<script src="/.within.website/x/cmd/anubis/x.js"></script>
                      proof-of-work difficulty "challenge""#;
        let hits = detect(body, None, None);
        assert!(hits.contains(&PowSystem::Anubis));
        assert!(!hits.contains(&PowSystem::GenericHashcash));
    }

    #[test]
    fn check_emits_finding_and_skips_clean_pages() {
        let ex = html_exchange(
            r#"<script src="/.within.website/x/cmd/anubis/x.js"></script>"#,
            &[],
        );
        let f = PowChallengePresence.check(&ex);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("Anubis"));
        assert!(f[0].detail.contains("camio-automate::pow"));

        let clean = html_exchange("<html><body>hi</body></html>", &[]);
        assert!(PowChallengePresence.check(&clean).is_empty());
    }

    #[test]
    fn skips_non_html() {
        let mut h = HeaderList::new();
        h.push("Content-Type", "application/json");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(r#"{"challenge":"x","difficulty":4,"proof-of-work":true}"#),
        };
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner)
            .with_response(resp);
        assert!(PowChallengePresence.check(&ex).is_empty());
    }
}
