//! CAPTCHA-presence detection (plan §8 "Scan & crawl": automated discovery of
//! attack-surface hints).
//!
//! Many engagements hit a CAPTCHA wall before the interesting pages load, and
//! automated tooling (crawlers, scanners, auth-flow fuzzers) needs to *notice*
//! the wall so the operator can decide how to proceed — solve, skip, or switch
//! to a human-driven path. This check is **passive**: it reads the captured
//! response body and headers, matches well-known CAPTCHA provider fingerprints,
//! and emits one informational finding per hit. No requests are sent.
//!
//! What this check does NOT do: bypass the CAPTCHA, train a model to answer it,
//! or decide whether the page is "really protected". The matching is deliberately
//! narrow: a page that merely *mentions* CAPTCHA in prose will not trigger.

use crate::checks::{finding, is_html};
use crate::PassiveCheck;
use camio_core::{Confidence, Finding, HttpExchange, Severity};
use std::sync::OnceLock;

/// The CAPTCHA families Camio can detect from a captured HTML response.
///
/// The order mirrors how common each one is in authenticated-admin attack
/// surface as of 2026: Cloudflare Turnstile and hCaptcha have overtaken
/// reCAPTCHA v2 for new deployments, but reCAPTCHA (v2 and v3) is still what
/// you meet on most legacy sign-in and contact forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaKind {
    /// Google reCAPTCHA v2 ("I'm not a robot" checkbox or image challenge).
    RecaptchaV2,
    /// Google reCAPTCHA v3 (invisible score-based; the page embeds a site key
    /// and calls `grecaptcha.execute`).
    RecaptchaV3,
    /// hCaptcha (Intuition Machines) — reCAPTCHA-compatible drop-in widget.
    HCaptcha,
    /// Cloudflare Turnstile — invisible/non-interactive challenge widget.
    Turnstile,
    /// An inline `<img>` CAPTCHA: a `name="captcha"` / `id="captcha"` input next
    /// to an `<img>` the server renders. This is the family the OCR solver in
    /// `camio-ai::captcha_ocr` can actually attempt to answer.
    ImageInline,
}

impl CaptchaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CaptchaKind::RecaptchaV2 => "reCAPTCHA v2",
            CaptchaKind::RecaptchaV3 => "reCAPTCHA v3",
            CaptchaKind::HCaptcha => "hCaptcha",
            CaptchaKind::Turnstile => "Cloudflare Turnstile",
            CaptchaKind::ImageInline => "image CAPTCHA",
        }
    }

    pub fn solver_hint(self) -> &'static str {
        match self {
            CaptchaKind::ImageInline => {
                "Camio's OCR solver may be able to answer this — run `camio captcha solve <img-url>` or route the exchange through `camio-ai::captcha_ocr`."
            }
            CaptchaKind::RecaptchaV3 | CaptchaKind::Turnstile => {
                "Invisible/score-based; OCR does not apply. Automation needs a real browser session (Camio's managed browser) and an opted-in third-party solving service."
            }
            CaptchaKind::RecaptchaV2 | CaptchaKind::HCaptcha => {
                "Interactive challenge; OCR does not apply. Drive the managed browser with a human-in-the-loop, or forward to a third-party solver with explicit authorization."
            }
        }
    }
}

/// Detect every CAPTCHA kind visible in an HTML response body.
///
/// Returns the distinct kinds (never duplicated) in a stable order; callers use
/// this both for findings and to short-circuit a form-submission workflow.
pub fn detect_in_html(body: &str) -> Vec<CaptchaKind> {
    let mut hits = Vec::new();
    let add = |hits: &mut Vec<CaptchaKind>, k: CaptchaKind| {
        if !hits.contains(&k) {
            hits.push(k);
        }
    };

    // reCAPTCHA families. The script URL `api.js?render=<X>` is the key
    // discriminator: `render=explicit` (or no render param) is v2; `render=`
    // followed by a *site key* is v3's invisible, score-based load. The
    // `g-recaptcha` class (hyphen) marks the v2 checkbox widget and is distinct
    // from the `grecaptcha` JS object (no hyphen) and the `grecaptcha-badge`
    // class, so it does not false-match a v3 page.
    let api_js = body.contains("www.google.com/recaptcha/api.js")
        || body.contains("recaptcha.net/recaptcha/api.js");
    let render_explicit = body.contains("api.js?render=explicit");
    // A `render=` value that isn't the literal "explicit" is a v3 site key.
    let render_sitekey = body.contains("api.js?render=") && !render_explicit;
    let v2_widget_class = body.contains("g-recaptcha");
    let enterprise = body.contains("recaptcha/enterprise.js");

    // v3: score-based site-key load, an explicit `grecaptcha.execute(` call, or
    // the Enterprise script (which is score-based like v3).
    if render_sitekey || body.contains("grecaptcha.execute(") || enterprise {
        add(&mut hits, CaptchaKind::RecaptchaV3);
    }
    // v2: the checkbox/explicit widget — the `g-recaptcha` class, or `api.js`
    // loaded WITHOUT a v3 site-key render param. Guarded by `!render_sitekey` so
    // a pure v3 page (which still references `api.js`) is not also tagged v2.
    if v2_widget_class || (api_js && !render_sitekey) {
        add(&mut hits, CaptchaKind::RecaptchaV2);
    }

    // hCaptcha.
    if body.contains("hcaptcha.com/1/api.js")
        || body.contains("class=\"h-captcha\"")
        || body.contains("class='h-captcha'")
    {
        add(&mut hits, CaptchaKind::HCaptcha);
    }

    // Cloudflare Turnstile.
    if body.contains("challenges.cloudflare.com/turnstile")
        || body.contains("class=\"cf-turnstile\"")
        || body.contains("class='cf-turnstile'")
    {
        add(&mut hits, CaptchaKind::Turnstile);
    }

    // Inline image CAPTCHA — an `<input>` named/id'd `captcha` AND an `<img>`
    // the server renders. Both conditions are required: a lone captcha-named
    // input is usually a widget's hidden response field (e.g. reCAPTCHA's
    // `g-recaptcha-response`, hCaptcha's `h-captcha-response`), which is NOT an
    // OCR-solvable image CAPTCHA — routing those to the OCR solver would be
    // wrong. We also reject inputs whose name carries a known-widget token so a
    // reCAPTCHA/hCaptcha/Turnstile page is never mislabeled `ImageInline`.
    if body_has_img(body) {
        if let Some(re) = image_captcha_re() {
            let is_widget_field = |m: &str| {
                let m = m.to_ascii_lowercase();
                m.contains("recaptcha")
                    || m.contains("h-captcha")
                    || m.contains("hcaptcha")
                    || m.contains("turnstile")
            };
            if re.find_iter(body).any(|m| !is_widget_field(m.as_str())) {
                add(&mut hits, CaptchaKind::ImageInline);
            }
        }
    }

    hits
}

/// `true` when the body contains an `<img` tag (case-insensitive), the visual
/// element an OCR-solvable image CAPTCHA requires.
fn body_has_img(body: &str) -> bool {
    // Cheap case-insensitive scan for the `<img` prefix without allocating a
    // lowercased copy of the whole body.
    let bytes = body.as_bytes();
    bytes.windows(4).any(|w| {
        w[0] == b'<'
            && (w[1] | 0x20) == b'i'
            && (w[2] | 0x20) == b'm'
            && (w[3] | 0x20) == b'g'
    })
}

/// Compile the image-CAPTCHA regex once, process-wide. A compile failure (which
/// cannot happen for this fixed pattern) degrades to "no match" rather than
/// panicking — this crate forbids `unwrap`/`panic!` outside tests.
///
/// The `captcha` token may be surrounded by letters, digits, `_` or `-`
/// (`captcha1`, `user_captcha`, `captcha-code`), so the surrounding class
/// includes `0-9` rather than relying on the trailing `[^>]*` to absorb a digit.
fn image_captcha_re() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?is)<input[^>]*\b(?:name|id)\s*=\s*["']?[a-z0-9_-]*captcha[a-z0-9_-]*["']?[^>]*>"#,
        )
        .ok()
    })
    .as_ref()
}

/// Passive CAPTCHA-presence detector.
pub struct CaptchaPresence;

impl PassiveCheck for CaptchaPresence {
    fn id(&self) -> &'static str {
        "captcha-presence"
    }

    fn title(&self) -> &'static str {
        "CAPTCHA challenge present"
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
        let hits = detect_in_html(&body);
        if hits.is_empty() {
            return Vec::new();
        }

        let names = hits
            .iter()
            .map(|k| format!("`{}`", k.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        let hints = hits
            .iter()
            .map(|k| format!("- **{}**: {}", k.as_str(), k.solver_hint()))
            .collect::<Vec<_>>()
            .join("\n");
        vec![finding(
            "CAPTCHA challenge present",
            Severity::Info,
            Confidence::Firm,
            format!(
                "Detected CAPTCHA widget(s) on this page: {names}. This is attack-surface context for automation planning — the page will block headless replay unless the challenge is solved.\n\nHow to proceed:\n{hints}\n\nNo requests were sent to produce this finding; it was read from the already-captured HTML response."
            ),
            ex.id,
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camio_core::{Body, HeaderList, HttpRequest, HttpResponse, HttpVersion, Source};

    fn html_exchange(body: &str) -> HttpExchange {
        let mut h = HeaderList::new();
        h.push("Content-Type", "text/html");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(body),
        };
        HttpExchange::new(
            HttpRequest::get("https://example.test/login"),
            Source::Scanner,
        )
        .with_response(resp)
    }

    #[test]
    fn detects_recaptcha_v2() {
        let body = r#"<html><body>
            <form><div class="g-recaptcha" data-sitekey="abc"></div></form>
            <script src="https://www.google.com/recaptcha/api.js"></script>
        </body></html>"#;
        let hits = detect_in_html(body);
        assert!(hits.contains(&CaptchaKind::RecaptchaV2));
    }

    #[test]
    fn detects_recaptcha_v3() {
        let body = r#"<script>grecaptcha.execute('key', {action: 'login'})</script>"#;
        assert!(detect_in_html(body).contains(&CaptchaKind::RecaptchaV3));
    }

    #[test]
    fn recaptcha_v3_sitekey_load_is_v3_not_v2() {
        // The invisible v3 load: api.js?render=<sitekey>. Must be v3, and must
        // NOT be double-tagged v2 (the api.js substring would otherwise match).
        let body = r#"<script src="https://www.google.com/recaptcha/api.js?render=6LcABCdef"></script>"#;
        let hits = detect_in_html(body);
        assert!(hits.contains(&CaptchaKind::RecaptchaV3), "{hits:?}");
        assert!(!hits.contains(&CaptchaKind::RecaptchaV2), "{hits:?}");
    }

    #[test]
    fn recaptcha_explicit_render_is_v2_not_v3() {
        // api.js?render=explicit is v2 programmatic render, NOT v3.
        let body = r#"<script src="https://www.google.com/recaptcha/api.js?render=explicit&onload=cb"></script>
                      <div class="g-recaptcha"></div>"#;
        let hits = detect_in_html(body);
        assert!(hits.contains(&CaptchaKind::RecaptchaV2), "{hits:?}");
        assert!(!hits.contains(&CaptchaKind::RecaptchaV3), "{hits:?}");
    }

    #[test]
    fn recaptcha_hidden_response_field_is_not_image_inline() {
        // reCAPTCHA renders a hidden <textarea id="g-recaptcha-response"> and
        // some integrations a hidden input; with an unrelated <img> on the page
        // this must NOT be mislabeled an OCR-solvable image CAPTCHA.
        let body = r#"<html><body>
            <img src="/logo.png" alt="logo">
            <div class="g-recaptcha" data-sitekey="k"></div>
            <input type="hidden" name="g-recaptcha-response" value="">
            <script src="https://www.google.com/recaptcha/api.js"></script>
        </body></html>"#;
        let hits = detect_in_html(body);
        assert!(hits.contains(&CaptchaKind::RecaptchaV2), "{hits:?}");
        assert!(!hits.contains(&CaptchaKind::ImageInline), "{hits:?}");
    }

    #[test]
    fn image_captcha_requires_an_img_element() {
        // A captcha-named input with NO <img> on the page is not an image
        // CAPTCHA (it's likely a widget's response field or a server-side flow).
        let body = r#"<form><input type="text" name="captcha_code"></form>"#;
        assert!(!detect_in_html(body).contains(&CaptchaKind::ImageInline));
    }

    #[test]
    fn image_captcha_matches_digit_suffixed_field() {
        let body = r#"<form><img src="/c.png"><input name="captcha1"></form>"#;
        assert!(detect_in_html(body).contains(&CaptchaKind::ImageInline));
    }

    #[test]
    fn detects_hcaptcha() {
        let body = r#"<div class="h-captcha" data-sitekey="k"></div>
                      <script src="https://js.hcaptcha.com/1/api.js"></script>"#;
        assert!(detect_in_html(body).contains(&CaptchaKind::HCaptcha));
    }

    #[test]
    fn detects_turnstile() {
        let body = r#"<div class="cf-turnstile" data-sitekey="site"></div>"#;
        assert!(detect_in_html(body).contains(&CaptchaKind::Turnstile));
    }

    #[test]
    fn detects_inline_image_captcha() {
        let body = r#"<form>
            <img src="/captcha.png" alt="captcha">
            <input type="text" name="captcha_code" required>
        </form>"#;
        assert!(detect_in_html(body).contains(&CaptchaKind::ImageInline));
    }

    #[test]
    fn plain_prose_mention_does_not_trigger() {
        let body = "<p>Please contact us if the captcha is not working.</p>";
        assert!(detect_in_html(body).is_empty());
    }

    #[test]
    fn check_emits_finding_on_hit_only() {
        let ex = html_exchange(r#"<div class="g-recaptcha"></div>"#);
        let findings = CaptchaPresence.check(&ex);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("reCAPTCHA v2"));
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].confidence, Confidence::Firm);

        let empty = html_exchange("<html></html>");
        assert!(CaptchaPresence.check(&empty).is_empty());
    }

    #[test]
    fn check_skips_non_html() {
        let mut h = HeaderList::new();
        h.push("Content-Type", "application/json");
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: h,
            body: Body::from_text(r#"{"captcha": "/captcha.png"}"#),
        };
        let ex = HttpExchange::new(HttpRequest::get("https://x.test/"), Source::Scanner)
            .with_response(resp);
        assert!(CaptchaPresence.check(&ex).is_empty());
    }

    #[test]
    fn solver_hint_image_names_the_tool() {
        assert!(CaptchaKind::ImageInline.solver_hint().contains("OCR"));
        assert!(CaptchaKind::ImageInline.solver_hint().contains("camio"));
    }
}
