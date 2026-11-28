//! Dynamic, context-aware payload encoding.
//!
//! When a payload reaches a target it must survive the parser the server runs
//! for that particular field. This module names the parsers we care about as
//! **[`InputContext`]**s (URL path, URL query, form-urlencoded, JSON string,
//! XML text, XML attribute, header value, cookie value, HTML body / attribute /
//! script / style, GraphQL string, multipart boundary, raw) and maps each
//! context to the set of **[`Encoding`]**s that are safe-and-interesting for
//! that context.
//!
//! The pipeline that `camio-automate` exposes:
//!
//! 1. Operator supplies a raw payload set (hand-curated, or from
//!    `payloads/DB/base/*.txt`, or built by `combo`).
//! 2. [`expand_for_context`] produces every encoded variant that is compatible
//!    with the destination context. Each variant is tagged with the encoding
//!    name so a classifier can see which representation survived.
//! 3. The caller sends them through the matched engine as usual.
//!
//! The module is pure (no network, no std::fs), tested, and has no external
//! dependencies beyond the standard library.

use std::collections::BTreeSet;
use std::fmt;

use crate::payloads::PayloadSet;

// ---------------------------------------------------------------------------
// Encodings
// ---------------------------------------------------------------------------

/// A named transform of a payload byte-string.
///
/// Adding a variant: implement it in [`Encoding::apply`] and extend
/// [`compatible_encodings`] with the contexts it's valid in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// Identity transform — the payload as-is. Always first in a run.
    Raw,
    /// RFC 3986 percent-encoding of every non-unreserved byte.
    UrlEncoded,
    /// Like [`Encoding::UrlEncoded`] but keeps `/` unencoded — for URL *path*
    /// positions, where encoding `/` to `%2F` would defeat traversal probes.
    UrlEncodedPath,
    /// The path-preserving encoding applied twice.
    UrlEncodedPathDouble,
    /// The path-preserving encoding applied three times.
    UrlEncodedPathTriple,
    /// Percent-encoded twice. Reaches sinks that URL-decode in two hops.
    UrlEncodedDouble,
    /// Percent-encoded three times. For nested proxies.
    UrlEncodedTriple,
    /// HTML-entity-escape: &, <, >, ", '.
    HtmlEntity,
    /// Numeric HTML entities: `&#NN;` for every char.
    HtmlEntityNumeric,
    /// Hex HTML entities: `&#xNN;` for every char.
    HtmlEntityHex,
    /// Base64 (standard, with padding).
    Base64,
    /// Base64 URL-safe (`-_` alphabet, no padding).
    Base64Url,
    /// Lowercase hex, no separator.
    Hex,
    /// Uppercase hex, no separator.
    HexUpper,
    /// `\\uXXXX` escapes for anything non-ASCII-printable (JS/JSON compatible).
    UnicodeEscape,
    /// `\\xNN` escapes of special characters only (JS-string-safe).
    JsStringEscape,
    /// JSON-string escaping: `"`, `\\`, control chars → `\\u00NN`.
    JsonStringEscape,
    /// XML-entity escaping of `&`, `<`, `>`.
    XmlEntity,
    /// SQL comment obfuscation — inserts `/**/` between tokens (lossy-safe).
    SqlCommentObfuscation,
    /// Alternating case for alphabetic characters (`sCrIpT`).
    MixedCase,
    /// Uppercase every alphabetic character.
    UpperCase,
    /// Lowercase every alphabetic character.
    LowerCase,
    /// Prepend a literal `\\0` (useful against some C-based WAFs).
    NullPrefix,
    /// Insert a null-byte terminator after the payload (`%00`).
    NullSuffix,
    /// Overlong UTF-8 of `/` and `.` only (path-traversal bypass).
    OverlongSlash,
    /// Base32 (RFC 4648, uppercase, with padding).
    Base32,
    /// ROT13 (letters only).
    Rot13,
    /// Octal escape of non-ASCII-printable bytes (`\177` style).
    OctalEscape,
    /// `\\uDB80\\uDC00` paired-surrogate style for non-BMP (actually just the
    /// UTF-16 BE hex representation per code unit — compatible with JS/JSON).
    Utf16BeHex,
    /// `String.fromCharCode(97,98,…)` — produces a JS expression that evaluates
    /// to the original string. Suited to `html-script` sinks.
    CharCodeAt,
    /// `\\xNN` backslash-x escape of every byte (always the full string).
    BackslashX,
    /// UTF-7 encoding for the classic IE XSS WAF bypass. Only the first-wave
    /// payload shape; most modern browsers do not interpret UTF-7 anymore, but
    /// some middleware still does.
    Utf7,
    /// Reversed string (useful against some keyword blocklists that only
    /// scan forward).
    Reverse,
}

impl Encoding {
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::UrlEncoded => "url",
            Encoding::UrlEncodedPath => "url-path-encoded",
            Encoding::UrlEncodedPathDouble => "url-path-double",
            Encoding::UrlEncodedPathTriple => "url-path-triple",
            Encoding::UrlEncodedDouble => "url-double",
            Encoding::UrlEncodedTriple => "url-triple",
            Encoding::HtmlEntity => "html",
            Encoding::HtmlEntityNumeric => "html-numeric",
            Encoding::HtmlEntityHex => "html-hex",
            Encoding::Base64 => "b64",
            Encoding::Base64Url => "b64url",
            Encoding::Hex => "hex",
            Encoding::HexUpper => "hex-upper",
            Encoding::UnicodeEscape => "unicode-escape",
            Encoding::JsStringEscape => "js-escape",
            Encoding::JsonStringEscape => "json-escape",
            Encoding::XmlEntity => "xml",
            Encoding::SqlCommentObfuscation => "sql-comment",
            Encoding::MixedCase => "mixed-case",
            Encoding::UpperCase => "upper-case",
            Encoding::LowerCase => "lower-case",
            Encoding::NullPrefix => "null-prefix",
            Encoding::NullSuffix => "null-suffix",
            Encoding::OverlongSlash => "overlong-slash",
            Encoding::Base32 => "b32",
            Encoding::Rot13 => "rot13",
            Encoding::OctalEscape => "octal",
            Encoding::Utf16BeHex => "utf16-be-hex",
            Encoding::CharCodeAt => "fromcharcode",
            Encoding::BackslashX => "backslash-x",
            Encoding::Utf7 => "utf7",
            Encoding::Reverse => "reverse",
        }
    }

    /// Parse by name (case-insensitive). Returns `None` for an unknown name.
    pub fn from_name(name: &str) -> Option<Self> {
        let n = name.trim().to_ascii_lowercase();
        Encoding::all().iter().copied().find(|e| e.name() == n)
    }

    /// Every supported encoding, in stable order. Useful for listing.
    pub fn all() -> &'static [Encoding] {
        &[
            Encoding::Raw,
            Encoding::UrlEncoded,
            Encoding::UrlEncodedPath,
            Encoding::UrlEncodedPathDouble,
            Encoding::UrlEncodedPathTriple,
            Encoding::UrlEncodedDouble,
            Encoding::UrlEncodedTriple,
            Encoding::HtmlEntity,
            Encoding::HtmlEntityNumeric,
            Encoding::HtmlEntityHex,
            Encoding::Base64,
            Encoding::Base64Url,
            Encoding::Base32,
            Encoding::Hex,
            Encoding::HexUpper,
            Encoding::UnicodeEscape,
            Encoding::JsStringEscape,
            Encoding::JsonStringEscape,
            Encoding::XmlEntity,
            Encoding::SqlCommentObfuscation,
            Encoding::MixedCase,
            Encoding::UpperCase,
            Encoding::LowerCase,
            Encoding::NullPrefix,
            Encoding::NullSuffix,
            Encoding::OverlongSlash,
            Encoding::Rot13,
            Encoding::OctalEscape,
            Encoding::Utf16BeHex,
            Encoding::CharCodeAt,
            Encoding::BackslashX,
            Encoding::Utf7,
            Encoding::Reverse,
        ]
    }

    /// Apply this encoding to `value`. Encodings are deterministic and total.
    pub fn apply(self, value: &str) -> String {
        match self {
            Encoding::Raw => value.to_string(),
            Encoding::UrlEncoded => url_encode(value, false),
            Encoding::UrlEncodedPath => url_encode(value, true),
            Encoding::UrlEncodedDouble => url_encode(&url_encode(value, false), false),
            Encoding::UrlEncodedPathDouble => url_encode(&url_encode(value, true), false),
            Encoding::UrlEncodedTriple => {
                url_encode(&url_encode(&url_encode(value, false), false), false)
            }
            Encoding::UrlEncodedPathTriple => {
                url_encode(&url_encode(&url_encode(value, true), false), false)
            }
            Encoding::HtmlEntity => html_entity_escape(value),
            Encoding::HtmlEntityNumeric => {
                value.chars().map(|c| format!("&#{};", c as u32)).collect()
            }
            Encoding::HtmlEntityHex => value
                .chars()
                .map(|c| format!("&#x{:x};", c as u32))
                .collect(),
            Encoding::Base64 => base64_encode(value.as_bytes(), false),
            Encoding::Base64Url => base64_encode(value.as_bytes(), true),
            Encoding::Hex => value.bytes().map(|b| format!("{b:02x}")).collect(),
            Encoding::HexUpper => value.bytes().map(|b| format!("{b:02X}")).collect(),
            Encoding::UnicodeEscape => unicode_escape(value),
            Encoding::JsStringEscape => js_escape(value),
            Encoding::JsonStringEscape => json_escape(value),
            Encoding::XmlEntity => xml_entity_escape(value),
            Encoding::SqlCommentObfuscation => sql_comment_obfuscate(value),
            Encoding::MixedCase => mixed_case(value),
            Encoding::UpperCase => value.to_uppercase(),
            Encoding::LowerCase => value.to_lowercase(),
            Encoding::NullPrefix => format!("\\0{value}"),
            Encoding::NullSuffix => format!("{value}%00"),
            Encoding::OverlongSlash => value.replace('/', "%c0%af").replace('.', "%c0%ae"),
            Encoding::Base32 => base32_encode(value.as_bytes()),
            Encoding::Rot13 => rot13(value),
            Encoding::OctalEscape => octal_escape(value),
            Encoding::Utf16BeHex => utf16_be_hex(value),
            Encoding::CharCodeAt => char_code_at(value),
            Encoding::BackslashX => value.bytes().map(|b| format!("\\x{b:02x}")).collect(),
            Encoding::Utf7 => utf7_encode(value),
            Encoding::Reverse => value.chars().rev().collect(),
        }
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Input contexts
// ---------------------------------------------------------------------------

/// Where a payload is landing on the wire. The right encoding set depends on
/// which parser the server runs for that slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InputContext {
    /// A path segment of the URL.
    UrlPath,
    /// A query-string value (`?a=HERE`).
    UrlQuery,
    /// An `application/x-www-form-urlencoded` value.
    FormUrlencoded,
    /// A JSON string value.
    JsonString,
    /// A JSON numeric slot (rare but exists for coercion issues).
    JsonNumber,
    /// XML text content.
    XmlText,
    /// XML attribute value.
    XmlAttribute,
    /// HTTP header value.
    HttpHeaderValue,
    /// Cookie value (one field of `Cookie:` or `Set-Cookie:`).
    HttpCookie,
    /// HTML body text (between tags).
    HtmlBody,
    /// HTML attribute value (`<a href="HERE">`).
    HtmlAttribute,
    /// Inside `<script>…</script>` (JS string literal).
    HtmlScript,
    /// Inside `<style>…</style>` (CSS value).
    HtmlStyle,
    /// GraphQL string argument.
    GraphqlString,
    /// Multipart form-data file/field.
    Multipart,
    /// No framing — send bytes verbatim (e.g. raw TCP body).
    Raw,
}

impl InputContext {
    /// Parse by short name (`url-query`, `json`, `html-attr`, …).
    pub fn from_name(name: &str) -> Option<Self> {
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            "url-path" | "path" => InputContext::UrlPath,
            "url-query" | "query" | "url" => InputContext::UrlQuery,
            "form" | "form-urlencoded" => InputContext::FormUrlencoded,
            "json" | "json-string" => InputContext::JsonString,
            "json-number" => InputContext::JsonNumber,
            "xml" | "xml-text" => InputContext::XmlText,
            "xml-attr" | "xml-attribute" => InputContext::XmlAttribute,
            "header" | "http-header" => InputContext::HttpHeaderValue,
            "cookie" => InputContext::HttpCookie,
            "html" | "html-body" => InputContext::HtmlBody,
            "html-attr" | "html-attribute" => InputContext::HtmlAttribute,
            "html-script" | "script" => InputContext::HtmlScript,
            "html-style" | "style" | "css" => InputContext::HtmlStyle,
            "graphql" | "graphql-string" => InputContext::GraphqlString,
            "multipart" => InputContext::Multipart,
            "raw" | "none" => InputContext::Raw,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            InputContext::UrlPath => "url-path",
            InputContext::UrlQuery => "url-query",
            InputContext::FormUrlencoded => "form",
            InputContext::JsonString => "json",
            InputContext::JsonNumber => "json-number",
            InputContext::XmlText => "xml",
            InputContext::XmlAttribute => "xml-attr",
            InputContext::HttpHeaderValue => "header",
            InputContext::HttpCookie => "cookie",
            InputContext::HtmlBody => "html",
            InputContext::HtmlAttribute => "html-attr",
            InputContext::HtmlScript => "html-script",
            InputContext::HtmlStyle => "html-style",
            InputContext::GraphqlString => "graphql",
            InputContext::Multipart => "multipart",
            InputContext::Raw => "raw",
        }
    }
}

/// Return the encodings worth trying in `ctx`, in a sensible priority order
/// (cheapest first, raw always first). The returned list is deduplicated and
/// stable.
pub fn compatible_encodings(ctx: InputContext) -> Vec<Encoding> {
    use Encoding::*;
    match ctx {
        // A path position keeps `/` (a null prefix is not wire-valid in any
        // URL/form context, and encoding `/` to `%2F` would defeat traversal).
        InputContext::UrlPath => vec![
            Raw,
            UrlEncodedPath,
            UrlEncodedPathDouble,
            UrlEncodedPathTriple,
            OverlongSlash,
            NullSuffix,
            Hex,
            Base32,
        ],
        InputContext::UrlQuery | InputContext::FormUrlencoded => vec![
            Raw,
            UrlEncoded,
            UrlEncodedDouble,
            UrlEncodedTriple,
            MixedCase,
            OverlongSlash,
            NullSuffix,
            Hex,
            Base32,
        ],
        InputContext::JsonString | InputContext::GraphqlString => vec![
            Raw,
            JsonStringEscape,
            UnicodeEscape,
            BackslashX,
            Base64,
            Base64Url,
            Base32,
            Hex,
        ],
        InputContext::JsonNumber => vec![Raw, Hex],
        InputContext::XmlText => vec![
            Raw,
            XmlEntity,
            HtmlEntityNumeric,
            HtmlEntityHex,
            Base64,
            Base32,
            Hex,
            Utf16BeHex,
        ],
        InputContext::XmlAttribute => vec![
            Raw,
            XmlEntity,
            HtmlEntityNumeric,
            HtmlEntityHex,
            UrlEncoded,
            Base64,
        ],
        InputContext::HttpHeaderValue | InputContext::HttpCookie => vec![
            Raw,
            UrlEncoded,
            UrlEncodedDouble,
            Hex,
            Base64,
            Base64Url,
            Base32,
            Rot13,
            MixedCase,
        ],
        InputContext::HtmlBody => vec![
            Raw,
            HtmlEntity,
            HtmlEntityNumeric,
            HtmlEntityHex,
            MixedCase,
            UnicodeEscape,
            UrlEncoded,
            Utf7,
        ],
        InputContext::HtmlAttribute => vec![
            Raw,
            HtmlEntity,
            HtmlEntityNumeric,
            HtmlEntityHex,
            UrlEncoded,
            UnicodeEscape,
            MixedCase,
        ],
        InputContext::HtmlScript => vec![
            Raw,
            JsStringEscape,
            UnicodeEscape,
            HtmlEntity,
            HtmlEntityNumeric,
            CharCodeAt,
            BackslashX,
            OctalEscape,
            Base64,
        ],
        InputContext::HtmlStyle => vec![Raw, HtmlEntity, UrlEncoded, UnicodeEscape],
        InputContext::Multipart => vec![Raw, UrlEncoded, Base64, Base32, Hex],
        InputContext::Raw => vec![Raw, Base64, Base64Url, Base32, Hex, UrlEncoded, Reverse],
    }
}

/// Encodings relevant when the payload is an SQL-style snippet (works in any
/// context where the server will later parse it as SQL).
pub fn sql_encodings() -> Vec<Encoding> {
    vec![
        Encoding::Raw,
        Encoding::SqlCommentObfuscation,
        Encoding::MixedCase,
        Encoding::UpperCase,
        Encoding::LowerCase,
        Encoding::UrlEncoded,
        Encoding::UrlEncodedDouble,
        Encoding::Hex,
    ]
}

// ---------------------------------------------------------------------------
// Expansion (dynamic encoded-payload testing)
// ---------------------------------------------------------------------------

/// A payload paired with the encoding that produced it. Carried through
/// expansion so a classifier can see which encoding survived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPayload {
    pub body: String,
    pub encoding: Encoding,
}

/// Expand `set` into every (payload × encoding) pair compatible with `ctx`,
/// deduplicated. Raw always comes first for each input payload so the
/// un-encoded shot is tested before the encoded shots.
pub fn expand_for_context(set: &PayloadSet, ctx: InputContext) -> Vec<EncodedPayload> {
    expand_with_encodings(set, &compatible_encodings(ctx))
}

/// Expand `set` through an explicit encoding list. Preserves the given order
/// (so callers can promote the cheapest encodings) and dedups by `(body, encoding)`.
pub fn expand_with_encodings(set: &PayloadSet, encodings: &[Encoding]) -> Vec<EncodedPayload> {
    let mut out: Vec<EncodedPayload> = Vec::new();
    // Dedup on the *body*: two encodings that produce the same bytes are the
    // same request on the wire, and sending both wastes a probe slot.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for raw in &set.payloads {
        for &enc in encodings {
            let body = enc.apply(raw);
            if body.is_empty() {
                continue;
            }
            if seen.insert(body.clone()) {
                out.push(EncodedPayload {
                    body,
                    encoding: enc,
                });
            }
        }
    }
    out
}

/// Materialize a context-expanded set back into a [`PayloadSet`] — bodies only,
/// order preserved. Useful for pumping into the campaign generator.
pub fn to_payload_set(name: &str, expanded: &[EncodedPayload]) -> PayloadSet {
    PayloadSet::new(name, expanded.iter().map(|e| e.body.clone()).collect())
}

// ---------------------------------------------------------------------------
// Mutation chains (sequential / composed encodings for WAF evasion)
// ---------------------------------------------------------------------------

/// Apply a *chain* of encodings to `payload`, folding left-to-right: start with
/// `payload`, apply `chain[0]`, then `chain[1]` to that result, and so on.
///
/// Unlike [`expand_with_encodings`] — which treats each encoding as an
/// independent *alternative* representation — a chain **composes** encodings,
/// so each transform feeds the next. For example `[UrlEncoded, UrlEncoded]`
/// double-url-encodes (a space `" "` → `"%20"` → `"%2520"`), the shape that
/// defeats a WAF that URL-decodes exactly once before matching.
///
/// An empty chain returns `payload` unchanged (the identity fold).
pub fn apply_encoding_chain(payload: &str, chain: &[Encoding]) -> String {
    chain
        .iter()
        .fold(payload.to_string(), |acc, enc| enc.apply(&acc))
}

/// Parse a `>`-separated chain spec (e.g. `"url>url>b64"`) into an ordered list
/// of [`Encoding`]s, left-to-right in application order.
///
/// Each token is trimmed and resolved through [`Encoding::from_name`]
/// (case-insensitive). The first unresolved token yields
/// `Err("unknown encoding `<tok>`")`. An empty or whitespace-only spec is an
/// error too (a chain must name at least one encoding).
pub fn parse_encoding_chain(spec: &str) -> Result<Vec<Encoding>, String> {
    if spec.trim().is_empty() {
        return Err("empty encoding chain".to_string());
    }
    let mut chain = Vec::new();
    for tok in spec.split('>') {
        let name = tok.trim();
        match Encoding::from_name(name) {
            Some(enc) => chain.push(enc),
            None => return Err(format!("unknown encoding `{name}`")),
        }
    }
    Ok(chain)
}

/// Apply a composed encoding `chain` to every payload in `set`, preserving the
/// set's order. The chain is folded onto each payload independently (see
/// [`apply_encoding_chain`]).
pub fn chain_payload_set(set: &PayloadSet, chain: &[Encoding]) -> Vec<String> {
    set.payloads
        .iter()
        .map(|p| apply_encoding_chain(p, chain))
        .collect()
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~')
}

fn url_encode(value: &str, keep_slashes: bool) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for b in value.bytes() {
        if is_unreserved(b) || (keep_slashes && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn html_entity_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn xml_entity_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn base64_encode(bytes: &[u8], url_safe: bool) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let table = if url_safe { URL } else { STD };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        let b2 = bytes[i + 2];
        out.push(table[(b0 >> 2) as usize] as char);
        out.push(table[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        out.push(table[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        out.push(table[(b2 & 0b111111) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b0 = bytes[i];
        out.push(table[(b0 >> 2) as usize] as char);
        out.push(table[((b0 & 0b11) << 4) as usize] as char);
        if !url_safe {
            out.push_str("==");
        }
    } else if rem == 2 {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        out.push(table[(b0 >> 2) as usize] as char);
        out.push(table[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        out.push(table[((b1 & 0b1111) << 2) as usize] as char);
        if !url_safe {
            out.push('=');
        }
    }
    out
}

fn unicode_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_ascii() && c.is_ascii_graphic() && !matches!(c, '\\' | '"' | '\'' | '<' | '>') {
            out.push(c);
        } else {
            let code = c as u32;
            if code <= 0xFFFF {
                out.push_str(&format!("\\u{code:04x}"));
            } else {
                // Surrogate pair.
                let code = code - 0x10000;
                let high = 0xD800 + (code >> 10);
                let low = 0xDC00 + (code & 0x3FF);
                out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
        }
    }
    out
}

fn js_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '"' | '\'' | '<' | '>' | '/' | '\n' | '\r' | '\t') {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn sql_comment_obfuscate(value: &str) -> String {
    // Insert `/**/` between every pair of SQL keyword tokens if the payload
    // looks SQL-ish; otherwise fall back to inserting between every space.
    const KEYWORDS: &[&str] = &[
        "UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP",
        "GROUP", "ORDER", "BY", "HAVING", "LIMIT", "INTO", "VALUES", "TABLE", "JOIN", "ON",
    ];
    let upper = value.to_uppercase();
    let mut has_keyword = false;
    for k in KEYWORDS {
        if upper.contains(k) {
            has_keyword = true;
            break;
        }
    }
    if !has_keyword {
        return value.replace(' ', "/**/");
    }
    let mut out = String::with_capacity(value.len() + value.len() / 4);
    let mut prev_was_word = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if !prev_was_word && !out.is_empty() && !out.ends_with("/**/") {
                out.push_str("/**/");
            }
            prev_was_word = true;
            out.push(ch);
        } else if ch == ' ' {
            out.push_str("/**/");
            prev_was_word = false;
        } else {
            out.push(ch);
            prev_was_word = false;
        }
    }
    out
}

fn mixed_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut flip = true;
    for c in value.chars() {
        if c.is_ascii_alphabetic() {
            if flip {
                out.extend(c.to_uppercase());
            } else {
                out.extend(c.to_lowercase());
            }
            flip = !flip;
        } else {
            out.push(c);
        }
    }
    out
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits = 0usize;
    for &b in bytes {
        buffer = (buffer << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn rot13(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from_u32(c as u32 + 13).unwrap_or(c),
            'n'..='z' | 'N'..='Z' => char::from_u32(c as u32 - 13).unwrap_or(c),
            _ => c,
        })
        .collect()
}

fn octal_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 4);
    for b in value.bytes() {
        if b.is_ascii_graphic() && !matches!(b, b'\\' | b'"' | b'\'' | b'<' | b'>') {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\{b:03o}"));
        }
    }
    out
}

fn utf16_be_hex(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 4);
    for code_unit in value.encode_utf16() {
        out.push_str(&format!("{code_unit:04x}"));
    }
    out
}

fn char_code_at(value: &str) -> String {
    let codes: Vec<String> = value.chars().map(|c| (c as u32).to_string()).collect();
    format!("String.fromCharCode({})", codes.join(","))
}

fn utf7_encode(value: &str) -> String {
    // Classic IE XSS WAF-bypass shape. Only non-direct chars are base64-encoded
    // between `+` and `-`; `+` itself becomes `+-`. Direct charset is the
    // RFC-2152 "set D" plus the ASCII ones from set O.
    fn is_direct(c: char) -> bool {
        matches!(c,
            'A'..='Z' | 'a'..='z' | '0'..='9'
            | '\'' | '(' | ')' | ',' | '-' | '.' | '/' | ':' | '?' | ' '
            | '\t' | '\r' | '\n'
        )
    }
    let mut out = String::with_capacity(value.len() + 16);
    let mut buf = String::new();
    let flush = |buf: &mut String, out: &mut String| {
        if buf.is_empty() {
            return;
        }
        let utf16: Vec<u16> = buf.encode_utf16().collect();
        let mut bytes = Vec::with_capacity(utf16.len() * 2);
        for u in &utf16 {
            bytes.push((*u >> 8) as u8);
            bytes.push((*u & 0xff) as u8);
        }
        let mut b64 = base64_encode(&bytes, false);
        while b64.ends_with('=') {
            b64.pop();
        }
        out.push('+');
        out.push_str(&b64);
        out.push('-');
        buf.clear();
    };
    for c in value.chars() {
        if c == '+' {
            flush(&mut buf, &mut out);
            out.push_str("+-");
        } else if is_direct(c) {
            flush(&mut buf, &mut out);
            out.push(c);
        } else {
            buf.push(c);
        }
    }
    flush(&mut buf, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn set(name: &str, items: &[&str]) -> PayloadSet {
        PayloadSet::new(name, items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn raw_is_identity() {
        assert_eq!(Encoding::Raw.apply("<script>"), "<script>");
    }

    #[test]
    fn url_encode_escapes_specials() {
        assert_eq!(Encoding::UrlEncoded.apply("a b"), "a%20b");
        assert_eq!(Encoding::UrlEncoded.apply("a&b=c"), "a%26b%3Dc");
        assert_eq!(Encoding::UrlEncoded.apply("<script>"), "%3Cscript%3E");
    }

    #[test]
    fn url_encode_double_and_triple() {
        assert_eq!(Encoding::UrlEncodedDouble.apply(" "), "%2520");
        assert_eq!(Encoding::UrlEncodedTriple.apply(" "), "%252520");
    }

    #[test]
    fn html_entity_escapes_five_specials() {
        assert_eq!(
            Encoding::HtmlEntity.apply("<a href=\"x&y\">'"),
            "&lt;a href=&quot;x&amp;y&quot;&gt;&#39;"
        );
    }

    #[test]
    fn html_entity_numeric_and_hex() {
        assert_eq!(Encoding::HtmlEntityNumeric.apply("ab"), "&#97;&#98;");
        assert_eq!(Encoding::HtmlEntityHex.apply("ab"), "&#x61;&#x62;");
    }

    #[test]
    fn base64_standard_and_url() {
        assert_eq!(Encoding::Base64.apply("hello"), "aGVsbG8=");
        assert_eq!(Encoding::Base64Url.apply("hello"), "aGVsbG8");
        assert_eq!(Encoding::Base64.apply("?>>"), "Pz4+");
        assert_eq!(Encoding::Base64Url.apply("?>>"), "Pz4-");
    }

    #[test]
    fn hex_variants() {
        assert_eq!(Encoding::Hex.apply("ab"), "6162");
        // digits-only hex is case-identical; use a char that produces letters.
        assert_eq!(Encoding::Hex.apply("A"), "41");
        assert_eq!(Encoding::HexUpper.apply("A"), "41");
        // A char that produces hex letters: `o` (0x6f) — both lower and upper
        // produce `6f`/`6F` respectively.
        assert_eq!(Encoding::Hex.apply("\u{007f}"), "7f");
        assert_eq!(Encoding::HexUpper.apply("\u{007f}"), "7F");
    }

    #[test]
    fn mixed_case_alternates_alphabetic() {
        assert_eq!(Encoding::MixedCase.apply("script"), "ScRiPt");
        // Non-alpha characters don't advance the flip, so "a1b2c3" ->
        // A(flip)-1-b(flip)-2-C(flip)-3 yields "A1b2C3".
        assert_eq!(Encoding::MixedCase.apply("a1b2c3"), "A1b2C3");
    }

    #[test]
    fn sql_comment_obfuscates_keywords() {
        let s = Encoding::SqlCommentObfuscation.apply("UNION SELECT 1");
        assert!(s.contains("/**/"));
        assert!(!s.contains(" "));
    }

    #[test]
    fn js_escape_quotes_and_angles() {
        let s = Encoding::JsStringEscape.apply("<x\"y>");
        assert!(s.contains("\\x3c"));
        assert!(s.contains("\\x22"));
    }

    #[test]
    fn json_escape_quotes_backslashes_controls() {
        let s = Encoding::JsonStringEscape.apply("a\"b\\c\n");
        assert_eq!(s, "a\\\"b\\\\c\\n");
    }

    #[test]
    fn unicode_escape_non_ascii() {
        let s = Encoding::UnicodeEscape.apply("aΩb");
        assert!(s.contains("\\u03a9"));
    }

    #[test]
    fn overlong_slash_replaces_slashes_and_dots() {
        let s = Encoding::OverlongSlash.apply("../x/");
        assert!(s.contains("%c0%af"));
        assert!(s.contains("%c0%ae"));
    }

    #[test]
    fn compatible_encodings_always_lead_with_raw() {
        for ctx in [
            InputContext::UrlQuery,
            InputContext::JsonString,
            InputContext::HtmlBody,
            InputContext::HttpHeaderValue,
            InputContext::GraphqlString,
            InputContext::XmlText,
            InputContext::XmlAttribute,
            InputContext::HtmlScript,
        ] {
            let list = compatible_encodings(ctx);
            assert_eq!(list.first(), Some(&Encoding::Raw), "ctx {ctx:?}");
            // No duplicates.
            let mut dedup = list.clone();
            dedup.sort_unstable();
            dedup.dedup();
            assert_eq!(dedup.len(), list.len(), "dup in {ctx:?}");
        }
    }

    #[test]
    fn expand_for_context_produces_raw_plus_variants() {
        let s = set("xss", &["<x>"]);
        let out = expand_for_context(&s, InputContext::HtmlBody);
        assert!(out
            .iter()
            .any(|p| p.encoding == Encoding::Raw && p.body == "<x>"));
        assert!(out.iter().any(|p| p.encoding == Encoding::HtmlEntity));
        // Raw always first for each payload.
        assert_eq!(out[0].encoding, Encoding::Raw);
    }

    #[test]
    fn expand_dedups_identical_encodings() {
        let s = set("same", &["abc"]);
        // Two encodings that produce the same bytes are the same request.
        let out = expand_with_encodings(&s, &[Encoding::Raw, Encoding::LowerCase]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].body, "abc");
    }

    #[test]
    fn to_payload_set_preserves_order() {
        let s = set("x", &["<a>", "<b>"]);
        let out = expand_with_encodings(&s, &[Encoding::Raw]);
        let ps = to_payload_set("expanded", &out);
        assert_eq!(ps.payloads, vec!["<a>", "<b>"]);
    }

    #[test]
    fn encoding_name_roundtrip() {
        for &e in Encoding::all() {
            assert_eq!(Encoding::from_name(e.name()), Some(e));
        }
    }

    #[test]
    fn context_name_roundtrip() {
        for n in [
            "url-query",
            "json",
            "header",
            "html",
            "html-attr",
            "html-script",
            "xml",
            "cookie",
            "graphql",
            "raw",
        ] {
            let c = InputContext::from_name(n).unwrap();
            assert!(!c.name().is_empty());
        }
    }

    #[test]
    fn sql_encodings_covers_the_core_bypass_set() {
        let s = sql_encodings();
        assert!(s.contains(&Encoding::SqlCommentObfuscation));
        assert!(s.contains(&Encoding::MixedCase));
        assert!(s.contains(&Encoding::UrlEncoded));
    }

    #[test]
    fn base32_encode_known_vectors() {
        // RFC 4648 §10 — the empty string encodes to empty.
        assert_eq!(Encoding::Base32.apply(""), "");
        // "f" -> "MY======", "fo" -> "MZXQ====", "foo" -> "MZXW6==="
        assert_eq!(Encoding::Base32.apply("f"), "MY======");
        assert_eq!(Encoding::Base32.apply("fo"), "MZXQ====");
        assert_eq!(Encoding::Base32.apply("foo"), "MZXW6===");
        assert_eq!(Encoding::Base32.apply("foob"), "MZXW6YQ=");
        assert_eq!(Encoding::Base32.apply("fooba"), "MZXW6YTB");
        assert_eq!(Encoding::Base32.apply("foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn rot13_is_self_inverse() {
        let s = "Hello, World! 123";
        let once = Encoding::Rot13.apply(s);
        assert_eq!(once, "Uryyb, Jbeyq! 123");
        let twice = Encoding::Rot13.apply(&once);
        assert_eq!(twice, s);
    }

    #[test]
    fn octal_escape_escapes_specials() {
        // `<` is 0x3c = \074; `a` is 0x61 = \141 but printable -> kept.
        let s = Encoding::OctalEscape.apply("a<b");
        assert_eq!(s, "a\\074b");
        let s2 = Encoding::OctalEscape.apply("'\"");
        assert!(s2.starts_with("\\"));
    }

    #[test]
    fn utf16_be_hex_emits_two_bytes_per_code_unit() {
        let s = Encoding::Utf16BeHex.apply("AB");
        assert_eq!(s, "00410042");
        // Non-BMP uses a surrogate pair -> 4 code units -> 8 hex chars.
        let emoji = Encoding::Utf16BeHex.apply("\u{1F600}");
        assert_eq!(emoji.len(), 8);
        assert!(emoji.starts_with("d83d"));
    }

    #[test]
    fn char_code_at_emits_js_call() {
        assert_eq!(
            Encoding::CharCodeAt.apply("AB"),
            "String.fromCharCode(65,66)"
        );
    }

    #[test]
    fn backslash_x_escapes_every_byte() {
        assert_eq!(Encoding::BackslashX.apply("AB"), "\\x41\\x42");
    }

    #[test]
    fn utf7_wraps_special_chars() {
        // The classic IE XSS bypass: `<script>` under UTF-7.
        let s = Encoding::Utf7.apply("<script>");
        // Must begin with `+` for a non-direct run.
        assert!(s.contains('+'));
        // Must end with `-` to close the base64 run.
        assert!(s.ends_with('-'));
        // Direct chars like 'script' would have been passed through, so the
        // encoded run should be short (just `<` and `>` in the two runs).
        assert!(s.contains("script") || s.len() > 2);
    }

    #[test]
    fn reverse_is_its_own_inverse_for_ascii() {
        let s = Encoding::Reverse.apply("abcdef");
        assert_eq!(s, "fedcba");
        assert_eq!(Encoding::Reverse.apply(&s), "abcdef");
    }

    #[test]
    fn all_encodings_enumerated_in_all_function() {
        let n = Encoding::all().len();
        // At least the 30 we've defined so far.
        assert!(n >= 30, "expected >=30, got {n}");
        // from_name roundtrip still holds for everything.
        for e in Encoding::all() {
            assert_eq!(Encoding::from_name(e.name()), Some(*e));
        }
    }

    #[test]
    fn html_script_context_offers_fromcharcode_and_backslash_x() {
        let encs = compatible_encodings(InputContext::HtmlScript);
        assert!(encs.contains(&Encoding::CharCodeAt));
        assert!(encs.contains(&Encoding::BackslashX));
        assert!(encs.contains(&Encoding::OctalEscape));
    }

    #[test]
    fn header_context_offers_rot13_and_base32() {
        let encs = compatible_encodings(InputContext::HttpHeaderValue);
        assert!(encs.contains(&Encoding::Rot13));
        assert!(encs.contains(&Encoding::Base32));
    }

    #[test]
    fn encoding_chain_double_url_encodes() {
        // url>url composes: " " -> "%20" -> "%2520" (defeats a WAF that decodes
        // exactly once). This is distinct from url applied as an alternative.
        let chain = [Encoding::UrlEncoded, Encoding::UrlEncoded];
        assert_eq!(apply_encoding_chain(" ", &chain), "%2520");
        // A single-element chain is just that one encoding.
        assert_eq!(
            apply_encoding_chain("hello", &[Encoding::Base64]),
            "aGVsbG8="
        );
    }

    #[test]
    fn encoding_chain_empty_is_identity() {
        assert_eq!(apply_encoding_chain("<script>", &[]), "<script>");
    }

    #[test]
    fn encoding_chain_folds_left_to_right() {
        // url then base64: the base64 is of the url-encoded bytes, not the raw.
        let chain = [Encoding::UrlEncoded, Encoding::Base64];
        let expected = Encoding::Base64.apply(&Encoding::UrlEncoded.apply("a b"));
        assert_eq!(apply_encoding_chain("a b", &chain), expected);
        // Order matters: the reverse chain generally differs.
        let rev = [Encoding::Base64, Encoding::UrlEncoded];
        assert_ne!(
            apply_encoding_chain("a b", &chain),
            apply_encoding_chain("a b", &rev)
        );
    }

    #[test]
    fn parse_encoding_chain_parses_and_errors() {
        assert_eq!(
            parse_encoding_chain("url>html").unwrap(),
            vec![Encoding::UrlEncoded, Encoding::HtmlEntity]
        );
        // Tokens are trimmed and case-insensitive.
        assert_eq!(
            parse_encoding_chain(" URL > URL > b64 ").unwrap(),
            vec![Encoding::UrlEncoded, Encoding::UrlEncoded, Encoding::Base64]
        );
        // Unknown token -> error naming the token.
        let err = parse_encoding_chain("url>nope").unwrap_err();
        assert!(err.contains("nope"), "got {err}");
        // Empty / whitespace spec is an error.
        assert!(parse_encoding_chain("").is_err());
        assert!(parse_encoding_chain("   ").is_err());
    }

    #[test]
    fn parse_then_apply_round_trips_a_chain() {
        let chain = parse_encoding_chain("url>url").unwrap();
        assert_eq!(apply_encoding_chain(" ", &chain), "%2520");
    }

    #[test]
    fn chain_payload_set_maps_each_payload() {
        let s = set("x", &["a b", "c d"]);
        let out = chain_payload_set(&s, &[Encoding::UrlEncoded, Encoding::UrlEncoded]);
        assert_eq!(out, vec!["a%2520b".to_string(), "c%2520d".to_string()]);
        // Empty chain leaves every payload untouched, order preserved.
        let identity = chain_payload_set(&s, &[]);
        assert_eq!(identity, vec!["a b".to_string(), "c d".to_string()]);
    }
}

#[cfg(test)]
mod encoding_fix_tests {
    use super::*;

    #[test]
    fn path_positions_keep_slashes() {
        // `../` must stay `../` (encoded only where needed): `%2e%2e%2f` is a
        // different byte stream than `../`.
        let path = Encoding::UrlEncodedPath.apply("../../etc/passwd");
        assert_eq!(path, "../../etc/passwd");
        // Query positions still encode the slash.
        assert_eq!(Encoding::UrlEncoded.apply("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn url_contexts_have_no_null_prefix() {
        // A null prefix is not a wire-valid probe in a URL/form context.
        for ctx in [
            InputContext::UrlPath,
            InputContext::UrlQuery,
            InputContext::FormUrlencoded,
        ] {
            let encodings = compatible_encodings(ctx);
            assert!(
                !encodings.contains(&Encoding::NullPrefix),
                "{ctx:?} must not include a null prefix"
            );
        }
    }

    #[test]
    fn identical_bodies_are_not_emitted_twice() {
        // `Raw` and `LowerCase` of "abc" are the same bytes: one request, not two.
        let set = PayloadSet::new("x", vec!["abc".to_string()]);
        let expanded = expand_with_encodings(&set, &[Encoding::Raw, Encoding::LowerCase]);
        let bodies: Vec<&str> = expanded.iter().map(|e| e.body.as_str()).collect();
        assert_eq!(bodies, vec!["abc"], "got {bodies:?}");
    }
}
