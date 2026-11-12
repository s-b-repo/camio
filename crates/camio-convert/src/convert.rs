//! Reversible encodings, one-way hashes, and the [`Transform`] catalog
//! (plan §8 "Convert / Decoder / Comparer", §7.3 "inline encode/decode").
//!
//! Every operation here is pure — it takes `&[u8]` and returns owned bytes — so
//! the same catalog backs the inline message-editor Convert control, the `camio
//! convert` CLI verb, and a Convert node reused inside a Workflow (plan §8).
//! Design rules shared with the rest of Camio:
//!
//!   * **No panics.** Every fallible path returns a typed [`ConvertError`] that
//!     implements [`Display`](std::fmt::Display) + [`std::error::Error`]; a bad
//!     payload is data, never a crash.
//!   * **Byte-exact round-trips.** For every reversible [`Transform`], decoding
//!     an encoding reproduces the original bytes for all of `0..=255`, so the
//!     editor can round-trip a selection without mangling it.
//!   * **Hashes are one-way** and emit a lowercase hex digest; they report
//!     [`is_reversible`](Transform::is_reversible) `== false`.
//!
//! This module hand-rolls the small, well-specified codecs (hex, percent, HTML
//! entities) and leans on the crate's declared dependencies for base64, the
//! RustCrypto digests, and flate2 (gzip/deflate). It deliberately depends on no
//! other Camio crate — a Convert step is reusable everywhere.

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use flate2::read::{DeflateDecoder, GzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::io::{Read, Write};

/// Standard base64 (RFC 4648 §4). Encodes with canonical `=` padding; decoding
/// is padding-indifferent and tolerant of embedded ASCII whitespace so pasted,
/// line-wrapped payloads decode.
const B64_STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// URL- and filename-safe base64 (RFC 4648 §5), the alphabet JWT uses. Encodes
/// **without** padding (the common `-`/`_` form); decoding is padding-indifferent
/// so both padded and unpadded input round-trip.
const B64_URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// An error from a Convert operation. Carries a human-readable reason for the
/// status bar / CLI; never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConvertError {
    /// Input was not valid for the decoder (bad base64/hex/percent/UTF-8, odd
    /// hex length, a malformed JWT, …).
    Decode(String),
    /// A compressed stream could not be inflated (truncated/corrupt gzip or
    /// deflate data).
    Decompress(String),
    /// The requested transform is not available in this build/context.
    Unsupported(String),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConvertError::Decode(s) => write!(f, "decode error: {s}"),
            ConvertError::Decompress(s) => write!(f, "decompress error: {s}"),
            ConvertError::Unsupported(s) => write!(f, "unsupported transform: {s}"),
        }
    }
}

impl std::error::Error for ConvertError {}

// ---------------------------------------------------------------------------
// Transform catalog
// ---------------------------------------------------------------------------

/// A single reversible encoding, one-way hash, or (de)compression operation.
///
/// Variants come in encode/decode (or compress/decompress) pairs except the
/// four trailing hashes, which are encode-only. Use [`Transform::apply`] to run
/// one, [`Transform::from_name`]/[`Transform::name`] to map to/from CLI tokens,
/// and [`apply_pipeline`] to chain several left-to-right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transform {
    Base64Encode,
    Base64Decode,
    Base64UrlEncode,
    Base64UrlDecode,
    UrlEncode,
    UrlDecode,
    HtmlEncode,
    HtmlDecode,
    HexEncode,
    HexDecode,
    GzipCompress,
    GzipDecompress,
    DeflateCompress,
    DeflateDecompress,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

/// Every [`Transform`], in catalog order — the backing array for
/// [`Transform::all`] and [`Transform::from_name`].
const ALL: [Transform; 18] = [
    Transform::Base64Encode,
    Transform::Base64Decode,
    Transform::Base64UrlEncode,
    Transform::Base64UrlDecode,
    Transform::UrlEncode,
    Transform::UrlDecode,
    Transform::HtmlEncode,
    Transform::HtmlDecode,
    Transform::HexEncode,
    Transform::HexDecode,
    Transform::GzipCompress,
    Transform::GzipDecompress,
    Transform::DeflateCompress,
    Transform::DeflateDecompress,
    Transform::Md5,
    Transform::Sha1,
    Transform::Sha256,
    Transform::Sha512,
];

impl Transform {
    /// The canonical kebab-case token for this transform. Round-trips through
    /// [`Transform::from_name`] (i.e. `from_name(t.name()) == Some(t)`).
    pub fn name(self) -> &'static str {
        match self {
            Transform::Base64Encode => "base64",
            Transform::Base64Decode => "base64-decode",
            Transform::Base64UrlEncode => "base64url",
            Transform::Base64UrlDecode => "base64url-decode",
            Transform::UrlEncode => "url",
            Transform::UrlDecode => "url-decode",
            Transform::HtmlEncode => "html",
            Transform::HtmlDecode => "html-decode",
            Transform::HexEncode => "hex",
            Transform::HexDecode => "hex-decode",
            Transform::GzipCompress => "gzip",
            Transform::GzipDecompress => "gunzip",
            Transform::DeflateCompress => "deflate",
            Transform::DeflateDecompress => "inflate",
            Transform::Md5 => "md5",
            Transform::Sha1 => "sha1",
            Transform::Sha256 => "sha256",
            Transform::Sha512 => "sha512",
        }
    }

    /// Resolve a CLI/workflow token to a transform, accepting kebab aliases.
    ///
    /// The bare family name is the forward operation (`"base64"`, `"url"`,
    /// `"html"`, `"hex"` encode; `"gzip"`/`"deflate"` compress). Explicit
    /// `-encode`/`-decode` (and `-compress`/`-decompress`) long forms, plus the
    /// `gunzip`/`inflate` inverses, are all accepted. Matching is case-sensitive
    /// (tokens are already lowercase kebab). Returns `None` for an unknown token.
    pub fn from_name(s: &str) -> Option<Transform> {
        let t = match s {
            "base64" | "base64-encode" | "b64" | "b64encode" => Transform::Base64Encode,
            "base64-decode" | "b64decode" | "unbase64" => Transform::Base64Decode,
            "base64url" | "base64url-encode" | "base64-url" | "b64url" => {
                Transform::Base64UrlEncode
            }
            "base64url-decode" | "base64-url-decode" | "b64url-decode" => {
                Transform::Base64UrlDecode
            }
            "url" | "url-encode" | "urlencode" | "percent" | "percent-encode" => {
                Transform::UrlEncode
            }
            "url-decode" | "urldecode" | "percent-decode" => Transform::UrlDecode,
            "html" | "html-encode" | "htmlencode" | "html-entities" => Transform::HtmlEncode,
            "html-decode" | "htmldecode" | "html-entity-decode" => Transform::HtmlDecode,
            "hex" | "hex-encode" | "hexencode" => Transform::HexEncode,
            "hex-decode" | "hexdecode" | "unhex" => Transform::HexDecode,
            "gzip" | "gzip-compress" | "gz" => Transform::GzipCompress,
            "gunzip" | "gzip-decompress" | "gzip-decode" => Transform::GzipDecompress,
            "deflate" | "deflate-compress" => Transform::DeflateCompress,
            "inflate" | "deflate-decompress" | "deflate-decode" => Transform::DeflateDecompress,
            "md5" => Transform::Md5,
            "sha1" | "sha-1" => Transform::Sha1,
            "sha256" | "sha-256" => Transform::Sha256,
            "sha512" | "sha-512" => Transform::Sha512,
            _ => return None,
        };
        Some(t)
    }

    /// Every transform, for CLI listing / autocomplete (plan §7.3 query bar).
    pub fn all() -> &'static [Transform] {
        &ALL
    }

    /// Whether this transform can be undone by another transform in the catalog.
    /// The four hashes are one-way and return `false`; everything else `true`.
    pub fn is_reversible(self) -> bool {
        !matches!(
            self,
            Transform::Md5 | Transform::Sha1 | Transform::Sha256 | Transform::Sha512
        )
    }

    /// Run the transform over `input`, returning owned output bytes.
    pub fn apply(self, input: &[u8]) -> Result<Vec<u8>, ConvertError> {
        match self {
            Transform::Base64Encode => Ok(B64_STD.encode(input).into_bytes()),
            Transform::Base64Decode => b64_decode(&B64_STD, input),
            Transform::Base64UrlEncode => Ok(B64_URL.encode(input).into_bytes()),
            Transform::Base64UrlDecode => b64_decode(&B64_URL, input),
            Transform::UrlEncode => Ok(url_encode(input)),
            Transform::UrlDecode => Ok(url_decode(input)),
            Transform::HtmlEncode => Ok(html_encode(input)),
            Transform::HtmlDecode => Ok(html_decode(input)),
            Transform::HexEncode => Ok(hex_encode(input)),
            Transform::HexDecode => hex_decode(input),
            Transform::GzipCompress => gzip_compress(input),
            Transform::GzipDecompress => gzip_decompress(input),
            Transform::DeflateCompress => deflate_compress(input),
            Transform::DeflateDecompress => deflate_decompress(input),
            Transform::Md5 => Ok(hex_encode(Md5::digest(input).as_slice())),
            Transform::Sha1 => Ok(hex_encode(Sha1::digest(input).as_slice())),
            Transform::Sha256 => Ok(hex_encode(Sha256::digest(input).as_slice())),
            Transform::Sha512 => Ok(hex_encode(Sha512::digest(input).as_slice())),
        }
    }
}

/// Run a chain of transforms left-to-right, feeding each one's output into the
/// next. An empty chain returns the input unchanged. The first error stops the
/// pipeline and is returned.
pub fn apply_pipeline(input: &[u8], steps: &[Transform]) -> Result<Vec<u8>, ConvertError> {
    let mut acc = input.to_vec();
    for step in steps {
        acc = step.apply(&acc)?;
    }
    Ok(acc)
}

// ---------------------------------------------------------------------------
// base64 helpers
// ---------------------------------------------------------------------------

/// Decode base64 with the given engine, first dropping ASCII whitespace so
/// line-wrapped / pasted input decodes.
fn b64_decode(engine: &GeneralPurpose, input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    engine
        .decode(cleaned)
        .map_err(|e| ConvertError::Decode(format!("base64: {e}")))
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex encoding (two chars per byte).
fn hex_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX_LOWER[(b >> 4) as usize]);
        out.push(HEX_LOWER[(b & 0x0f) as usize]);
    }
    out
}

/// Decode hex, ignoring ASCII whitespace. Errors on an odd digit count or any
/// non-hex, non-whitespace byte.
fn hex_decode(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let mut nibbles: Vec<u8> = Vec::with_capacity(input.len());
    for &c in input {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => {
                return Err(ConvertError::Decode(format!(
                    "hex: invalid digit 0x{c:02x}"
                )))
            }
        };
        nibbles.push(v);
    }
    if nibbles.len() % 2 != 0 {
        return Err(ConvertError::Decode(
            "hex: odd number of digits".to_string(),
        ));
    }
    Ok(nibbles
        .chunks_exact(2)
        .map(|p| (p[0] << 4) | p[1])
        .collect())
}

// ---------------------------------------------------------------------------
// Percent-encoding (RFC 3986)
// ---------------------------------------------------------------------------

/// RFC 3986 unreserved set: `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode every byte that is not RFC 3986 unreserved (uppercase hex,
/// the RFC's recommended producer form). Spaces become `%20`, not `+`.
fn url_encode(input: &[u8]) -> Vec<u8> {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if is_unreserved(b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX_UPPER[(b >> 4) as usize]);
            out.push(HEX_UPPER[(b & 0x0f) as usize]);
        }
    }
    out
}

/// Decode percent-encoding: `%XX` → byte and `+` → space. Lenient — a `%` not
/// followed by two hex digits is emitted literally (a paste of arbitrary data
/// never errors here).
fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < input.len() => match (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// A single hex digit's value, or `None` if `c` is not `[0-9A-Fa-f]`.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// HTML entities
// ---------------------------------------------------------------------------

/// Entity-encode the five HTML-significant characters (`&`, `<`, `>`, `"`, `'`).
/// Operates byte-wise so arbitrary (incl. non-UTF-8) input round-trips through
/// [`html_decode`]; `'` becomes the numeric `&#39;` (valid in both HTML and XML).
fn html_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&#39;"),
            _ => out.push(b),
        }
    }
    out
}

/// Decode HTML entities: the named `amp`/`lt`/`gt`/`quot`/`apos`, decimal
/// `&#NN;`, and hex `&#xHH;` / `&#XHH;`. Lenient — an `&` that does not open a
/// recognized entity is emitted literally. Numeric references are emitted as
/// UTF-8.
fn html_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'&' {
            if let Some(rel) = input[i + 1..].iter().position(|&c| c == b';') {
                let entity = &input[i + 1..i + 1 + rel];
                if let Some(decoded) = decode_entity(entity) {
                    out.extend_from_slice(&decoded);
                    i += 1 + rel + 1;
                    continue;
                }
            }
            out.push(b'&');
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Decode the content between `&` and `;`. Returns `None` for an unrecognized
/// entity (the caller then keeps the literal `&`).
fn decode_entity(entity: &[u8]) -> Option<Vec<u8>> {
    match entity {
        b"amp" => Some(vec![b'&']),
        b"lt" => Some(vec![b'<']),
        b"gt" => Some(vec![b'>']),
        b"quot" => Some(vec![b'"']),
        b"apos" => Some(vec![b'\'']),
        _ => {
            let rest = entity.strip_prefix(b"#")?;
            if rest.is_empty() {
                return None;
            }
            let code =
                if let Some(hex) = rest.strip_prefix(b"x").or_else(|| rest.strip_prefix(b"X")) {
                    u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?
                } else {
                    std::str::from_utf8(rest).ok()?.parse::<u32>().ok()?
                };
            let ch = char::from_u32(code)?;
            let mut buf = [0u8; 4];
            Some(ch.encode_utf8(&mut buf).as_bytes().to_vec())
        }
    }
}

// ---------------------------------------------------------------------------
// gzip / deflate (flate2)
// ---------------------------------------------------------------------------

fn gzip_compress(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| ConvertError::Decompress(format!("gzip write: {e}")))?;
    encoder
        .finish()
        .map_err(|e| ConvertError::Decompress(format!("gzip finish: {e}")))
}

fn gzip_decompress(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let mut decoder = GzDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| ConvertError::Decompress(format!("gzip: {e}")))?;
    Ok(out)
}

fn deflate_compress(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(input)
        .map_err(|e| ConvertError::Decompress(format!("deflate write: {e}")))?;
    encoder
        .finish()
        .map_err(|e| ConvertError::Decompress(format!("deflate finish: {e}")))
}

fn deflate_decompress(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let mut decoder = DeflateDecoder::new(input);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| ConvertError::Decompress(format!("deflate: {e}")))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// JWT (decode only)
// ---------------------------------------------------------------------------

/// The three decoded parts of a JWT. **Signature is never verified** — this is
/// an inspection aid for the message editor, not an auth check. `header_json`
/// and `payload_json` are the raw UTF-8 JSON text of the first two segments;
/// `signature_b64url` is the third segment left in its base64url form (it is raw
/// bytes, not text).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JwtParts {
    pub header_json: String,
    pub payload_json: String,
    pub signature_b64url: String,
}

/// Split a compact JWS/JWT on `.` and base64url-decode the header and payload to
/// their JSON text. **Does not verify the signature** and makes no claim about
/// the token's validity; it only decodes. Errors if the token does not have
/// exactly three `.`-separated segments, if a segment is not valid base64url, or
/// if the header/payload are not valid UTF-8.
pub fn decode_jwt(token: &str) -> Result<JwtParts, ConvertError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(ConvertError::Decode(format!(
            "jwt: expected 3 dot-separated segments, found {}",
            parts.len()
        )));
    }
    let header = decode_jwt_segment(parts[0], "header")?;
    let payload = decode_jwt_segment(parts[1], "payload")?;
    Ok(JwtParts {
        header_json: header,
        payload_json: payload,
        signature_b64url: parts[2].to_string(),
    })
}

/// base64url-decode one JWT segment to UTF-8 text, labeling errors by segment.
fn decode_jwt_segment(segment: &str, label: &str) -> Result<String, ConvertError> {
    let bytes = B64_URL
        .decode(segment.as_bytes())
        .map_err(|e| ConvertError::Decode(format!("jwt {label}: base64url: {e}")))?;
    String::from_utf8(bytes).map_err(|e| ConvertError::Decode(format!("jwt {label}: utf-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A non-trivial payload that includes every byte `0..=255` exactly once,
    /// used for the round-trip identity checks.
    fn all_bytes() -> Vec<u8> {
        (0u16..=255).map(|b| b as u8).collect()
    }

    #[test]
    fn all_bytes_helper_covers_every_octet() {
        let b = all_bytes();
        assert_eq!(b.len(), 256);
        assert_eq!(b[0], 0);
        assert_eq!(b[255], 255);
    }

    /// For a reversible transform pair, decode(encode(x)) must equal x.
    fn assert_roundtrip(enc: Transform, dec: Transform, input: &[u8]) {
        assert!(enc.is_reversible() && dec.is_reversible());
        let encoded = enc.apply(input).expect("encode");
        let decoded = dec.apply(&encoded).expect("decode");
        assert_eq!(decoded, input, "roundtrip {:?}/{:?}", enc, dec);
    }

    #[test]
    fn base64_roundtrips_all_bytes() {
        assert_roundtrip(
            Transform::Base64Encode,
            Transform::Base64Decode,
            &all_bytes(),
        );
        assert_roundtrip(Transform::Base64Encode, Transform::Base64Decode, b"hello");
    }

    #[test]
    fn base64url_roundtrips_all_bytes() {
        assert_roundtrip(
            Transform::Base64UrlEncode,
            Transform::Base64UrlDecode,
            &all_bytes(),
        );
    }

    #[test]
    fn url_roundtrips_all_bytes() {
        assert_roundtrip(Transform::UrlEncode, Transform::UrlDecode, &all_bytes());
    }

    #[test]
    fn html_roundtrips_all_bytes() {
        assert_roundtrip(Transform::HtmlEncode, Transform::HtmlDecode, &all_bytes());
    }

    #[test]
    fn hex_roundtrips_all_bytes() {
        assert_roundtrip(Transform::HexEncode, Transform::HexDecode, &all_bytes());
    }

    #[test]
    fn gzip_roundtrips_all_bytes() {
        assert_roundtrip(
            Transform::GzipCompress,
            Transform::GzipDecompress,
            &all_bytes(),
        );
        // Also a larger, compressible payload.
        let big = b"ababab".repeat(1000);
        assert_roundtrip(Transform::GzipCompress, Transform::GzipDecompress, &big);
    }

    #[test]
    fn deflate_roundtrips_all_bytes() {
        assert_roundtrip(
            Transform::DeflateCompress,
            Transform::DeflateDecompress,
            &all_bytes(),
        );
    }

    #[test]
    fn base64_known_vector() {
        assert_eq!(
            Transform::Base64Encode.apply(b"hello").unwrap(),
            b"aGVsbG8="
        );
        assert_eq!(
            Transform::Base64Decode.apply(b"aGVsbG8=").unwrap(),
            b"hello"
        );
    }

    #[test]
    fn base64_decode_tolerates_whitespace_and_missing_padding() {
        assert_eq!(
            Transform::Base64Decode.apply(b"aGVs\nbG8=").unwrap(),
            b"hello"
        );
        // Padding-indifferent: unpadded standard input still decodes.
        assert_eq!(Transform::Base64Decode.apply(b"aGVsbG8").unwrap(), b"hello");
    }

    #[test]
    fn base64_decode_rejects_invalid() {
        let err = Transform::Base64Decode
            .apply(b"not valid base64!!")
            .unwrap_err();
        assert!(matches!(err, ConvertError::Decode(_)));
    }

    #[test]
    fn base64url_uses_url_alphabet_without_padding() {
        // 0xff,0xff,0xfe -> standard "///+", url-safe "___-" (no padding).
        let encoded = Transform::Base64UrlEncode
            .apply(&[0xff, 0xff, 0xfe])
            .unwrap();
        assert_eq!(encoded, b"___-");
    }

    #[test]
    fn hashes_are_not_reversible() {
        for t in [
            Transform::Md5,
            Transform::Sha1,
            Transform::Sha256,
            Transform::Sha512,
        ] {
            assert!(!t.is_reversible());
        }
        for t in Transform::all() {
            let is_hash = matches!(
                t,
                Transform::Md5 | Transform::Sha1 | Transform::Sha256 | Transform::Sha512
            );
            assert_eq!(t.is_reversible(), !is_hash);
        }
    }

    #[test]
    fn hash_known_vectors() {
        assert_eq!(
            Transform::Md5.apply(b"").unwrap(),
            b"d41d8cd98f00b204e9800998ecf8427e".to_vec()
        );
        assert_eq!(
            Transform::Sha1.apply(b"abc").unwrap(),
            b"a9993e364706816aba3e25717850c26c9cd0d89d".to_vec()
        );
        assert_eq!(
            Transform::Sha256.apply(b"abc").unwrap(),
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_vec()
        );
        assert_eq!(
            Transform::Sha512.apply(b"abc").unwrap(),
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .to_vec()
        );
    }

    #[test]
    fn url_encode_known_vector() {
        assert_eq!(
            Transform::UrlEncode.apply(b" /?&=").unwrap(),
            b"%20%2F%3F%26%3D".to_vec()
        );
        // Unreserved characters pass through untouched.
        assert_eq!(
            Transform::UrlEncode.apply(b"aZ0-._~").unwrap(),
            b"aZ0-._~".to_vec()
        );
    }

    #[test]
    fn url_decode_handles_percent_plus_and_literal() {
        // %20 -> space, + -> space.
        assert_eq!(Transform::UrlDecode.apply(b"%20+").unwrap(), b"  ".to_vec());
        // Lowercase hex is accepted.
        assert_eq!(Transform::UrlDecode.apply(b"%2f").unwrap(), b"/".to_vec());
        // Malformed percent is left literal (lenient).
        assert_eq!(Transform::UrlDecode.apply(b"a%2").unwrap(), b"a%2".to_vec());
    }

    #[test]
    fn html_encode_known_and_numeric_roundtrip() {
        assert_eq!(
            Transform::HtmlEncode.apply(b"<a href=\"x\">&'").unwrap(),
            b"&lt;a href=&quot;x&quot;&gt;&amp;&#39;".to_vec()
        );
        // Decode of named + numeric (decimal and hex) entities.
        let decoded = Transform::HtmlDecode
            .apply(b"&lt;&#65;&#x42;&apos;&amp;")
            .unwrap();
        assert_eq!(decoded, b"<AB'&".to_vec());
    }

    #[test]
    fn html_decode_lenient_on_bare_ampersand() {
        assert_eq!(
            Transform::HtmlDecode.apply(b"a & b &nope; c").unwrap(),
            b"a & b &nope; c".to_vec()
        );
    }

    #[test]
    fn hex_known_and_errors() {
        assert_eq!(
            Transform::HexEncode.apply(&[0x00, 0x0f, 0xff]).unwrap(),
            b"000fff"
        );
        assert_eq!(
            Transform::HexDecode.apply(b"00 0f\nFF").unwrap(),
            vec![0x00, 0x0f, 0xff]
        );
        assert!(matches!(
            Transform::HexDecode.apply(b"abc").unwrap_err(),
            ConvertError::Decode(_)
        ));
        assert!(matches!(
            Transform::HexDecode.apply(b"zz").unwrap_err(),
            ConvertError::Decode(_)
        ));
    }

    #[test]
    fn gzip_decompress_rejects_garbage() {
        let err = Transform::GzipDecompress.apply(b"not gzip").unwrap_err();
        assert!(matches!(err, ConvertError::Decompress(_)));
    }

    #[test]
    fn name_from_name_roundtrip_for_every_transform() {
        for &t in Transform::all() {
            assert_eq!(Transform::from_name(t.name()), Some(t), "name {}", t.name());
        }
        assert_eq!(Transform::all().len(), 18);
    }

    #[test]
    fn from_name_accepts_aliases_and_rejects_unknown() {
        assert_eq!(
            Transform::from_name("base64-encode"),
            Some(Transform::Base64Encode)
        );
        assert_eq!(
            Transform::from_name("gunzip"),
            Some(Transform::GzipDecompress)
        );
        assert_eq!(
            Transform::from_name("inflate"),
            Some(Transform::DeflateDecompress)
        );
        assert_eq!(
            Transform::from_name("url-encode"),
            Some(Transform::UrlEncode)
        );
        assert_eq!(Transform::from_name("html"), Some(Transform::HtmlEncode));
        assert_eq!(Transform::from_name("nonsense"), None);
    }

    #[test]
    fn pipeline_chains_left_to_right() {
        // text -> base64 -> hex, then back.
        let out = apply_pipeline(b"hi", &[Transform::Base64Encode, Transform::HexEncode]).unwrap();
        assert_eq!(out, Transform::HexEncode.apply(b"aGk=").unwrap());
        let back = apply_pipeline(&out, &[Transform::HexDecode, Transform::Base64Decode]).unwrap();
        assert_eq!(back, b"hi");
    }

    #[test]
    fn empty_pipeline_is_identity() {
        assert_eq!(apply_pipeline(b"abc", &[]).unwrap(), b"abc");
    }

    #[test]
    fn pipeline_propagates_first_error() {
        let err =
            apply_pipeline(b"zz", &[Transform::HexDecode, Transform::Base64Decode]).unwrap_err();
        assert!(matches!(err, ConvertError::Decode(_)));
    }

    #[test]
    fn decode_jwt_sample() {
        // header {"alg":"HS256","typ":"JWT"} . payload {"sub":"1234","name":"Camio"} . sig
        let header = Transform::Base64UrlEncode
            .apply(br#"{"alg":"HS256","typ":"JWT"}"#)
            .unwrap();
        let payload = Transform::Base64UrlEncode
            .apply(br#"{"sub":"1234","name":"Camio"}"#)
            .unwrap();
        let token = format!(
            "{}.{}.{}",
            String::from_utf8(header).unwrap(),
            String::from_utf8(payload).unwrap(),
            "c2lnbmF0dXJl"
        );
        let parts = decode_jwt(&token).unwrap();
        assert_eq!(parts.header_json, r#"{"alg":"HS256","typ":"JWT"}"#);
        assert_eq!(parts.payload_json, r#"{"sub":"1234","name":"Camio"}"#);
        assert_eq!(parts.signature_b64url, "c2lnbmF0dXJl");
    }

    #[test]
    fn decode_jwt_canonical_vector() {
        // A well-known HS256 sample token (RFC 7519-style); signature not verified.
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let parts = decode_jwt(token).unwrap();
        assert_eq!(parts.header_json, r#"{"alg":"HS256","typ":"JWT"}"#);
        assert!(parts.payload_json.contains(r#""name":"John Doe""#));
    }

    #[test]
    fn decode_jwt_rejects_wrong_segment_count() {
        assert!(matches!(
            decode_jwt("onlyonesegment").unwrap_err(),
            ConvertError::Decode(_)
        ));
        assert!(matches!(
            decode_jwt("a.b.c.d").unwrap_err(),
            ConvertError::Decode(_)
        ));
    }

    #[test]
    fn jwt_parts_serde_roundtrips() {
        let parts = JwtParts {
            header_json: r#"{"alg":"HS256","typ":"JWT"}"#.to_string(),
            payload_json: r#"{"sub":"1"}"#.to_string(),
            signature_b64url: "c2ln".to_string(),
        };
        let json = serde_json::to_string(&parts).unwrap();
        let back: JwtParts = serde_json::from_str(&json).unwrap();
        assert_eq!(back, parts);
    }

    #[test]
    fn convert_error_displays_each_variant() {
        assert_eq!(
            ConvertError::Decode("x".into()).to_string(),
            "decode error: x"
        );
        assert_eq!(
            ConvertError::Decompress("y".into()).to_string(),
            "decompress error: y"
        );
        assert_eq!(
            ConvertError::Unsupported("z".into()).to_string(),
            "unsupported transform: z"
        );
        // It is a std::error::Error.
        let e: &dyn std::error::Error = &ConvertError::Decode("x".into());
        assert_eq!(e.to_string(), "decode error: x");
    }
}
