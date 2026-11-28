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
// Payload-transform primitives over the operator's own input (hashing a
// payload before sending it) — not password or token hashing. audit-allow: L1
use md5::Md5;
use sha1::Sha1; // audit-allow: L2
use sha2::{Digest, Sha256, Sha384, Sha512};
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
    /// A limited pipeline reached its per-step byte limit.
    Limit(usize),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConvertError::Decode(s) => write!(f, "decode error: {s}"),
            ConvertError::Decompress(s) => write!(f, "decompress error: {s}"),
            ConvertError::Unsupported(s) => write!(f, "unsupported transform: {s}"),
            ConvertError::Limit(bytes) => write!(f, "transform exceeds the {bytes}-byte limit"),
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
    Base32Encode,
    Base32Decode,
    Rot13,
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

/// Every [`Transform`], in catalog order — the backing array for
/// [`Transform::all`] and [`Transform::from_name`].
const ALL: [Transform; 21] = [
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
    Transform::Base32Encode,
    Transform::Base32Decode,
    Transform::Rot13,
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
            Transform::Base32Encode => "base32",
            Transform::Base32Decode => "base32-decode",
            Transform::Rot13 => "rot13",
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
            "base32" | "base32-encode" | "b32" => Transform::Base32Encode,
            "base32-decode" | "b32decode" | "unbase32" => Transform::Base32Decode,
            "rot13" | "rot-13" | "caesar13" => Transform::Rot13,
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
            Transform::Base32Encode => Ok(base32_encode(input)),
            Transform::Base32Decode => base32_decode(input),
            Transform::Rot13 => Ok(rot13(input)),
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

/// Run a pipeline with an input and intermediate output limit, including a
/// streaming limit for gzip and deflate expansion.
pub fn apply_pipeline_limited(
    input: &[u8],
    steps: &[Transform],
    limit: usize,
) -> Result<Vec<u8>, ConvertError> {
    if input.len() > limit {
        return Err(ConvertError::Limit(limit));
    }
    let mut current = input.to_vec();
    for step in steps {
        current = match step {
            Transform::GzipDecompress => {
                inflate(GzDecoder::new(current.as_slice()), "gzip", limit)?
            }
            Transform::DeflateDecompress => {
                inflate(DeflateDecoder::new(current.as_slice()), "deflate", limit)?
            }
            _ => step.apply(&current)?,
        };
        if current.len() > limit {
            return Err(ConvertError::Limit(limit));
        }
    }
    Ok(current)
}

#[cfg(test)]
#[test]
fn bounded_pipeline_limits_expansion_and_accepts_the_exact_boundary() {
    for (pack, unpack) in [
        (Transform::GzipCompress, Transform::GzipDecompress),
        (Transform::DeflateCompress, Transform::DeflateDecompress),
    ] {
        let original = vec![b'x'; 4096];
        let compressed = pack.apply(&original).unwrap();
        assert_eq!(
            apply_pipeline_limited(&compressed, &[unpack], 2048),
            Err(ConvertError::Limit(2048))
        );
        assert_eq!(
            apply_pipeline_limited(&compressed, &[unpack], 4096).unwrap(),
            original
        );
    }
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

/// RFC 4648 base32 alphabet (upper-case, no lower-case).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 encode with `=` padding. Common for TOTP secrets, DNS
/// exfiltration and some tokens, so it belongs in the decoder/encoder (F17).
fn base32_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(5) * 8);
    for chunk in input.chunks(5) {
        // Pack up to 5 bytes into a 40-bit buffer, MSB first.
        let mut buf = 0u64;
        for (i, &b) in chunk.iter().enumerate() {
            buf |= (b as u64) << (32 - i * 8);
        }
        // Each chunk of n bytes yields a fixed number of base32 symbols.
        let symbols = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for i in 0..8 {
            if i < symbols {
                let idx = ((buf >> (35 - i * 5)) & 0x1f) as usize;
                out.push(BASE32_ALPHABET[idx]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

/// RFC 4648 base32 decode: ignores whitespace and padding, accepts upper or
/// lower case.
fn base32_decode(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    let mut bits = 0u64;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 1);
    for &c in input {
        if c.is_ascii_whitespace() || c == b'=' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let val = match up {
            b'A'..=b'Z' => up - b'A',
            b'2'..=b'7' => up - b'2' + 26,
            _ => {
                return Err(ConvertError::Decode(format!(
                    "base32: invalid digit 0x{c:02x}"
                )))
            }
        };
        bits = (bits << 5) | val as u64;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Ok(out)
}

/// ROT13: rotate ASCII letters by 13 (symmetric; its own inverse). Non-letters
/// pass through unchanged.
fn rot13(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .map(|&c| match c {
            b'a'..=b'z' => b'a' + (c - b'a' + 13) % 26,
            b'A'..=b'Z' => b'A' + (c - b'A' + 13) % 26,
            other => other,
        })
        .collect()
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

/// Default decompression cap for the streaming (unbounded) transform path, so a
/// gzip/deflate bomb cannot exhaust memory (plan §12: protect against
/// decompression-heavy inputs).
const DEFAULT_DECOMPRESS_LIMIT: usize = 32 * 1024 * 1024;

fn gzip_decompress(input: &[u8]) -> Result<Vec<u8>, ConvertError> {
    inflate(GzDecoder::new(input), "gzip", DEFAULT_DECOMPRESS_LIMIT)
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
    inflate(
        DeflateDecoder::new(input),
        "deflate",
        DEFAULT_DECOMPRESS_LIMIT,
    )
}

fn inflate(decoder: impl Read, name: &str, limit: usize) -> Result<Vec<u8>, ConvertError> {
    let mut out = Vec::new();
    decoder
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| ConvertError::Decompress(format!("{name}: {e}")))?;
    if out.len() > limit {
        return Err(ConvertError::Limit(limit));
    }
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

// ---------------------------------------------------------------------------
// JWT security analysis (inspired by jwt_tool / the Burp JWT extensions)
// ---------------------------------------------------------------------------

/// Severity of a JWT weakness, mirroring the finding severities elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtSeverity {
    Critical,
    High,
    Medium,
    Info,
}

/// One weakness found in a JWT.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JwtIssue {
    pub severity: JwtSeverity,
    pub title: String,
    pub detail: String,
}

/// The result of analysing a JWT for common weaknesses. Decoding never verifies
/// a real signature; the only verification performed is the **offline HMAC
/// secret-guessing** against the supplied wordlist (so a hit means the token is
/// forgeable with that secret).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JwtAnalysis {
    pub header_json: String,
    pub payload_json: String,
    /// The `alg` header value, lowercased (e.g. `"hs256"`, `"none"`, `"rs256"`).
    pub alg: String,
    pub issues: Vec<JwtIssue>,
    /// The HMAC secret from the wordlist that verified the signature, if any.
    /// Its presence is itself a Critical issue (the token is forgeable).
    pub cracked_secret: Option<String>,
}

/// A short built-in wordlist of the HMAC secrets that turn up most often in real
/// JWT deployments (dev defaults, framework examples, trivial passwords). Used
/// when the caller supplies no wordlist of its own.
pub const COMMON_JWT_SECRETS: &[&str] = &[
    "secret",
    "secretkey",
    "your-256-bit-secret",
    "your_jwt_secret",
    "jwt_secret",
    "jwtsecret",
    "changeme",
    "password",
    "123456",
    "admin",
    "key",
    "private",
    "test",
    "supersecret",
    "s3cr3t",
    "qwerty",
    "secret123",
    "mysecret",
    "token",
    "default",
];

/// Analyse `token` for common JWT weaknesses: the `alg:none` signature bypass,
/// a weak/guessable HMAC secret (tried against `wordlist`, or
/// [`COMMON_JWT_SECRETS`] when `wordlist` is empty), and claim-hygiene problems
/// (missing/expired `exp`, a future `nbf`). `now_unix` is the current time for
/// the claim checks; pass `None` to read the system clock.
///
/// Sends nothing. The HMAC guessing is a bounded, offline loop over the
/// wordlist. Intended for **authorized** testing of tokens you are permitted to
/// assess.
pub fn analyze_jwt(
    token: &str,
    wordlist: &[String],
    now_unix: Option<u64>,
) -> Result<JwtAnalysis, ConvertError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(ConvertError::Decode(format!(
            "jwt: expected 3 dot-separated segments, found {}",
            parts.len()
        )));
    }
    let decoded = decode_jwt(token)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_segment = parts[2];

    let header: serde_json::Value =
        serde_json::from_str(&decoded.header_json).unwrap_or(serde_json::Value::Null);
    let payload: serde_json::Value =
        serde_json::from_str(&decoded.payload_json).unwrap_or(serde_json::Value::Null);

    let alg = header
        .get("alg")
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut issues: Vec<JwtIssue> = Vec::new();
    let mut cracked_secret: Option<String> = None;

    // --- alg:none — signature bypass -------------------------------------
    if alg == "none" {
        issues.push(JwtIssue {
            severity: JwtSeverity::Critical,
            title: "Algorithm 'none' accepted in header".to_string(),
            detail: "The token's header declares `alg: none`. If the server honours it, the signature is not verified at all — an attacker can forge any payload (e.g. elevate to admin) by setting `alg:none` and sending an empty signature. Confirm the server rejects it.".to_string(),
        });
    }

    // --- Empty signature with a real alg ---------------------------------
    if sig_segment.is_empty() && alg != "none" && !alg.is_empty() {
        issues.push(JwtIssue {
            severity: JwtSeverity::High,
            title: "Empty signature".to_string(),
            detail: format!("The token declares `alg: {alg}` but carries no signature. A server that accepts it is not verifying signatures."),
        });
    }

    // --- Weak HMAC secret (offline guess) --------------------------------
    if alg.starts_with("hs") && !sig_segment.is_empty() {
        let list_owned: Vec<String>;
        let list: &[String] = if wordlist.is_empty() {
            list_owned = COMMON_JWT_SECRETS.iter().map(|s| s.to_string()).collect();
            &list_owned
        } else {
            wordlist
        };
        if let Some(hit) = crack_hmac(&alg, signing_input.as_bytes(), sig_segment, list) {
            issues.push(JwtIssue {
                severity: JwtSeverity::Critical,
                title: "Weak HMAC signing secret".to_string(),
                detail: format!("The `{alg}` signature verifies against the guessable secret `{hit}`. The token is fully forgeable — anyone with this secret can mint valid tokens with any claims."),
            });
            cracked_secret = Some(hit);
        }
    }

    // --- Claim hygiene ----------------------------------------------------
    let now = now_unix.unwrap_or_else(now_unix_secs);
    match payload.get("exp").and_then(json_as_u64) {
        None => issues.push(JwtIssue {
            severity: JwtSeverity::Medium,
            title: "No expiry claim (exp)".to_string(),
            detail: "The token has no `exp` claim, so it never expires. A leaked token stays valid indefinitely.".to_string(),
        }),
        Some(exp) if exp < now => issues.push(JwtIssue {
            severity: JwtSeverity::Info,
            title: "Token is expired".to_string(),
            detail: format!("The `exp` claim ({exp}) is in the past (now {now}). This token should already be rejected."),
        }),
        _ => {}
    }
    if let Some(nbf) = payload.get("nbf").and_then(json_as_u64) {
        if nbf > now {
            issues.push(JwtIssue {
                severity: JwtSeverity::Info,
                title: "Token not yet valid (nbf in the future)".to_string(),
                detail: format!("The `nbf` claim ({nbf}) is after now ({now})."),
            });
        }
    }

    Ok(JwtAnalysis {
        header_json: decoded.header_json,
        payload_json: decoded.payload_json,
        alg,
        issues,
        cracked_secret,
    })
}

/// Current UNIX time in seconds (best-effort; 0 before the epoch).
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read a JSON number as `u64` whether it is encoded as an integer or (as some
/// libraries emit timestamps) a float.
fn json_as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_f64().map(|f| f as u64))
}

/// Try each secret in `wordlist` against the HMAC signature; return the first
/// that verifies. `alg` is one of `hs256`/`hs384`/`hs512`.
fn crack_hmac(alg: &str, signing_input: &[u8], sig_b64url: &str, wordlist: &[String]) -> Option<String> {
    let want = B64_URL.decode(sig_b64url.as_bytes()).ok()?;
    for secret in wordlist {
        let got = match alg {
            "hs256" => hmac(Sha256::new(), 64, secret.as_bytes(), signing_input),
            "hs384" => hmac(Sha384::new(), 128, secret.as_bytes(), signing_input),
            "hs512" => hmac(Sha512::new(), 128, secret.as_bytes(), signing_input),
            _ => return None,
        };
        if constant_time_eq(&got, &want) {
            return Some(secret.clone());
        }
    }
    None
}

/// Generic HMAC over any `sha2` digest. `block` is the hash's block size in
/// bytes (64 for SHA-256, 128 for SHA-384/512). Implemented here rather than
/// pulling the `hmac` crate because it is a handful of lines and keeps the
/// dependency surface small (the same choice `camio-core::ai_guard` made).
fn hmac<D>(mut inner: D, block: usize, key: &[u8], msg: &[u8]) -> Vec<u8>
where
    D: Digest + Clone + sha2::digest::FixedOutputReset,
{
    // Key shortening: a key longer than the block is replaced by its hash.
    let mut key_block = vec![0u8; block];
    if key.len() > block {
        let mut h = inner.clone();
        Digest::update(&mut h, key);
        let hashed = h.finalize_reset().to_vec();
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut i_pad = key_block.clone();
    let mut o_pad = key_block;
    for b in i_pad.iter_mut() {
        *b ^= 0x36;
    }
    for b in o_pad.iter_mut() {
        *b ^= 0x5c;
    }
    // inner = H(i_pad || msg)
    Digest::update(&mut inner, &i_pad);
    Digest::update(&mut inner, msg);
    let inner_digest = inner.finalize_reset();
    // outer = H(o_pad || inner)
    Digest::update(&mut inner, &o_pad);
    Digest::update(&mut inner, &inner_digest);
    inner.finalize().to_vec()
}

/// Length-independent constant-time byte comparison (prevents a timing side
/// channel in the signature check — academic for an offline tool, but correct).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Favicon hash (Shodan `http.favicon.hash` / favfreak) — asset correlation
// ---------------------------------------------------------------------------

/// Compute the **Shodan favicon hash** of a favicon's bytes: the value you can
/// pivot on in Shodan (`http.favicon.hash:<N>`), Censys or FOFA to find every
/// host serving the same favicon — a fast way to map an organisation's other
/// assets, shadow IT, and origin servers hiding behind a CDN.
///
/// The algorithm must match Shodan exactly: standard-base64 the bytes **the way
/// Python's `base64.encodebytes` does** (76-char lines, each terminated by
/// `\n`), then take the signed 32-bit MurmurHash3 (x86, seed 0) of that text.
/// Returns the signed `i32` Shodan reports.
pub fn favicon_hash(favicon: &[u8]) -> i32 {
    let b64 = B64_STD.encode(favicon);
    // Emulate Python's base64.encodebytes: wrap at 76 chars, newline per line.
    let mut lined = String::with_capacity(b64.len() + b64.len() / 76 + 1);
    let bytes = b64.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let end = (i + 76).min(bytes.len());
        lined.push_str(&b64[i..end]);
        lined.push('\n');
        i = end;
    }
    murmur3_x86_32(lined.as_bytes(), 0) as i32
}

/// [`favicon_hash`] for a standard-base64-encoded favicon — the convenient form
/// for callers (e.g. the MCP server) that carry the bytes as base64 text.
pub fn favicon_hash_base64(b64: &str) -> Result<i32, ConvertError> {
    let bytes = B64_STD
        .decode(b64.trim().as_bytes())
        .map_err(|e| ConvertError::Decode(format!("favicon base64: {e}")))?;
    Ok(favicon_hash(&bytes))
}

/// MurmurHash3 x86 32-bit (the variant Shodan/mmh3 uses).
fn murmur3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h = seed;
    let nblocks = data.len() / 4;
    for i in 0..nblocks {
        let o = i * 4;
        let mut k = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        k = k.wrapping_mul(C1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    // Tail.
    let tail = &data[nblocks * 4..];
    let mut k1 = 0u32;
    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h ^= k1;
    }
    // Finalization mix.
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
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
        assert_eq!(Transform::all().len(), 21);
    }

    #[test]
    fn base32_round_trips_rfc4648_vectors() {
        // RFC 4648 §10 test vectors.
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ] {
            let out = Transform::Base32Encode.apply(plain.as_bytes()).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), encoded, "encode {plain}");
            let back = Transform::Base32Decode.apply(encoded.as_bytes()).unwrap();
            assert_eq!(String::from_utf8(back).unwrap(), plain, "decode {encoded}");
        }
    }

    #[test]
    fn base32_decode_rejects_invalid() {
        assert!(Transform::Base32Decode.apply(b"MZXW6!!!").is_err());
    }

    #[test]
    fn rot13_is_its_own_inverse() {
        let plain = b"Hello, Camio 123!";
        let once = Transform::Rot13.apply(plain).unwrap();
        assert_eq!(&once, b"Uryyb, Pnzvb 123!");
        let twice = Transform::Rot13.apply(&once).unwrap();
        assert_eq!(&twice, plain);
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

    // ---- JWT security analysis ----

    #[test]
    fn analyze_jwt_cracks_the_canonical_jwt_io_secret() {
        // The jwt.io sample HS256 token is signed with "your-256-bit-secret"
        // (which is in COMMON_JWT_SECRETS). A successful crack also proves the
        // HMAC-SHA256 implementation matches the reference signature.
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let a = analyze_jwt(token, &[], Some(1_516_239_999)).unwrap();
        assert_eq!(a.alg, "hs256");
        assert_eq!(a.cracked_secret.as_deref(), Some("your-256-bit-secret"));
        assert!(a
            .issues
            .iter()
            .any(|i| i.severity == JwtSeverity::Critical && i.title.contains("Weak HMAC")));
    }

    #[test]
    fn analyze_jwt_wrong_secret_does_not_crack() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        // A wordlist without the real secret must not produce a false crack.
        let a = analyze_jwt(token, &["nope".to_string(), "wrong".to_string()], Some(0)).unwrap();
        assert_eq!(a.cracked_secret, None);
    }

    #[test]
    fn analyze_jwt_flags_alg_none() {
        let header = B64_URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = B64_URL.encode(br#"{"sub":"admin","exp":9999999999}"#);
        let token = format!("{header}.{payload}.");
        let a = analyze_jwt(&token, &[], Some(0)).unwrap();
        assert_eq!(a.alg, "none");
        assert!(a
            .issues
            .iter()
            .any(|i| i.severity == JwtSeverity::Critical && i.title.contains("'none'")));
    }

    #[test]
    fn analyze_jwt_flags_missing_and_expired_exp() {
        // No exp → Medium.
        let header = B64_URL.encode(br#"{"alg":"HS256"}"#);
        let payload = B64_URL.encode(br#"{"sub":"x"}"#);
        let token = format!("{header}.{payload}.c2ln");
        let a = analyze_jwt(&token, &["none".to_string()], Some(1000)).unwrap();
        assert!(a.issues.iter().any(|i| i.title.contains("No expiry")));

        // Expired exp → Info.
        let payload2 = B64_URL.encode(br#"{"sub":"x","exp":500}"#);
        let token2 = format!("{header}.{payload2}.c2ln");
        let a2 = analyze_jwt(&token2, &["none".to_string()], Some(1000)).unwrap();
        assert!(a2.issues.iter().any(|i| i.title.contains("expired")));
    }

    // ---- Favicon hash (Shodan) ----

    #[test]
    fn murmur3_empty_is_zero() {
        assert_eq!(murmur3_x86_32(b"", 0), 0);
    }

    #[test]
    fn favicon_hash_empty_is_zero_and_deterministic() {
        // base64.encodebytes(b"") == b"" so mmh3("") == 0, matching Shodan.
        assert_eq!(favicon_hash(&[]), 0);
        let data = b"\x89PNG\r\n\x1a\n some favicon bytes here";
        assert_eq!(favicon_hash(data), favicon_hash(data));
    }

    #[test]
    fn favicon_hash_wraps_76_char_lines_like_python() {
        // 60 bytes → 80 base64 chars → two lines (76 + 4) each with a trailing
        // newline, exactly as Python's base64.encodebytes produces. We assert
        // the hash is stable and non-zero for a realistic-length input (the
        // line-wrapping path is exercised).
        let data = vec![0x41u8; 60];
        let h = favicon_hash(&data);
        assert_ne!(h, 0);
        assert_eq!(h, favicon_hash(&data));
    }
}
