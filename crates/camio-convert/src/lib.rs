//! `camio-convert` — Convert / Decoder / Comparer (plan §8, §7.3).
//!
//! Pure, reusable data transforms and comparisons, with no dependency on any
//! other Camio crate so a step here can run inline in the message editor, as the
//! `camio convert` CLI verb, or as a node inside a Workflow (plan §8, §7.3).
//!
//! * [`convert`] — the [`Transform`] catalog of reversible encodings
//!   (base64 / base64url, percent, HTML entities, hex), gzip/deflate
//!   (de)compression, and one-way hashes (MD5/SHA-1/SHA-256/SHA-512), plus
//!   [`apply_pipeline`] for chaining and [`decode_jwt`] for inspecting a JWT
//!   (decode only — the signature is never verified).
//! * [`compare`] — [`diff_bytes`] for a structural byte summary and
//!   [`diff_lines`] / [`unified_diff`] for an LCS-based line diff.
//!
//! Every fallible operation returns a typed [`ConvertError`]; there are no
//! panics in non-test code. Result types are serde-serializable so they can be
//! saved as evidence or returned over MCP, and no transform reorders or
//! canonicalizes its input.

pub mod compare;
pub mod convert;

pub use compare::{diff_bytes, diff_lines, unified_diff, ByteDiff, LineChange, LineOp};
pub use convert::{apply_pipeline, decode_jwt, ConvertError, JwtParts, Transform};
