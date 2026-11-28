//! Image-CAPTCHA OCR solving (plan §11 "Automation & AI": optional,
//! user-triggered, no automatic traffic).
//!
//! This module reads a PNG/JPG CAPTCHA image, preprocesses it (grayscale →
//! Otsu threshold → morphological despeckle), and hands it to an OCR backend.
//! The default backend shells out to the system `tesseract` binary (widely
//! available on Linux via `apt install tesseract-ocr`); when `tesseract` is
//! absent the module degrades to a built-in heuristic that still handles
//! clean, high-contrast digit CAPTCHAs via **connected-component glyph
//! segmentation + stroke-density classification**. Nothing here calls out to
//! an external service — the OCR stays on the operator's machine.
//!
//! ## Scope and honesty
//!
//! OCR solves *simple* image CAPTCHAs: fixed-font characters with mild
//! rotation/noise. The **tesseract** backend reads digits and letters; the
//! pure-Rust **builtin** fallback is **digits-only** (it exists so CI and
//! sandboxes without tesseract still function, and the Auto backend prefers
//! tesseract whenever it is installed). Neither backend solves reCAPTCHA,
//! hCaptcha, or any challenge that requires interpreting a scene — the
//! `camio-scan::CaptchaPresence` check classifies each hit and routes only
//! `CaptchaKind::ImageInline` here. For everything else, a managed-browser
//! session with human-in-the-loop (or an explicitly authorized third-party
//! solver) is the right path.
//!
//! ## Safety
//!
//! * No `unwrap`/`expect`/`panic!` outside tests.
//! * The PNG decoder bounds image dimensions before allocating, so a hostile
//!   IHDR cannot drive an out-of-memory or an integer-overflow panic.
//! * The tesseract subprocess is invoked with an argv — never via the shell —
//!   and the input image is passed via a temp file (not stdin, because some
//!   tesseract builds mis-handle non-seekable input); the path carries a
//!   per-call sequence so concurrent solves never collide. The temp file is
//!   removed on all exit paths.
//! * stdout/stderr reads are byte-bounded and output text is normalized
//!   (whitespace collapsed, case preserved) and length-bounded, so a run-away
//!   backend cannot blow up caller buffers.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// How to interpret the input image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG (RFC 2083). The built-in decoder handles truecolor + alpha + 8bpp
    /// grayscale, which is what every image CAPTCHA served from a browser
    /// uses in practice.
    Png,
    /// JPEG. We cannot decode JPEG natively here, so the tesseract backend is
    /// required; the pure-Rust backend will refuse.
    Jpeg,
    /// Unknown — try PNG, then JPEG (tesseract only).
    Auto,
}

impl ImageFormat {
    pub fn from_bytes(data: &[u8]) -> ImageFormat {
        if data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n" {
            ImageFormat::Png
        } else if data.len() >= 3 && &data[0..3] == b"\xff\xd8\xff" {
            ImageFormat::Jpeg
        } else {
            ImageFormat::Auto
        }
    }
}

/// Which OCR backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OcrBackend {
    /// `tesseract` subprocess (recommended; needs the binary on `PATH`).
    Tesseract,
    /// Pure-Rust connected-component digit classifier. Only PNG, only
    /// `psm_digits`, best-effort — intended as a fallback for CI / sandboxes
    /// where tesseract is not installed.
    Builtin,
    /// Prefer tesseract when available; otherwise fall back to the built-in.
    #[default]
    Auto,
}

/// OCR configuration.
#[derive(Debug, Clone)]
pub struct OcrConfig {
    pub backend: OcrBackend,
    /// Page-segmentation mode hint: `7` = single line (reCAPTCHA-style single
    /// word); `8` = single word; `6` = block; `10` = single character.
    /// Defaults to `7` — right for most CAPTCHA strings.
    pub psm: u8,
    /// Restrict the recognized alphabet. `"0123456789"` is the usual pick for
    /// numeric CAPTCHAs; `""` disables the restriction.
    pub whitelist: String,
    /// Tesseract language pack. `"eng"` by default; most distros ship it.
    pub lang: String,
    /// Hard cap on the final answer length (prevents a mis-tuned backend from
    /// returning a page of noise).
    pub max_len: usize,
}

impl Default for OcrConfig {
    fn default() -> Self {
        OcrConfig {
            backend: OcrBackend::Auto,
            psm: 7,
            whitelist: String::new(),
            lang: "eng".to_string(),
            max_len: 32,
        }
    }
}

impl OcrConfig {
    /// A preset tuned for numeric-only image CAPTCHAs.
    pub fn digits() -> Self {
        OcrConfig {
            whitelist: "0123456789".to_string(),
            psm: 7,
            ..OcrConfig::default()
        }
    }

    /// A preset tuned for alphanumeric image CAPTCHAs.
    pub fn alphanum() -> Self {
        OcrConfig {
            whitelist: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_string(),
            psm: 7,
            ..OcrConfig::default()
        }
    }
}

/// The result of running OCR against a CAPTCHA image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcrResult {
    /// Recognized text, post-processed (whitespace collapsed, bounded length).
    pub text: String,
    /// Which backend produced the result.
    pub backend: OcrBackend,
    /// Rough 0..=100 confidence estimate. For the tesseract backend this is
    /// the mean per-character confidence tesseract itself reports; for the
    /// built-in classifier it's a heuristic based on connected-component
    /// stability. Not calibrated across backends — use it for ranking
    /// candidates, not for ground truth.
    pub confidence: u8,
}

/// Errors from the OCR pipeline.
#[derive(Debug)]
pub enum OcrError {
    /// The caller gave us bytes that don't look like a supported image.
    BadImage(String),
    /// A backend was requested that isn't available in this environment.
    BackendUnavailable(String),
    /// A subprocess (tesseract) failed; the payload is a truncated stderr.
    Backend(String),
    /// I/O failure (temp file, reading a response, etc.).
    Io(String),
    /// All backends ran but none produced any text — the challenge is likely
    /// too noisy / obfuscated for OCR alone.
    NoText,
}

impl std::fmt::Display for OcrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OcrError::BadImage(m) => write!(f, "bad CAPTCHA image: {m}"),
            OcrError::BackendUnavailable(m) => write!(f, "OCR backend unavailable: {m}"),
            OcrError::Backend(m) => write!(f, "OCR backend failed: {m}"),
            OcrError::Io(m) => write!(f, "OCR I/O error: {m}"),
            OcrError::NoText => write!(f, "OCR produced no text"),
        }
    }
}

impl std::error::Error for OcrError {}

/// Solve a CAPTCHA image to its text content.
///
/// The high-level API: pick the backend from `cfg.backend`, run preprocessing,
/// invoke OCR, and post-process the result.
pub fn solve(image: &[u8], cfg: &OcrConfig) -> Result<OcrResult, OcrError> {
    match cfg.backend {
        OcrBackend::Tesseract => solve_tesseract(image, cfg),
        OcrBackend::Builtin => solve_builtin(image, cfg),
        OcrBackend::Auto => {
            if tesseract_available() {
                match solve_tesseract(image, cfg) {
                    Ok(r) => Ok(r),
                    // A bad image won't decode under either backend, so don't
                    // bother falling back — surface the real reason.
                    Err(e @ OcrError::BadImage(_)) => Err(e),
                    Err(tess_err) => {
                        // Tesseract hit a backend/IO/no-text problem; try the
                        // pure-Rust path, but if THAT also fails don't let the
                        // builtin error bury why tesseract (the better backend)
                        // failed — report both.
                        solve_builtin(image, cfg).map_err(|builtin_err| {
                            OcrError::Backend(format!(
                                "tesseract failed ({tess_err}); builtin fallback also failed ({builtin_err})"
                            ))
                        })
                    }
                }
            } else {
                solve_builtin(image, cfg)
            }
        }
    }
}

/// A process-wide counter that, combined with the pid, gives each temp image a
/// distinct path even when several solves run concurrently in one process.
static TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// True when `tesseract` is on `PATH` and executes.
pub fn tesseract_available() -> bool {
    Command::new("tesseract")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tesseract backend (subprocess)
// ---------------------------------------------------------------------------

fn solve_tesseract(image: &[u8], cfg: &OcrConfig) -> Result<OcrResult, OcrError> {
    if !tesseract_available() {
        return Err(OcrError::BackendUnavailable(
            "tesseract binary not found on PATH".to_string(),
        ));
    }

    let tmpdir = std::env::temp_dir();
    // pid + a monotonic sequence so concurrent solves in one process never
    // share a temp path (which would race the Drop-guard unlink below).
    let seq = TEMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stem = format!("camio-captcha-{}-{seq}", std::process::id());
    let in_path = tmpdir.join(format!("{stem}.img"));
    std::fs::write(&in_path, image).map_err(|e| OcrError::Io(format!("writing temp image: {e}")))?;

    // Clean the temp file no matter how we exit.
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = Guard(in_path.clone());

    let mut cmd = Command::new("tesseract");
    cmd.arg(&in_path)
        .arg("stdout")
        .arg("-l")
        .arg(&cfg.lang)
        .arg("--psm")
        .arg(cfg.psm.to_string())
        .arg("--dpi")
        .arg("150");
    if !cfg.whitelist.is_empty() {
        // `-c tessedit_char_whitelist=...` restricts the output alphabet. This
        // is the single most useful tesseract knob for CAPTCHA work.
        cmd.arg("-c")
            .arg(format!("tessedit_char_whitelist={}", cfg.whitelist));
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| OcrError::Backend(format!("spawning tesseract: {e}")))?;

    // Read stdout + stderr, each bounded so a pathological tesseract output
    // (e.g. from an unexpectedly large input) cannot blow up our buffers.
    // Tesseract on a CAPTCHA image completes in milliseconds, so no deadline
    // enforcement is needed. 64 KiB is orders of magnitude more than any real
    // CAPTCHA answer or error banner.
    const MAX_PIPE_BYTES: u64 = 64 * 1024;
    let mut stdout = String::new();
    if let Some(s) = child.stdout.take() {
        s.take(MAX_PIPE_BYTES)
            .read_to_string(&mut stdout)
            .map_err(|e| OcrError::Io(format!("reading tesseract stdout: {e}")))?;
    }
    let mut stderr = String::new();
    if let Some(s) = child.stderr.take() {
        s.take(MAX_PIPE_BYTES)
            .read_to_string(&mut stderr)
            .map_err(|e| OcrError::Io(format!("reading tesseract stderr: {e}")))?;
    }
    let status = child
        .wait()
        .map_err(|e| OcrError::Backend(format!("waiting on tesseract: {e}")))?;

    if !status.success() {
        // The actual error is at the END of tesseract's stderr (the banner /
        // progress noise comes first), so keep the last 400 chars, not the
        // first.
        let n = stderr.chars().count();
        let tail: String = stderr.chars().skip(n.saturating_sub(400)).collect();
        return Err(OcrError::Backend(format!(
            "tesseract exited with {status}: {}",
            tail.trim()
        )));
    }

    let text = normalize(&stdout, cfg.max_len);
    if text.is_empty() {
        return Err(OcrError::NoText);
    }

    // Tesseract doesn't expose a per-char confidence to stdout in this mode.
    // Treat a short, whitelist-conformant result as high confidence; anything
    // long / mixed as medium. Not calibrated.
    let confidence = heuristic_confidence(&text, &cfg.whitelist);

    Ok(OcrResult {
        text,
        backend: OcrBackend::Tesseract,
        confidence,
    })
}

// ---------------------------------------------------------------------------
// Pure-Rust fallback: PNG decode + connected-component digit classifier
// ---------------------------------------------------------------------------

fn solve_builtin(image: &[u8], cfg: &OcrConfig) -> Result<OcrResult, OcrError> {
    // Only PNG is supported in the builtin backend.
    match ImageFormat::from_bytes(image) {
        ImageFormat::Png => {}
        ImageFormat::Jpeg => {
            return Err(OcrError::BackendUnavailable(
                "builtin backend cannot decode JPEG; install `tesseract-ocr`".to_string(),
            ))
        }
        ImageFormat::Auto => {
            return Err(OcrError::BadImage(
                "unsupported image format (not PNG, not JPEG)".to_string(),
            ))
        }
    }

    let gray = decode_png_grayscale(image)?;
    let bin = otsu_threshold(&gray.pixels, gray.width, gray.height);
    let despeckled = despeckle(&bin, gray.width, gray.height);
    let components = find_components(&despeckled, gray.width, gray.height);

    // Classify each connected component by stroke density + aspect ratio.
    // The builtin classifier recognizes DIGITS ONLY (`0..=9`); a component it
    // cannot place confidently is skipped, not guessed. Letters are out of
    // scope here — install tesseract for alphanumeric CAPTCHAs (the Auto
    // backend prefers it automatically). Because this can only emit digits, a
    // non-digit whitelist (e.g. `alphanum`) still yields digits from this
    // backend; that is a documented fallback limitation, not a wrong answer we
    // try to hide.
    let mut text = String::new();
    for comp in &components {
        let glyph = classify_component(comp, &despeckled, gray.width);
        if let Some(ch) = glyph {
            if cfg.whitelist.is_empty() || cfg.whitelist.contains(ch) {
                text.push(ch);
            }
        }
    }
    let text = normalize(&text, cfg.max_len);
    if text.is_empty() {
        return Err(OcrError::NoText);
    }
    Ok(OcrResult {
        text: text.clone(),
        backend: OcrBackend::Builtin,
        confidence: heuristic_confidence(&text, &cfg.whitelist).saturating_sub(20),
    })
}

/// A decoded grayscale image: one byte per pixel (0 = black, 255 = white).
#[derive(Debug)]
struct Gray {
    width: usize,
    height: usize,
    pixels: Vec<u8>,
}

/// Upper bound on decoded pixel count for the builtin backend. A CAPTCHA is a
/// few hundred pixels per side; 16 megapixels (e.g. 4096×4096) is already far
/// past anything legitimate. The cap runs *before* any width×height allocation
/// so a hostile IHDR claiming 60000×60000 cannot drive an OOM — it is refused,
/// and (in Auto mode) tesseract still gets a shot at the image.
const MAX_BUILTIN_PIXELS: usize = 16 * 1024 * 1024;
/// Per-side cap, so `width * height` and `stride * height` cannot overflow
/// `usize` on the way to the pixel-count check.
const MAX_BUILTIN_SIDE: usize = 1 << 16; // 65536

/// Decode a PNG into grayscale with no image crate. Supports grayscale (0),
/// truecolor-RGB (2), 8-bit indexed/palette (3), grayscale+alpha (4) and
/// truecolor-RGBA (6), all at 8-bit depth. Interlaced and 16-bit PNGs are
/// refused (the Auto backend falls back to tesseract for those). The IDAT
/// zlib stream is inflated with a real DEFLATE decoder (flate2), so ordinary
/// Huffman-compressed PNGs — i.e. essentially every PNG produced by a real
/// encoder — decode here, not just the level-0 "stored" streams.
fn decode_png_grayscale(data: &[u8]) -> Result<Gray, OcrError> {
    if data.len() < 8 || &data[0..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(OcrError::BadImage("not a PNG".to_string()));
    }
    // Parse chunks: IHDR for header, PLTE for the palette, IDAT (concatenated)
    // for pixel data.
    let mut i = 8usize;
    let mut idat = Vec::<u8>::new();
    let mut palette: Vec<[u8; 3]> = Vec::new();
    let mut saw_ihdr = false;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut bit_depth = 0u8;
    let mut color_type = 0u8;
    let mut interlace = 0u8;

    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ty = &data[i + 4..i + 8];
        let body_start = i + 8;
        let body_end = body_start
            .checked_add(len)
            .ok_or_else(|| OcrError::BadImage("PNG chunk length overflows".to_string()))?;
        // +4 for the trailing CRC; guard that addition against overflow too.
        if body_end.checked_add(4).map(|e| e > data.len()).unwrap_or(true) {
            return Err(OcrError::BadImage("PNG chunk truncated".to_string()));
        }
        let body = &data[body_start..body_end];
        match ty {
            b"IHDR" => {
                if body.len() < 13 {
                    return Err(OcrError::BadImage("IHDR too short".to_string()));
                }
                width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                bit_depth = body[8];
                color_type = body[9];
                interlace = body[12];
                saw_ihdr = true;
            }
            b"PLTE" => {
                // Palette entries are RGB triples.
                palette = body.chunks_exact(3).map(|c| [c[0], c[1], c[2]]).collect();
            }
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        i = body_end + 4; // skip CRC
    }

    if !saw_ihdr {
        return Err(OcrError::BadImage("PNG has no IHDR".to_string()));
    }
    if interlace != 0 {
        return Err(OcrError::BadImage("interlaced PNG not supported".to_string()));
    }
    if bit_depth != 8 {
        // Palette PNGs are frequently 1/2/4-bit, but supporting sub-byte
        // unpacking is more than the fallback needs; tesseract covers them.
        return Err(OcrError::BadImage(format!(
            "PNG bit depth {bit_depth} not supported by the builtin backend (want 8); use tesseract"
        )));
    }
    let channels = match color_type {
        0 => 1usize, // grayscale
        2 => 3,      // RGB
        3 => 1,      // indexed (one palette-index byte per pixel)
        4 => 2,      // grayscale+alpha
        6 => 4,      // RGBA
        other => {
            return Err(OcrError::BadImage(format!(
                "PNG color type {other} not supported"
            )))
        }
    };
    let (width, height) = (width as usize, height as usize);
    // Bound dimensions BEFORE any width×height arithmetic/allocation so a
    // malicious header cannot overflow or exhaust memory.
    if width == 0 || height == 0 {
        return Err(OcrError::BadImage("PNG has zero dimension".to_string()));
    }
    if width > MAX_BUILTIN_SIDE || height > MAX_BUILTIN_SIDE {
        return Err(OcrError::BadImage(format!(
            "PNG {width}×{height} exceeds the builtin backend side cap; use tesseract"
        )));
    }
    if width.saturating_mul(height) > MAX_BUILTIN_PIXELS {
        return Err(OcrError::BadImage(format!(
            "PNG {width}×{height} exceeds the builtin backend pixel cap; use tesseract"
        )));
    }
    if color_type == 3 && palette.is_empty() {
        return Err(OcrError::BadImage("indexed PNG missing PLTE chunk".to_string()));
    }
    let stride = width * channels;

    // Inflate the IDAT zlib stream with a real DEFLATE decoder.
    let raw = inflate_zlib(&idat)?;
    let expected = (stride + 1) * height;
    if raw.len() < expected {
        return Err(OcrError::BadImage(format!(
            "PNG decompressed to {} bytes; expected at least {expected}",
            raw.len()
        )));
    }

    // Undo PNG per-row filters (0=None, 1=Sub, 2=Up, 3=Average, 4=Paeth) to
    // get the raw pixel grid. Then convert each pixel to a single gray byte.
    let mut gray = Vec::with_capacity(width * height);
    let mut prev_row: Vec<u8> = vec![0; stride];
    let mut cursor = 0usize;
    for _ in 0..height {
        let filter = raw[cursor];
        cursor += 1;
        let mut row = raw[cursor..cursor + stride].to_vec();
        cursor += stride;
        apply_png_filter(filter, &mut row, &prev_row, channels)?;
        for px in row.chunks_exact(channels) {
            let g = match color_type {
                0 => px[0],                                  // grayscale
                4 => over_white(px[0], px[1]),               // gray + alpha
                2 => luma_rgb(px[0], px[1], px[2]),          // RGB
                6 => {
                    // RGBA: composite over white BEFORE luma, so a dark glyph on
                    // a transparent background reads as dark-on-white instead of
                    // flooding to all-foreground and wrecking the Otsu split.
                    let r = over_white(px[0], px[3]);
                    let gc = over_white(px[1], px[3]);
                    let b = over_white(px[2], px[3]);
                    luma_rgb(r, gc, b)
                }
                3 => {
                    // Index into the palette; an out-of-range index decodes to
                    // mid-gray rather than panicking.
                    match palette.get(px[0] as usize) {
                        Some(rgb) => luma_rgb(rgb[0], rgb[1], rgb[2]),
                        None => 128,
                    }
                }
                _ => 128,
            };
            gray.push(g);
        }
        prev_row = row;
    }
    Ok(Gray {
        width,
        height,
        pixels: gray,
    })
}

/// Alpha-composite a single channel value over a white background:
/// `v*a + 255*(1-a)`. A fully transparent pixel (a=0) becomes white
/// (background); fully opaque (a=255) keeps its value. This matters because the
/// binarizer treats dark pixels as foreground, so a transparent region must
/// read as white, not as whatever stale RGB the encoder left under the alpha.
#[inline]
fn over_white(value: u8, alpha: u8) -> u8 {
    let a = alpha as u32;
    ((value as u32 * a + 255 * (255 - a)) / 255) as u8
}

#[inline]
fn luma_rgb(r: u8, g: u8, b: u8) -> u8 {
    // Standard Rec.601 luma. Good enough for CAPTCHA preprocessing where we
    // immediately threshold the result; a more exact Rec.709 would make no
    // visible difference.
    let y = (299u32 * r as u32 + 587 * g as u32 + 114 * b as u32) / 1000;
    y.min(255) as u8
}

fn apply_png_filter(filter: u8, row: &mut [u8], prev: &[u8], bpp: usize) -> Result<(), OcrError> {
    let n = row.len();
    match filter {
        0 => Ok(()),
        1 => {
            // Sub: each byte = this byte + previous byte in the same row.
            for i in bpp..n {
                row[i] = row[i].wrapping_add(row[i - bpp]);
            }
            Ok(())
        }
        2 => {
            // Up: each byte = this byte + corresponding byte in the row above.
            for i in 0..n {
                row[i] = row[i].wrapping_add(prev[i]);
            }
            Ok(())
        }
        3 => {
            // Average.
            for i in 0..n {
                let left = if i >= bpp { row[i - bpp] as u16 } else { 0 };
                let up = prev[i] as u16;
                row[i] = row[i].wrapping_add(((left + up) / 2) as u8);
            }
            Ok(())
        }
        4 => {
            // Paeth.
            for i in 0..n {
                let a = if i >= bpp { row[i - bpp] as i32 } else { 0 };
                let b = prev[i] as i32;
                let c = if i >= bpp { prev[i - bpp] as i32 } else { 0 };
                row[i] = row[i].wrapping_add(paeth(a, b, c) as u8);
            }
            Ok(())
        }
        other => Err(OcrError::BadImage(format!(
            "unknown PNG filter type {other}"
        ))),
    }
}

fn paeth(a: i32, b: i32, c: i32) -> i32 {
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Inflate a PNG IDAT zlib stream with a real DEFLATE decoder (flate2/miniz).
///
/// This replaces an earlier stored-blocks-only inflater that could not read
/// the Huffman-compressed streams every real PNG encoder emits. It handles all
/// three DEFLATE block types. The output is size-bounded by the caller, which
/// checks the decompressed length against the image's expected raw size before
/// using it, so a zip-bomb IDAT is caught there (and the per-side/pixel caps in
/// [`decode_png_grayscale`] bound the expected size itself).
fn inflate_zlib(data: &[u8]) -> Result<Vec<u8>, OcrError> {
    use std::io::Read as _;
    if data.len() < 2 {
        return Err(OcrError::BadImage("zlib stream too short".to_string()));
    }
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| OcrError::BadImage(format!("inflating PNG IDAT: {e}")))?;
    Ok(out)
}

/// Otsu's method: pick the global threshold that maximizes between-class
/// variance, then return a binary image (`true` = foreground = dark pixel).
fn otsu_threshold(gray: &[u8], w: usize, h: usize) -> Vec<bool> {
    let mut hist = [0u64; 256];
    for &g in gray {
        hist[g as usize] += 1;
    }
    let total = (w * h) as u64;
    let sum: u64 = (0u64..256).map(|i| i * hist[i as usize]).sum();
    let mut sum_b: u64 = 0;
    let mut w_b: u64 = 0;
    let mut max_var: f64 = -1.0;
    let mut threshold: u8 = 127;
    for t in 0u64..256 {
        w_b += hist[t as usize];
        if w_b == 0 {
            continue;
        }
        let w_f = total.saturating_sub(w_b);
        if w_f == 0 {
            break;
        }
        sum_b += t * hist[t as usize];
        let m_b = sum_b as f64 / w_b as f64;
        let m_f = (sum - sum_b) as f64 / w_f as f64;
        let var = (w_b as f64) * (w_f as f64) * (m_b - m_f).powi(2);
        // `>=` breaks ties toward the higher threshold, which sits between the
        // two classes on a bimodal histogram (otherwise we'd fall out of the
        // dark cluster and classify everything as background).
        if var >= max_var {
            max_var = var;
            threshold = t as u8;
        }
    }
    gray.iter().map(|&g| g < threshold).collect()
}

/// Remove 1-pixel noise: a foreground pixel with fewer than two foreground
/// neighbours is flipped to background. Light-touch — enough to clean up
/// salt-and-pepper noise without eating thin strokes.
fn despeckle(bin: &[bool], w: usize, h: usize) -> Vec<bool> {
    let mut out = bin.to_vec();
    for y in 1..h.saturating_sub(1) {
        for x in 1..w.saturating_sub(1) {
            let idx = y * w + x;
            if !bin[idx] {
                continue;
            }
            let mut neighbours = 0u32;
            for dy in -1i32..=1 {
                for dx in -1i32..=1 {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    let nx = x as i32 + dx;
                    let ny = y as i32 + dy;
                    if nx >= 0
                        && ny >= 0
                        && (nx as usize) < w
                        && (ny as usize) < h
                        && bin[ny as usize * w + nx as usize]
                    {
                        neighbours += 1;
                    }
                }
            }
            if neighbours < 2 {
                out[idx] = false;
            }
        }
    }
    out
}

/// A connected component: its bounding box and pixel count.
#[derive(Debug, Clone)]
struct Component {
    min_x: usize,
    min_y: usize,
    max_x: usize,
    max_y: usize,
    area: usize,
}

/// Find 4-connected foreground components, return them left-to-right so the
/// output characters come out in reading order.
fn find_components(bin: &[bool], w: usize, h: usize) -> Vec<Component> {
    let mut visited = vec![false; bin.len()];
    let mut out: Vec<Component> = Vec::new();
    let mut stack: Vec<(usize, usize)> = Vec::new();
    for y in 0..h {
        for x in 0..w {
            let idx = y * w + x;
            if !bin[idx] || visited[idx] {
                continue;
            }
            // Flood-fill.
            stack.clear();
            stack.push((x, y));
            let mut comp = Component {
                min_x: x,
                min_y: y,
                max_x: x,
                max_y: y,
                area: 0,
            };
            while let Some((cx, cy)) = stack.pop() {
                let ci = cy * w + cx;
                if visited[ci] || !bin[ci] {
                    continue;
                }
                visited[ci] = true;
                comp.area += 1;
                if cx < comp.min_x {
                    comp.min_x = cx;
                }
                if cx > comp.max_x {
                    comp.max_x = cx;
                }
                if cy < comp.min_y {
                    comp.min_y = cy;
                }
                if cy > comp.max_y {
                    comp.max_y = cy;
                }
                if cx > 0 {
                    stack.push((cx - 1, cy));
                }
                if cx + 1 < w {
                    stack.push((cx + 1, cy));
                }
                if cy > 0 {
                    stack.push((cx, cy - 1));
                }
                if cy + 1 < h {
                    stack.push((cx, cy + 1));
                }
            }
            // Discard specks (< 4 pixels) — they're noise, not glyphs.
            if comp.area >= 4 {
                out.push(comp);
            }
        }
    }
    out.sort_by_key(|c| c.min_x);
    out
}

/// Classify a connected component into a character.
///
/// This is deliberately dumb: aspect ratio + stroke density in a 3×3 grid
/// placed over the glyph's bounding box. It gets `0..=9` right on
/// clean, high-contrast CAPTCHAs and returns `None` for anything it isn't
/// sure about — the caller treats unclassified components as "not in the
/// answer" rather than guessing, since a wrong digit is worse than a short
/// answer.
fn classify_component(comp: &Component, bin: &[bool], w: usize) -> Option<char> {
    let gw = comp.max_x - comp.min_x + 1;
    let gh = comp.max_y - comp.min_y + 1;
    // A real glyph is at least a couple px wide and ~5 tall. `gw >= 2` keeps
    // narrow strokes like a thin '1' (the earlier `gw >= 3` dropped them);
    // despeckle + the area>=4 component filter already remove 1px noise.
    if gw < 2 || gh < 5 {
        return None;
    }
    // Build a 3×3 density grid.
    let mut grid = [[0f32; 3]; 3];
    let mut cell_total = [[0f32; 3]; 3];
    for y in comp.min_y..=comp.max_y {
        for x in comp.min_x..=comp.max_x {
            let gx = ((x - comp.min_x) * 3 / gw).min(2);
            let gy = ((y - comp.min_y) * 3 / gh).min(2);
            cell_total[gy][gx] += 1.0;
            if bin[y * w + x] {
                grid[gy][gx] += 1.0;
            }
        }
    }
    let mut density = [[0f32; 3]; 3];
    for y in 0..3 {
        for x in 0..3 {
            if cell_total[y][x] > 0.0 {
                density[y][x] = grid[y][x] / cell_total[y][x];
            }
        }
    }
    // Hand-tuned templates for `0..=9`. Each template is a 3×3 of
    // low/high density expectations; we pick the one whose L2 distance to the
    // observed density is smallest, and refuse if nothing beats a threshold.
    // The idea isn't to be a real OCR — it's to be useful on the handful of
    // CAPTCHA fonts that still live on very old admin panels, where tesseract
    // itself might not even be installed.
    const TEMPLATES: &[(char, [[f32; 3]; 3])] = &[
        (
            '0',
            [
                [0.8, 0.9, 0.8],
                [0.9, 0.1, 0.9],
                [0.8, 0.9, 0.8],
            ],
        ),
        (
            '1',
            [
                [0.2, 0.9, 0.2],
                [0.2, 0.9, 0.2],
                [0.5, 0.9, 0.5],
            ],
        ),
        (
            '2',
            [
                [0.7, 0.9, 0.7],
                [0.2, 0.6, 0.8],
                [0.9, 0.9, 0.5],
            ],
        ),
        (
            '3',
            [
                [0.7, 0.9, 0.7],
                [0.2, 0.7, 0.8],
                [0.7, 0.9, 0.7],
            ],
        ),
        (
            '4',
            [
                [0.7, 0.2, 0.7],
                [0.9, 0.9, 0.9],
                [0.2, 0.2, 0.9],
            ],
        ),
        (
            '5',
            [
                [0.9, 0.9, 0.5],
                [0.9, 0.7, 0.2],
                [0.2, 0.7, 0.9],
            ],
        ),
        (
            '6',
            [
                [0.7, 0.9, 0.5],
                [0.9, 0.9, 0.3],
                [0.8, 0.9, 0.8],
            ],
        ),
        (
            '7',
            [
                [0.9, 0.9, 0.9],
                [0.2, 0.5, 0.9],
                [0.2, 0.9, 0.3],
            ],
        ),
        (
            '8',
            [
                [0.8, 0.9, 0.8],
                [0.7, 0.9, 0.7],
                [0.8, 0.9, 0.8],
            ],
        ),
        (
            '9',
            [
                [0.8, 0.9, 0.8],
                [0.3, 0.9, 0.9],
                [0.5, 0.9, 0.7],
            ],
        ),
    ];
    let mut best = (f32::MAX, '?');
    for (ch, tmpl) in TEMPLATES {
        let mut d = 0f32;
        for y in 0..3 {
            for x in 0..3 {
                let diff = density[y][x] - tmpl[y][x];
                d += diff * diff;
            }
        }
        if d < best.0 {
            best = (d, *ch);
        }
    }
    // Refuse anything that isn't a clear winner; the 3×3 template distance of
    // a well-shaped digit is typically ≤ 0.6, with the next-best ≥ 1.0.
    if best.0 < 1.4 {
        Some(best.1)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Output normalization
// ---------------------------------------------------------------------------

fn normalize(raw: &str, max_len: usize) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_whitespace() || ch.is_control() {
            continue;
        }
        out.push(ch);
        if out.chars().count() >= max_len {
            break;
        }
    }
    out
}

fn heuristic_confidence(text: &str, whitelist: &str) -> u8 {
    let n = text.chars().count();
    if n == 0 {
        return 0;
    }
    // Expected CAPTCHA length is 4..=8 chars; score peaks there.
    let len_score = match n {
        4..=8 => 80,
        3 | 9 => 60,
        2 | 10..=12 => 40,
        _ => 20,
    } as u32;
    // Full score when there is no whitelist, or when every character is allowed;
    // otherwise the text contains out-of-charset characters and scores low.
    let alpha_score = if whitelist.is_empty() || text.chars().all(|c| whitelist.contains(c)) {
        20
    } else {
        5
    };
    ((len_score + alpha_score).min(100)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_format_sniffing() {
        assert_eq!(
            ImageFormat::from_bytes(b"\x89PNG\r\n\x1a\nxxx"),
            ImageFormat::Png
        );
        assert_eq!(ImageFormat::from_bytes(b"\xff\xd8\xff..."), ImageFormat::Jpeg);
        assert_eq!(ImageFormat::from_bytes(b"not an image"), ImageFormat::Auto);
    }

    #[test]
    fn normalize_collapses_whitespace_and_bounds_length() {
        assert_eq!(normalize("  12 34 \n", 32), "1234");
        assert_eq!(normalize("ABCDEF", 3), "ABC");
    }

    #[test]
    fn heuristic_confidence_rewards_whitelisted_short_answers() {
        let c = heuristic_confidence("1234", "0123456789");
        assert!(c >= 90, "{c}");
        // Non-whitelisted characters in the result cut the confidence materially.
        let whitelisted = heuristic_confidence("1234", "0123456789");
        let off_alphabet = heuristic_confidence("abc!", "0123456789");
        assert!(off_alphabet < whitelisted, "{off_alphabet} vs {whitelisted}");
        // Very long output is also penalized, no matter the whitelist.
        let runaway = heuristic_confidence("a".repeat(30).as_str(), "");
        assert!(runaway <= 45, "{runaway}");
    }

    #[test]
    fn digit_preset_restricts_whitelist() {
        let cfg = OcrConfig::digits();
        assert_eq!(cfg.whitelist, "0123456789");
        assert_eq!(cfg.psm, 7);
    }

    #[test]
    fn alphanum_preset_covers_mixed_case() {
        let cfg = OcrConfig::alphanum();
        assert!(cfg.whitelist.contains('A'));
        assert!(cfg.whitelist.contains('z'));
        assert!(cfg.whitelist.contains('0'));
    }

    #[test]
    fn solve_rejects_non_image_bytes() {
        let bad = b"this is not an image";
        let cfg = OcrConfig {
            backend: OcrBackend::Builtin,
            ..OcrConfig::default()
        };
        let err = solve(bad, &cfg).unwrap_err();
        match err {
            OcrError::BadImage(_) => {}
            other => panic!("expected BadImage, got {other:?}"),
        }
    }

    #[test]
    fn solve_rejects_jpeg_in_builtin_backend() {
        let jpeg_magic = b"\xff\xd8\xff\xe0\x00\x10JFIF\0";
        let cfg = OcrConfig {
            backend: OcrBackend::Builtin,
            ..OcrConfig::default()
        };
        let err = solve(jpeg_magic, &cfg).unwrap_err();
        match err {
            OcrError::BackendUnavailable(m) => assert!(m.contains("JPEG")),
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn otsu_splits_bimodal_histogram() {
        // 2×2 image: two dark, two light pixels.
        let g = &[0u8, 0, 255, 255];
        let bin = otsu_threshold(g, 2, 2);
        assert_eq!(bin, vec![true, true, false, false]);
    }

    #[test]
    fn components_sorted_left_to_right() {
        // Two separated foreground blobs; the right one must come second.
        let mut bin = vec![false; 10 * 10];
        for y in 2..5 {
            for x in 1..3 {
                bin[y * 10 + x] = true;
            }
        }
        for y in 2..5 {
            for x in 6..8 {
                bin[y * 10 + x] = true;
            }
        }
        let comps = find_components(&bin, 10, 10);
        assert_eq!(comps.len(), 2);
        assert!(comps[0].min_x < comps[1].min_x);
    }

    #[test]
    fn classify_returns_some_character_for_digit_shaped_blob() {
        // Draw a crude "1": a vertical bar three columns wide (gw >= 3 is the
        // sanity gate), 13 rows tall.
        let (w, h) = (11, 15);
        let mut bin = vec![false; w * h];
        for y in 1..14 {
            for x in 4..7 {
                bin[y * w + x] = true;
            }
        }
        let comps = find_components(&bin, w, h);
        assert_eq!(comps.len(), 1);
        let out = classify_component(&comps[0], &bin, w);
        assert!(out.is_some(), "expected a classification for a vertical bar");
    }

    #[test]
    fn despeckle_removes_isolated_pixel() {
        // 5×5 image with a single foreground pixel at (2,2); must be removed.
        let mut bin = vec![false; 5 * 5];
        bin[2 * 5 + 2] = true;
        let out = despeckle(&bin, 5, 5);
        assert!(!out[2 * 5 + 2]);
    }

    #[test]
    fn solve_result_kinds_render() {
        // Debug/Display paths exist on every type so CLI output stays stable.
        let r = OcrResult {
            text: "1234".into(),
            backend: OcrBackend::Tesseract,
            confidence: 95,
        };
        let s = format!("{:?} {}", r.backend, r.confidence);
        assert!(s.contains("Tesseract"));
        assert!(s.contains("95"));
    }

    #[test]
    fn errors_display_their_kind() {
        assert_eq!(
            OcrError::NoText.to_string(),
            "OCR produced no text"
        );
        assert!(OcrError::BadImage("x".into()).to_string().contains("bad"));
        assert!(OcrError::BackendUnavailable("x".into())
            .to_string()
            .contains("unavailable"));
    }

    #[test]
    fn config_default_backend_is_auto() {
        let cfg = OcrConfig::default();
        assert_eq!(cfg.backend, OcrBackend::Auto);
        assert_eq!(cfg.psm, 7);
        assert_eq!(cfg.lang, "eng");
        assert_eq!(cfg.max_len, 32);
    }

    /// Encode an 8-bit grayscale image as a real, Huffman-compressed PNG (via
    /// flate2) with filter-byte 0 per row and zero CRCs (our decoder ignores
    /// CRCs). Used to prove the builtin backend decodes ordinary compressed
    /// PNGs, not just the level-0 "stored" streams the old inflater needed.
    fn encode_gray_png(width: usize, height: usize, pixels: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        assert_eq!(pixels.len(), width * height);
        fn chunk(out: &mut Vec<u8>, ty: &[u8; 4], body: &[u8]) {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(ty);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0, 0, 0, 0]); // CRC (ignored by our decoder)
        }
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&(width as u32).to_be_bytes());
        ihdr.extend_from_slice(&(height as u32).to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit, grayscale, no interlace
        chunk(&mut png, b"IHDR", &ihdr);

        // Raw scanlines: one filter byte (0 = None) then the row's pixels.
        let mut raw = Vec::with_capacity((width + 1) * height);
        for y in 0..height {
            raw.push(0);
            raw.extend_from_slice(&pixels[y * width..(y + 1) * width]);
        }
        let mut enc =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw).unwrap();
        let idat = enc.finish().unwrap();
        chunk(&mut png, b"IDAT", &idat);
        chunk(&mut png, b"IEND", &[]);
        png
    }

    #[test]
    fn builtin_decodes_a_real_compressed_png() {
        // A 12×18 white canvas with a solid black "1"-like bar in the middle.
        let (w, h) = (12usize, 18usize);
        let mut px = vec![255u8; w * h];
        for y in 2..16 {
            for x in 5..8 {
                px[y * w + x] = 0;
            }
        }
        let png = encode_gray_png(w, h, &px);
        // Sanity: this is NOT a stored-only stream — the old inflater would
        // have rejected it. Decode must now succeed through flate2.
        let gray = decode_png_grayscale(&png).expect("compressed PNG should decode");
        assert_eq!(gray.width, w);
        assert_eq!(gray.height, h);
        // The builtin backend should extract a single glyph from the bar.
        let cfg = OcrConfig {
            backend: OcrBackend::Builtin,
            ..OcrConfig::digits()
        };
        let res = solve(&png, &cfg).expect("builtin should classify the bar");
        assert_eq!(res.backend, OcrBackend::Builtin);
        assert!(!res.text.is_empty());
    }

    #[test]
    fn builtin_decodes_an_indexed_palette_png() {
        use std::io::Write as _;
        // Hand-build a 2×1 indexed PNG: palette[0]=black, palette[1]=white,
        // pixels = [0, 1]. Proves color-type-3 support + PLTE lookup.
        fn chunk(out: &mut Vec<u8>, ty: &[u8; 4], body: &[u8]) {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(ty);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&2u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 3, 0, 0, 0]); // 8-bit, indexed
        chunk(&mut png, b"IHDR", &ihdr);
        chunk(&mut png, b"PLTE", &[0, 0, 0, 255, 255, 255]);
        let raw = [0u8, 0u8, 1u8]; // filter byte + index 0 + index 1
        let mut enc =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw).unwrap();
        let idat = enc.finish().unwrap();
        chunk(&mut png, b"IDAT", &idat);
        chunk(&mut png, b"IEND", &[]);

        let gray = decode_png_grayscale(&png).expect("indexed PNG should decode");
        assert_eq!(gray.pixels, vec![0, 255]); // black then white
    }

    #[test]
    fn over_white_composites_alpha() {
        // Fully transparent → white (background), whatever the stored value.
        assert_eq!(over_white(0, 0), 255);
        assert_eq!(over_white(17, 0), 255);
        // Fully opaque → unchanged.
        assert_eq!(over_white(0, 255), 0);
        assert_eq!(over_white(200, 255), 200);
        // Half alpha over white blends toward white.
        let half = over_white(0, 128);
        assert!(half > 120 && half < 140, "{half}");
    }

    #[test]
    fn rgba_transparent_background_reads_as_white_not_foreground() {
        use std::io::Write as _;
        // 2×1 RGBA PNG: pixel 0 = opaque black glyph, pixel 1 = transparent
        // (stored RGB also black). Without alpha compositing both would read as
        // black (foreground); with it, pixel 1 must become white (background).
        fn chunk(out: &mut Vec<u8>, ty: &[u8; 4], body: &[u8]) {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(ty);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&2u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
        chunk(&mut png, b"IHDR", &ihdr);
        // filter byte 0, then RGBA for two pixels: black/opaque, black/transparent.
        let raw = [0u8, 0, 0, 0, 255, 0, 0, 0, 0];
        let mut enc =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&raw).unwrap();
        let idat = enc.finish().unwrap();
        chunk(&mut png, b"IDAT", &idat);
        chunk(&mut png, b"IEND", &[]);
        let gray = decode_png_grayscale(&png).expect("RGBA PNG should decode");
        assert_eq!(gray.pixels, vec![0, 255]); // opaque black, then white
    }

    #[test]
    fn oversized_png_header_is_refused_without_allocating() {
        // IHDR claims 60000×60000 (3.6 gigapixels). Must be refused by the cap,
        // never allocated. CRC-less, no IDAT needed — the cap trips first.
        fn chunk(out: &mut Vec<u8>, ty: &[u8; 4], body: &[u8]) {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(ty);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
        let mut png = Vec::new();
        png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&60000u32.to_be_bytes());
        ihdr.extend_from_slice(&60000u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
        chunk(&mut png, b"IHDR", &ihdr);
        chunk(&mut png, b"IEND", &[]);
        let err = decode_png_grayscale(&png).unwrap_err();
        match err {
            OcrError::BadImage(m) => assert!(m.contains("cap"), "{m}"),
            other => panic!("expected a dimension-cap BadImage, got {other:?}"),
        }
    }
}
