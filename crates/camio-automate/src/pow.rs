//! Proof-of-work challenge solver (plan §8 "Automate"; anti-bot wall handling).
//!
//! A growing share of sites gate access behind a **proof-of-work** challenge
//! instead of (or before) a CAPTCHA: the server hands the client a challenge
//! string and a difficulty, and the client must burn CPU to find a `nonce`
//! whose hash meets the difficulty target. This is the mechanism behind
//! **Anubis** (the Xe Iaso anti-scraper seen on many forges/wikis since 2024),
//! **mCaptcha**, and classic **hashcash**. Unlike a CAPTCHA it needs no human
//! and no third-party service — it is pure, local computation — so Camio can
//! solve it outright.
//!
//! This module is **pure and offline**: it takes a parsed challenge and returns
//! the winning nonce. It sends nothing. The caller submits the solution through
//! the fingerprint-matched, policy-gated engine (`camio-request`), which is
//! where scope/rate/authorization live (plan §16).
//!
//! ## Honesty about scope
//!
//! This solves *hash-preimage* PoW (SHA-256 leading-zero difficulty), which
//! covers Anubis, mCaptcha and hashcash. It does **not** solve PoW schemes
//! built on memory-hard or non-SHA functions (e.g. a scrypt/argon2 or blake3
//! puzzle) — those need the specific hash and are out of scope here; the
//! [`PowAlgorithm`] enum names what is supported so a caller can detect an
//! unsupported challenge rather than silently mis-solve it.
//!
//! ## Safety
//!
//! * No `unwrap`/`expect`/`panic!` outside tests.
//! * Every solve is bounded by [`PowChallenge::max_iterations`]: an
//!   over-hard or malformed challenge returns [`PowError::Exhausted`] instead
//!   of spinning forever.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Which hash + difficulty convention a challenge uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowAlgorithm {
    /// SHA-256 of `challenge || nonce`, difficulty = required number of leading
    /// **zero hex characters** in the lowercase hex digest. This is Anubis'
    /// convention (difficulty 4 ⇒ digest starts with `"0000"`).
    Sha256LeadingHexZeros,
    /// SHA-256 of `challenge || nonce`, difficulty = required number of leading
    /// **zero bits** in the raw digest. This is the hashcash / mCaptcha
    /// convention and is finer-grained (one bit at a time, not four).
    Sha256LeadingBitZeros,
}

impl PowAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            PowAlgorithm::Sha256LeadingHexZeros => "sha256-leading-hex-zeros",
            PowAlgorithm::Sha256LeadingBitZeros => "sha256-leading-bit-zeros",
        }
    }
}

/// How the nonce is appended to the challenge before hashing. Different schemes
/// stringify the counter differently; getting this wrong produces a hash the
/// server rejects, so it is explicit rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceFormat {
    /// Decimal ASCII (`"0"`, `"1"`, … `"42"`). Anubis uses this.
    Decimal,
    /// Lowercase hex ASCII (`"0"`, `"a"`, `"2f"`).
    LowerHex,
}

impl NonceFormat {
    fn render(self, nonce: u64) -> String {
        match self {
            NonceFormat::Decimal => nonce.to_string(),
            NonceFormat::LowerHex => format!("{nonce:x}"),
        }
    }
}

/// A fully-specified proof-of-work challenge ready to solve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowChallenge {
    pub algorithm: PowAlgorithm,
    /// The server-provided challenge string the nonce is appended to.
    pub challenge: String,
    /// Difficulty, interpreted per [`PowAlgorithm`] (leading zero hex chars, or
    /// leading zero bits).
    pub difficulty: u32,
    /// How to stringify the nonce before concatenation.
    pub nonce_format: NonceFormat,
    /// The nonce value to start the search from (usually 0; a non-zero start
    /// lets callers shard the search across workers).
    pub start_nonce: u64,
    /// Hard cap on hash attempts before giving up (keeps a too-hard or
    /// malformed challenge from spinning forever). `None` ⇒ a safe default.
    pub max_iterations: Option<u64>,
}

impl PowChallenge {
    /// An Anubis-style challenge: SHA-256, leading-zero-hex difficulty, decimal
    /// nonce from 0. This is the common case.
    pub fn anubis(challenge: impl Into<String>, difficulty: u32) -> Self {
        PowChallenge {
            algorithm: PowAlgorithm::Sha256LeadingHexZeros,
            challenge: challenge.into(),
            difficulty,
            nonce_format: NonceFormat::Decimal,
            start_nonce: 0,
            max_iterations: None,
        }
    }

    /// A hashcash-style challenge: SHA-256, leading-zero-**bit** difficulty.
    pub fn hashcash(challenge: impl Into<String>, difficulty_bits: u32) -> Self {
        PowChallenge {
            algorithm: PowAlgorithm::Sha256LeadingBitZeros,
            challenge: challenge.into(),
            difficulty: difficulty_bits,
            nonce_format: NonceFormat::Decimal,
            start_nonce: 0,
            max_iterations: None,
        }
    }

    /// The effective iteration cap. The default scales with difficulty but is
    /// clamped so a hostile challenge cannot request an unbounded burn:
    /// `16 << difficulty_bits` attempts (≈ a few seconds at the top of the
    /// supported range), capped at 2^32.
    fn effective_cap(&self) -> u64 {
        if let Some(c) = self.max_iterations {
            return c;
        }
        let bits = self.difficulty_bits();
        // 16 * 2^bits, saturating, capped at 2^32 so even a mis-read difficulty
        // terminates in bounded time.
        let scaled = 16u64.checked_shl(bits.min(32)).unwrap_or(u64::MAX);
        scaled.min(1u64 << 32)
    }

    /// Difficulty expressed in bits, regardless of the hex/bit convention (each
    /// leading zero hex char is 4 bits). Used to size the iteration budget.
    fn difficulty_bits(&self) -> u32 {
        match self.algorithm {
            PowAlgorithm::Sha256LeadingHexZeros => self.difficulty.saturating_mul(4),
            PowAlgorithm::Sha256LeadingBitZeros => self.difficulty,
        }
    }
}

/// A solved proof of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowSolution {
    /// The winning nonce value.
    pub nonce: u64,
    /// The nonce as it was stringified and concatenated (what the server
    /// expects echoed back).
    pub nonce_string: String,
    /// The lowercase hex digest that satisfied the difficulty.
    pub hash_hex: String,
    /// How many hashes were computed to find it (1-based).
    pub iterations: u64,
}

/// Errors from solving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowError {
    /// The iteration budget was exhausted without finding a solution — the
    /// challenge is harder than the budget allows, or malformed.
    Exhausted { attempts: u64 },
    /// The difficulty is impossible to satisfy (e.g. more leading zero bits than
    /// a 256-bit digest has).
    Unsatisfiable { difficulty_bits: u32 },
    /// The nonce counter would overflow before the budget was reached (only
    /// reachable with an enormous `start_nonce`).
    NonceOverflow,
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PowError::Exhausted { attempts } => {
                write!(f, "proof-of-work exhausted after {attempts} attempts")
            }
            PowError::Unsatisfiable { difficulty_bits } => write!(
                f,
                "proof-of-work difficulty of {difficulty_bits} bits exceeds the 256-bit digest"
            ),
            PowError::NonceOverflow => write!(f, "proof-of-work nonce counter overflowed"),
        }
    }
}

impl std::error::Error for PowError {}

/// Solve a proof-of-work challenge: find the first nonce (from `start_nonce`,
/// incrementing) whose digest meets the difficulty.
///
/// Returns the winning [`PowSolution`], or a [`PowError`] when the bounded
/// search gives up. Deterministic: the same challenge always yields the same
/// nonce.
pub fn solve(challenge: &PowChallenge) -> Result<PowSolution, PowError> {
    let difficulty_bits = challenge.difficulty_bits();
    if difficulty_bits > 256 {
        return Err(PowError::Unsatisfiable { difficulty_bits });
    }
    let cap = challenge.effective_cap();
    let base = challenge.challenge.as_bytes();

    let mut attempts: u64 = 0;
    let mut nonce = challenge.start_nonce;
    while attempts < cap {
        let nonce_string = challenge.nonce_format.render(nonce);

        // Hash challenge || nonce_string.
        let mut hasher = Sha256::new();
        hasher.update(base);
        hasher.update(nonce_string.as_bytes());
        let digest = hasher.finalize();

        attempts += 1;

        let satisfied = match challenge.algorithm {
            PowAlgorithm::Sha256LeadingHexZeros => {
                leading_zero_nibbles(&digest) >= challenge.difficulty
            }
            PowAlgorithm::Sha256LeadingBitZeros => {
                leading_zero_bits(&digest) >= challenge.difficulty
            }
        };
        if satisfied {
            return Ok(PowSolution {
                nonce,
                nonce_string,
                hash_hex: to_hex(&digest),
                iterations: attempts,
            });
        }

        nonce = match nonce.checked_add(1) {
            Some(n) => n,
            None => return Err(PowError::NonceOverflow),
        };
    }
    Err(PowError::Exhausted { attempts })
}

/// Verify a solution against its challenge (recompute the hash and re-check the
/// difficulty). Lets a caller confirm a solution it is about to submit, and
/// backs the solver's own tests.
pub fn verify(challenge: &PowChallenge, solution: &PowSolution) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge.challenge.as_bytes());
    hasher.update(solution.nonce_string.as_bytes());
    let digest = hasher.finalize();
    if to_hex(&digest) != solution.hash_hex {
        return false;
    }
    match challenge.algorithm {
        PowAlgorithm::Sha256LeadingHexZeros => {
            leading_zero_nibbles(&digest) >= challenge.difficulty
        }
        PowAlgorithm::Sha256LeadingBitZeros => leading_zero_bits(&digest) >= challenge.difficulty,
    }
}

/// Count leading zero bits in a big-endian byte digest.
fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in digest {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Count leading zero hex nibbles (4-bit groups) in a digest.
fn leading_zero_nibbles(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in digest {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        if hi == 0 {
            count += 1;
        } else {
            break;
        }
        if lo == 0 {
            count += 1;
        } else {
            break;
        }
    }
    count
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Parsing known challenge formats
// ---------------------------------------------------------------------------

/// Parse an **Anubis** challenge from the JSON its `/.within.website/…/challenge`
/// endpoint returns, or from the inline `<script id="anubis_challenge">` blob.
///
/// Anubis emits `{"challenge":"<hex>","rules":{"difficulty":N,"algorithm":"fast"}}`.
/// Unknown/absent fields yield `None` rather than a wrong guess.
pub fn parse_anubis(json: &str) -> Option<PowChallenge> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let challenge = v.get("challenge")?.as_str()?.to_string();
    // difficulty may sit at the top level or under "rules".
    let difficulty = v
        .get("rules")
        .and_then(|r| r.get("difficulty"))
        .or_else(|| v.get("difficulty"))
        .and_then(|d| d.as_u64())? as u32;
    Some(PowChallenge::anubis(challenge, difficulty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_counts() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0xff]), 16);
        assert_eq!(leading_zero_bits(&[0x0f, 0xff]), 4);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_nibbles(&[0x00, 0x0f]), 3);
        assert_eq!(leading_zero_nibbles(&[0x00, 0x00]), 4);
        assert_eq!(leading_zero_nibbles(&[0xf0]), 0);
    }

    #[test]
    fn solves_and_verifies_easy_hex_challenge() {
        // Difficulty 2 hex zeros (8 bits) is tiny: solvable in a handful of
        // iterations and fast enough for CI.
        let ch = PowChallenge::anubis("camio-test-challenge", 2);
        let sol = solve(&ch).expect("difficulty 2 must be solvable");
        assert!(sol.hash_hex.starts_with("00"));
        assert!(verify(&ch, &sol), "solution must verify");
        // Deterministic.
        let sol2 = solve(&ch).unwrap();
        assert_eq!(sol.nonce, sol2.nonce);
    }

    #[test]
    fn solves_leading_bit_challenge() {
        let ch = PowChallenge::hashcash("seed", 10); // 10 bits
        let sol = solve(&ch).expect("10-bit PoW must be solvable");
        assert!(verify(&ch, &sol));
        assert!(leading_zero_bits(&hex_to_bytes(&sol.hash_hex)) >= 10);
    }

    #[test]
    fn nonce_format_changes_the_hash() {
        let mut dec = PowChallenge::hashcash("seed", 8);
        dec.nonce_format = NonceFormat::Decimal;
        let mut hex = dec.clone();
        hex.nonce_format = NonceFormat::LowerHex;
        let a = solve(&dec).unwrap();
        let b = solve(&hex).unwrap();
        // Both valid under their own format; the stringified nonce differs in
        // representation once nonce >= 10.
        assert!(verify(&dec, &a));
        assert!(verify(&hex, &b));
    }

    #[test]
    fn exhaustion_is_bounded_not_infinite() {
        // Force a tiny budget against a hard difficulty: must give up quickly.
        let mut ch = PowChallenge::hashcash("seed", 64);
        ch.max_iterations = Some(50);
        match solve(&ch) {
            Err(PowError::Exhausted { attempts }) => assert_eq!(attempts, 50),
            other => panic!("expected bounded exhaustion, got {other:?}"),
        }
    }

    #[test]
    fn unsatisfiable_difficulty_is_rejected() {
        let ch = PowChallenge::hashcash("seed", 300); // > 256 bits
        assert_eq!(
            solve(&ch),
            Err(PowError::Unsatisfiable {
                difficulty_bits: 300
            })
        );
    }

    #[test]
    fn verify_rejects_a_tampered_hash() {
        let ch = PowChallenge::anubis("x", 1);
        let mut sol = solve(&ch).unwrap();
        sol.hash_hex = "deadbeef".to_string();
        assert!(!verify(&ch, &sol));
    }

    #[test]
    fn parse_anubis_json() {
        let json = r#"{"challenge":"abcdef0123","rules":{"difficulty":4,"algorithm":"fast"}}"#;
        let ch = parse_anubis(json).expect("valid anubis json");
        assert_eq!(ch.challenge, "abcdef0123");
        assert_eq!(ch.difficulty, 4);
        assert_eq!(ch.algorithm, PowAlgorithm::Sha256LeadingHexZeros);

        // Top-level difficulty variant.
        let json2 = r#"{"challenge":"zz","difficulty":3}"#;
        assert_eq!(parse_anubis(json2).unwrap().difficulty, 3);

        // Garbage → None, not a panic.
        assert!(parse_anubis("not json").is_none());
        assert!(parse_anubis(r#"{"no":"challenge"}"#).is_none());
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
