//! `camio-sequencer` — randomness/entropy analysis of session tokens and other
//! samples (plan §8, the "Sequencer" row: *"Sample capture + documented
//! randomness analysis, sample limits, reproducible reports"*).
//!
//! **Measure, don't assert.** This crate mirrors Camio's core honesty rule
//! (plan §6.1 "Measure, don't assert"): it produces a *statistical estimate* of
//! how much entropy a set of samples appears to carry. That estimate is **not a
//! cryptographic proof** of unpredictability — a generator can pass a cheap
//! entropy check and still be trivially predictable. Every [`SequencerReport`]
//! therefore carries that caveat in [`SequencerReport::notes`], and the report
//! is fully [`serde`]-serializable so an analysis is reproducible and reviewable
//! (plan §8: "reproducible reports").
//!
//! The crate is deliberately dependency-light (it does not depend on
//! `camio-core`): [`analyze`] works over the `char`s of each token and
//! [`analyze_bytes`] over raw bytes, so it can score anything from a hex session
//! id to a binary cookie.
//!
//! Two independent estimates are computed and the stronger one is reported:
//!
//!   * **Per-position entropy** — when every sample is the same length, the
//!     Shannon entropy of the symbol distribution at each index is measured and
//!     summed. This is the honest estimator for fixed-width tokens because it
//!     catches a position that never varies (e.g. a constant prefix or a
//!     checksum nibble) even when the pooled distribution looks healthy.
//!   * **Pooled per-symbol entropy × mean length** — the fallback when samples
//!     have mixed lengths and a per-position view is meaningless.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The honesty caveat attached to every report. The estimate is statistical,
/// never a proof — see the module docs and plan §6.1 ("Measure, don't assert").
const CAVEAT: &str =
    "This is a statistical estimate of randomness quality, not a cryptographic proof; \
     measure, don't assert — a passing estimate does not imply unpredictability.";

/// A coarse, human-facing verdict derived from the estimated entropy per token.
///
/// Bucketed from [`SequencerReport::effective_bits`]: `<32` → [`Quality::Poor`],
/// `<64` → [`Quality::Fair`], `<128` → [`Quality::Good`], `>=128` →
/// [`Quality::Excellent`]. The thresholds are rules of thumb for session-token
/// strength, not guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quality {
    Poor,
    Fair,
    Good,
    Excellent,
}

/// A reproducible, serializable randomness report for a set of samples
/// (plan §8). All fields are public so callers (CLI/MCP) can render or diff them
/// without going through accessors.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SequencerReport {
    /// Number of samples supplied.
    pub sample_count: usize,
    /// Number of distinct samples (whole-token equality).
    pub unique_count: usize,
    /// `sample_count - unique_count`: how many samples repeated an earlier one.
    pub duplicate_count: usize,
    /// `unique_count / sample_count`, or `0.0` when there are no samples. A
    /// value well below `1.0` is itself a red flag regardless of entropy.
    pub unique_ratio: f64,
    /// Shortest sample length (symbols), `0` when there are no samples.
    pub min_len: usize,
    /// Longest sample length (symbols), `0` when there are no samples.
    pub max_len: usize,
    /// Mean sample length (symbols), `0.0` when there are no samples.
    pub mean_len: f64,
    /// Distinct symbols observed across all samples pooled together (the
    /// observed alphabet size).
    pub charset_size: usize,
    /// Shannon entropy (bits) of the pooled symbol frequency distribution — the
    /// average information content of a single symbol.
    pub global_entropy_per_symbol: f64,
    /// Shannon entropy (bits) at each index, measured across the samples. Only
    /// populated when every sample shares one non-zero length; empty otherwise
    /// (mixed lengths, or all-empty samples).
    pub per_position_entropy: Vec<f64>,
    /// Best estimate of total entropy per token, in bits: the sum of
    /// [`per_position_entropy`](Self::per_position_entropy) when it is
    /// available, otherwise `global_entropy_per_symbol * mean_len`.
    pub effective_bits: f64,
    /// Coarse verdict derived from [`effective_bits`](Self::effective_bits).
    pub quality: Quality,
    /// Human-readable caveats and warnings. Always contains the "statistical
    /// estimate, not a proof" caveat; also flags mixed-length samples (which
    /// disable the per-position estimate) and small sample counts (`< 20`).
    pub notes: Vec<String>,
}

/// Shannon entropy in **bits** of a frequency table: `-Σ pᵢ·log₂ pᵢ` where
/// `pᵢ = freqs[i] / Σ freqs`.
///
/// Zero-count buckets contribute nothing (the `0·log₂0 = 0` convention) and an
/// all-zero or empty table yields `0.0`. The result ranges from `0.0` (one
/// symbol ever) to `log₂ n` (n equiprobable symbols).
///
/// ```
/// # use camio_sequencer::shannon_entropy;
/// assert_eq!(shannon_entropy(&[1, 1]), 1.0);
/// assert_eq!(shannon_entropy(&[1, 1, 1, 1]), 2.0);
/// assert_eq!(shannon_entropy(&[1]), 0.0);
/// ```
pub fn shannon_entropy(freqs: &[usize]) -> f64 {
    let total: usize = freqs.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    let mut entropy = 0.0_f64;
    for &f in freqs {
        if f == 0 {
            continue;
        }
        let p = f as f64 / total;
        entropy -= p * p.log2();
    }
    // Collapse a possible IEEE negative zero (e.g. a single symbol) to +0.0.
    if entropy == 0.0 {
        0.0
    } else {
        entropy
    }
}

/// Analyze a set of tokens by their Unicode scalar values (`char`s). Suitable
/// for textual session ids, CSRF tokens, hex/base64 strings, etc. Handles an
/// empty slice gracefully (see [`SequencerReport`]).
pub fn analyze(tokens: &[String]) -> SequencerReport {
    let samples: Vec<Vec<char>> = tokens.iter().map(|t| t.chars().collect()).collect();
    analyze_symbols(&samples)
}

/// Analyze a set of samples over the raw byte alphabet (`0..=255`). Suitable for
/// binary cookies or decoded tokens. Handles an empty slice gracefully.
pub fn analyze_bytes(samples: &[Vec<u8>]) -> SequencerReport {
    analyze_symbols(samples)
}

/// Bucket an entropy estimate (bits) into a [`Quality`] verdict.
fn quality_from_bits(bits: f64) -> Quality {
    if bits < 32.0 {
        Quality::Poor
    } else if bits < 64.0 {
        Quality::Fair
    } else if bits < 128.0 {
        Quality::Good
    } else {
        Quality::Excellent
    }
}

/// The shared estimator, generic over the symbol type so [`analyze`] (chars) and
/// [`analyze_bytes`] (bytes) share one audited code path.
fn analyze_symbols<S>(samples: &[Vec<S>]) -> SequencerReport
where
    S: Eq + std::hash::Hash,
{
    let sample_count = samples.len();
    if sample_count == 0 {
        return SequencerReport {
            sample_count: 0,
            unique_count: 0,
            duplicate_count: 0,
            unique_ratio: 0.0,
            min_len: 0,
            max_len: 0,
            mean_len: 0.0,
            charset_size: 0,
            global_entropy_per_symbol: 0.0,
            per_position_entropy: Vec::new(),
            effective_bits: 0.0,
            quality: Quality::Poor,
            notes: vec![
                CAVEAT.to_string(),
                "no samples were provided; there is nothing to analyze".to_string(),
            ],
        };
    }

    // Whole-sample uniqueness (duplicate tokens are a red flag on their own).
    let unique_count = samples.iter().collect::<HashSet<&Vec<S>>>().len();
    let duplicate_count = sample_count - unique_count;
    let unique_ratio = unique_count as f64 / sample_count as f64;

    // Lengths. `unwrap_or` keeps this panic-free even though the slice is known
    // non-empty here.
    let min_len = samples.iter().map(|s| s.len()).min().unwrap_or(0);
    let max_len = samples.iter().map(|s| s.len()).max().unwrap_or(0);
    let total_len: usize = samples.iter().map(|s| s.len()).sum();
    let mean_len = total_len as f64 / sample_count as f64;

    // Pooled symbol distribution → observed alphabet size and per-symbol entropy.
    let mut pooled: HashMap<&S, usize> = HashMap::new();
    for s in samples {
        for sym in s {
            *pooled.entry(sym).or_insert(0) += 1;
        }
    }
    let charset_size = pooled.len();
    let pooled_freqs: Vec<usize> = pooled.values().copied().collect();
    let global_entropy_per_symbol = shannon_entropy(&pooled_freqs);

    // Per-position entropy is only meaningful when all samples share one length.
    let uniform_length = min_len == max_len;
    let per_position_entropy: Vec<f64> = if uniform_length && min_len > 0 {
        (0..min_len)
            .map(|i| {
                let mut column: HashMap<&S, usize> = HashMap::new();
                for s in samples {
                    if let Some(sym) = s.get(i) {
                        *column.entry(sym).or_insert(0) += 1;
                    }
                }
                let freqs: Vec<usize> = column.values().copied().collect();
                shannon_entropy(&freqs)
            })
            .collect()
    } else {
        Vec::new()
    };

    // Prefer the per-position estimate; fall back to pooled entropy × length.
    let effective_bits: f64 = if per_position_entropy.is_empty() {
        global_entropy_per_symbol * mean_len
    } else {
        per_position_entropy.iter().sum()
    };

    let quality = quality_from_bits(effective_bits);

    let mut notes = vec![CAVEAT.to_string()];
    if !uniform_length {
        notes.push(format!(
            "samples have mixed lengths ({min_len}-{max_len} symbols); per-position \
             entropy is disabled and the estimate falls back to pooled per-symbol entropy"
        ));
    }
    if sample_count < 20 {
        notes.push(format!(
            "only {sample_count} sample(s); estimates from fewer than 20 samples are \
             unreliable — collect more before trusting the verdict"
        ));
    }

    SequencerReport {
        sample_count,
        unique_count,
        duplicate_count,
        unique_ratio,
        min_len,
        max_len,
        mean_len,
        charset_size,
        global_entropy_per_symbol,
        per_position_entropy,
        effective_bits,
        quality,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny deterministic LCG so entropy tests are reproducible without a
    /// `rand` dependency (Numerical Recipes constants).
    struct Lcg(u64);
    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
            (self.0 >> 16) as u32
        }
        fn next_hex(&mut self) -> char {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            HEX[(self.next_u32() & 0xf) as usize] as char
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ----- shannon_entropy ------------------------------------------------

    #[test]
    fn shannon_entropy_known_values() {
        assert_eq!(shannon_entropy(&[1, 1]), 1.0);
        assert_eq!(shannon_entropy(&[1, 1, 1, 1]), 2.0);
        assert_eq!(shannon_entropy(&[1]), 0.0);
    }

    #[test]
    fn shannon_entropy_empty_and_zero_tables_are_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0, 0, 0]), 0.0);
        // A lone non-zero bucket (with padding zeros) is still certainty → 0.
        assert_eq!(shannon_entropy(&[0, 5, 0]), 0.0);
    }

    #[test]
    fn shannon_entropy_scales_with_equiprobable_symbols() {
        // n equiprobable symbols → exactly log2(n) bits.
        assert_eq!(shannon_entropy(&[3, 3, 3, 3]), 2.0); // 4 symbols
        assert_eq!(shannon_entropy(&[7, 7, 7, 7, 7, 7, 7, 7]), 3.0); // 8 symbols
                                                                     // Skewed distributions carry less than the uniform maximum.
        assert!(shannon_entropy(&[9, 1]) < 1.0);
        assert!(shannon_entropy(&[9, 1]) > 0.0);
    }

    // ----- empty / degenerate input --------------------------------------

    #[test]
    fn empty_input_is_handled_gracefully() {
        let r = analyze(&[]);
        assert_eq!(r.sample_count, 0);
        assert_eq!(r.unique_count, 0);
        assert_eq!(r.duplicate_count, 0);
        assert_eq!(r.unique_ratio, 0.0);
        assert_eq!(r.effective_bits, 0.0);
        assert_eq!(r.quality, Quality::Poor);
        assert!(r.per_position_entropy.is_empty());
        assert!(r.notes.iter().any(|n| n.contains("statistical estimate")));
        assert!(r.notes.iter().any(|n| n.contains("nothing to analyze")));
    }

    #[test]
    fn all_identical_tokens_score_zero_and_poor() {
        let token = "deadbeefdeadbeefdeadbeefdeadbeef"; // 32 chars, charset {d,e,a,b,f}
        let tokens = vec![token.to_string(); 25];
        let r = analyze(&tokens);

        assert_eq!(r.sample_count, 25);
        assert_eq!(r.unique_count, 1);
        assert_eq!(r.duplicate_count, 24); // count - 1
        assert_eq!(r.min_len, 32);
        assert_eq!(r.max_len, 32);
        assert_eq!(r.charset_size, 5);
        assert!(r.effective_bits.abs() < 1e-9, "effective_bits ~ 0");
        assert_eq!(r.quality, Quality::Poor);
        // Per-position is enabled (uniform length) but every column is constant.
        assert_eq!(r.per_position_entropy.len(), 32);
        assert!(r.per_position_entropy.iter().all(|&e| e == 0.0));
    }

    // ----- realistic good tokens -----------------------------------------

    #[test]
    fn distinct_hex_tokens_have_full_charset_and_higher_entropy() {
        // 64 distinct 32-char lowercase-hex tokens. The first 8 chars encode the
        // index (guaranteeing uniqueness); the rest are LCG-driven hex.
        let mut rng = Lcg(0x1234_5678);
        let mut tokens = Vec::new();
        for i in 0u32..64 {
            let mut t = format!("{i:08x}");
            for _ in 0..24 {
                t.push(rng.next_hex());
            }
            tokens.push(t);
        }
        let r = analyze(&tokens);
        let identical = analyze(&vec!["deadbeefdeadbeefdeadbeefdeadbeef".to_string(); 64]);

        assert_eq!(r.sample_count, 64);
        assert_eq!(r.unique_count, 64);
        assert_eq!(r.unique_ratio, 1.0);
        assert_eq!(r.duplicate_count, 0);
        assert_eq!(r.charset_size, 16, "all 16 hex digits observed");
        assert_eq!(r.min_len, 32);
        assert_eq!(r.max_len, 32);
        assert_eq!(r.per_position_entropy.len(), 32);
        assert!(
            r.effective_bits > identical.effective_bits,
            "distinct tokens must estimate higher than identical ones"
        );
        assert!(r.effective_bits > 1.0);
    }

    // ----- mixed lengths --------------------------------------------------

    #[test]
    fn mixed_length_tokens_disable_per_position_and_note_it() {
        let r = analyze(&strings(&["aaa", "bbbb", "cc"]));
        assert_eq!(r.min_len, 2);
        assert_eq!(r.max_len, 4);
        assert!(
            r.per_position_entropy.is_empty(),
            "mixed lengths disable per-position entropy"
        );
        assert!(r.notes.iter().any(|n| n.contains("mixed length")));
        // Fallback estimator is pooled per-symbol entropy × mean length.
        assert_eq!(r.effective_bits, r.global_entropy_per_symbol * r.mean_len);
    }

    // ----- unique ratio ---------------------------------------------------

    #[test]
    fn unique_ratio_counts_duplicates_correctly() {
        let r = analyze(&strings(&["aa", "aa", "bb"]));
        assert_eq!(r.sample_count, 3);
        assert_eq!(r.unique_count, 2);
        assert_eq!(r.duplicate_count, 1);
        assert!((r.unique_ratio - 2.0 / 3.0).abs() < 1e-12);
    }

    // ----- byte analysis --------------------------------------------------

    #[test]
    fn analyze_bytes_uses_the_byte_alphabet() {
        let samples = vec![vec![0u8, 1, 2], vec![3u8, 4, 5]];
        let r = analyze_bytes(&samples);
        assert_eq!(r.sample_count, 2);
        assert_eq!(r.charset_size, 6); // six distinct byte values
        assert_eq!(r.min_len, 3);
        assert_eq!(r.max_len, 3);
        assert_eq!(r.per_position_entropy.len(), 3);
        // Each of the three columns holds two distinct values → 1 bit each.
        assert_eq!(r.effective_bits, 3.0);
    }

    // ----- quality banding (exact, via two-sample columns) ----------------

    /// Two byte-samples of `len` that differ in exactly the first `diff`
    /// positions. Each differing column is `{0,1}` → exactly 1.0 bit; each equal
    /// column → 0.0 bits. So `effective_bits == diff` exactly.
    fn two_samples_differing(diff: usize, len: usize) -> Vec<Vec<u8>> {
        let a = vec![0u8; len];
        let mut b = vec![0u8; len];
        for byte in b.iter_mut().take(diff) {
            *byte = 1;
        }
        vec![a, b]
    }

    #[test]
    fn effective_bits_equal_differing_column_count() {
        let r = analyze_bytes(&two_samples_differing(40, 130));
        assert_eq!(r.effective_bits, 40.0);
        assert_eq!(r.per_position_entropy.len(), 130);
        assert_eq!(r.per_position_entropy[0], 1.0);
        assert_eq!(r.per_position_entropy[129], 0.0);
    }

    #[test]
    fn quality_bands_map_at_their_thresholds() {
        assert_eq!(
            analyze_bytes(&two_samples_differing(0, 130)).quality,
            Quality::Poor
        );
        assert_eq!(
            analyze_bytes(&two_samples_differing(31, 130)).quality,
            Quality::Poor
        );
        assert_eq!(
            analyze_bytes(&two_samples_differing(32, 130)).quality,
            Quality::Fair
        );
        assert_eq!(
            analyze_bytes(&two_samples_differing(63, 130)).quality,
            Quality::Fair
        );
        assert_eq!(
            analyze_bytes(&two_samples_differing(64, 130)).quality,
            Quality::Good
        );
        assert_eq!(
            analyze_bytes(&two_samples_differing(127, 130)).quality,
            Quality::Good
        );
        assert_eq!(
            analyze_bytes(&two_samples_differing(128, 130)).quality,
            Quality::Excellent
        );
    }

    // ----- notes / honesty ------------------------------------------------

    #[test]
    fn caveat_is_always_present() {
        let r = analyze(&strings(&["abc", "def"]));
        assert!(r
            .notes
            .iter()
            .any(|n| n.contains("not a cryptographic proof")));
    }

    #[test]
    fn small_sample_count_is_flagged() {
        let small = analyze_bytes(&two_samples_differing(10, 20));
        assert!(small.notes.iter().any(|n| n.contains("fewer than 20")));

        // With >= 20 distinct samples the small-sample note is gone.
        let many: Vec<Vec<u8>> = (0u8..30).map(|i| vec![i, i.wrapping_add(1)]).collect();
        let big = analyze_bytes(&many);
        assert!(!big.notes.iter().any(|n| n.contains("fewer than 20")));
    }

    // ----- serialization (reproducible reports, plan §8) ------------------

    #[test]
    fn quality_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&Quality::Poor).unwrap(), "\"poor\"");
        assert_eq!(serde_json::to_string(&Quality::Fair).unwrap(), "\"fair\"");
        assert_eq!(serde_json::to_string(&Quality::Good).unwrap(), "\"good\"");
        assert_eq!(
            serde_json::to_string(&Quality::Excellent).unwrap(),
            "\"excellent\""
        );
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = analyze(&strings(&["abcd", "efgh", "ijkl"]));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"quality\""));
        let back: SequencerReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }
}
