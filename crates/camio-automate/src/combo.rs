//! Combined / chained payload generation.
//!
//! "Combo" composition takes payloads from multiple categories and emits new
//! payloads that exercise several sinks in one request. Two modes:
//!
//! * [`ComboMode::Parallel`] — pick index `i` from every set and join with a
//!   separator. Length = min(set lengths), analogous to Pitchfork.
//! * [`ComboMode::CrossProduct`] — Cartesian product of every set joined with
//!   a separator. Length = product of set lengths.
//! * [`ComboMode::Chain`] — concatenate the first payload of every set with a
//!   separator, then move on: `(a0, b0, c0), (a1, b1, c1), …`. Equivalent to
//!   `Parallel` with no `truncate`.
//!
//! The result is a single [`PayloadSet`] named `combo:<a>+<b>+…` so campaigns
//! can treat it as any other pack.

use crate::payloads::PayloadSet;

/// How to combine payloads across categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComboMode {
    /// Pick the same index from every input set. Length = min(set lengths).
    Parallel,
    /// Cartesian product. Length = product of set lengths — cap with `limit`.
    CrossProduct,
    /// Same as `Parallel` but cycles short sets instead of truncating to the
    /// shortest. Length = max(set lengths).
    Chain,
}

/// Compose payloads from `sets` into a single [`PayloadSet`], joining with
/// `separator`, capped to `limit` entries.
///
/// Returns `None` if `sets` is empty or `limit == 0`.
pub fn combo(
    sets: &[PayloadSet],
    mode: ComboMode,
    separator: &str,
    limit: usize,
) -> Option<PayloadSet> {
    if sets.is_empty() || limit == 0 {
        return None;
    }
    let name = format!(
        "combo:{}",
        sets.iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join("+")
    );

    let out: Vec<String> = match mode {
        ComboMode::Parallel => parallel(sets, separator, limit),
        ComboMode::Chain => chain(sets, separator, limit),
        ComboMode::CrossProduct => cross_product(sets, separator, limit),
    };
    Some(PayloadSet::new(name, out))
}

fn parallel(sets: &[PayloadSet], sep: &str, limit: usize) -> Vec<String> {
    let min_len = sets.iter().map(|s| s.payloads.len()).min().unwrap_or(0);
    let n = min_len.min(limit);
    (0..n)
        .map(|i| {
            sets.iter()
                .map(|s| s.payloads[i].as_str())
                .collect::<Vec<_>>()
                .join(sep)
        })
        .collect()
}

fn chain(sets: &[PayloadSet], sep: &str, limit: usize) -> Vec<String> {
    let max_len = sets.iter().map(|s| s.payloads.len()).max().unwrap_or(0);
    let n = max_len.min(limit);
    (0..n)
        .map(|i| {
            sets.iter()
                .map(|s| {
                    let len = s.payloads.len();
                    if len == 0 {
                        ""
                    } else {
                        s.payloads[i % len].as_str()
                    }
                })
                .collect::<Vec<_>>()
                .join(sep)
        })
        .collect()
}

fn cross_product(sets: &[PayloadSet], sep: &str, limit: usize) -> Vec<String> {
    // Emit the Cartesian product in row-major order, stopping at `limit`.
    let mut out: Vec<String> = Vec::new();
    let mut indices = vec![0usize; sets.len()];
    loop {
        // Skip combinations that include an empty set entirely.
        if sets.iter().any(|s| s.payloads.is_empty()) {
            return out;
        }
        let row: Vec<&str> = sets
            .iter()
            .zip(indices.iter())
            .map(|(s, &i)| s.payloads[i].as_str())
            .collect();
        out.push(row.join(sep));
        if out.len() >= limit {
            break;
        }
        // Advance indices (least-significant first).
        let mut i = sets.len();
        let mut carry = true;
        while carry && i > 0 {
            i -= 1;
            indices[i] += 1;
            if indices[i] < sets[i].payloads.len() {
                carry = false;
            } else {
                indices[i] = 0;
                carry = true;
            }
        }
        if carry {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(name: &str, items: &[&str]) -> PayloadSet {
        PayloadSet::new(name, items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn parallel_mode_picks_same_index() {
        let a = set("a", &["a1", "a2", "a3"]);
        let b = set("b", &["b1", "b2"]);
        let r = combo(&[a, b], ComboMode::Parallel, ";", 10).unwrap();
        assert_eq!(r.payloads, vec!["a1;b1", "a2;b2"]);
        assert_eq!(r.name, "combo:a+b");
    }

    #[test]
    fn chain_mode_cycles_short_sets() {
        let a = set("a", &["a1", "a2", "a3"]);
        let b = set("b", &["b1"]);
        let r = combo(&[a, b], ComboMode::Chain, "|", 10).unwrap();
        assert_eq!(r.payloads, vec!["a1|b1", "a2|b1", "a3|b1"]);
    }

    #[test]
    fn cross_product_enumerates_combinations() {
        let a = set("a", &["a1", "a2"]);
        let b = set("b", &["b1", "b2"]);
        let r = combo(&[a, b], ComboMode::CrossProduct, "+", 100).unwrap();
        assert_eq!(r.payloads, vec!["a1+b1", "a1+b2", "a2+b1", "a2+b2"]);
    }

    #[test]
    fn cross_product_respects_limit() {
        let a = set("a", &["a1", "a2", "a3", "a4"]);
        let b = set("b", &["b1", "b2", "b3", "b4"]);
        let r = combo(&[a, b], ComboMode::CrossProduct, ",", 3).unwrap();
        assert_eq!(r.payloads.len(), 3);
    }

    #[test]
    fn empty_sets_return_none() {
        assert!(combo(&[], ComboMode::Parallel, ";", 10).is_none());
        assert!(combo(&[set("a", &["x"])], ComboMode::Parallel, ";", 0).is_none());
    }

    #[test]
    fn name_reflects_inputs_in_order() {
        let r = combo(
            &[set("xss", &["<x>"]), set("sqli", &["'"])],
            ComboMode::Parallel,
            " ",
            10,
        )
        .unwrap();
        assert_eq!(r.name, "combo:xss+sqli");
    }
}
