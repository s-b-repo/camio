//! Comparer-class byte and line diffing (plan §8 "Convert / Decoder /
//! Comparer", §7.3 "byte-level diff built in").
//!
//! Two pure comparisons back the Replay response-diff and the Comparer surface:
//!
//!   * [`diff_bytes`] — an O(n) structural summary (equal? shared prefix/suffix,
//!     first differing offset) suitable for binary responses where a line diff
//!     is meaningless.
//!   * [`diff_lines`] — an LCS-based line diff producing a flat
//!     [`LineChange`] list, and [`unified_diff`], which renders that list as
//!     textual `@@` hunks with surrounding context.
//!
//! The results are serde-serializable so they can be saved as evidence and
//! shipped over the MCP server (plan §11). Nothing here canonicalizes or sorts
//! its input — bytes and lines are compared exactly as given.

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// Byte diff
// ---------------------------------------------------------------------------

/// A structural summary of how two byte strings differ. Cheap to compute and
/// meaningful for binary payloads: it reports equality, each length, the length
/// of the shared leading/trailing runs, and the offset of the first difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteDiff {
    /// `true` when the two inputs are byte-for-byte identical.
    pub equal: bool,
    /// Length of the first input.
    pub a_len: usize,
    /// Length of the second input.
    pub b_len: usize,
    /// Number of identical leading bytes.
    pub common_prefix: usize,
    /// Number of identical trailing bytes (never overlapping `common_prefix`).
    pub common_suffix: usize,
    /// Offset of the first differing byte, or `None` when `equal`. When one
    /// input is a strict prefix of the other this is the shorter length.
    pub first_diff_offset: Option<usize>,
}

/// Summarize how two byte strings differ (see [`ByteDiff`]).
pub fn diff_bytes(a: &[u8], b: &[u8]) -> ByteDiff {
    let equal = a == b;
    let min_len = a.len().min(b.len());

    let common_prefix = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count();

    // Shared trailing run, capped so prefix and suffix never overlap.
    let max_suffix = min_len - common_prefix;
    let common_suffix = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .take(max_suffix)
        .take_while(|(x, y)| x == y)
        .count();

    let first_diff_offset = if equal { None } else { Some(common_prefix) };

    ByteDiff {
        equal,
        a_len: a.len(),
        b_len: b.len(),
        common_prefix,
        common_suffix,
        first_diff_offset,
    }
}

// ---------------------------------------------------------------------------
// Line diff
// ---------------------------------------------------------------------------

/// The kind of change a [`LineChange`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineOp {
    /// The line is present, unchanged, in both inputs (listed once).
    Equal,
    /// The line is present only in the second (`b`) input.
    Insert,
    /// The line is present only in the first (`a`) input.
    Delete,
}

/// One line of a [`diff_lines`] result: an operation plus the line's text (the
/// trailing newline is not included).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineChange {
    pub op: LineOp,
    pub line: String,
}

impl LineChange {
    fn new(op: LineOp, line: &str) -> LineChange {
        LineChange {
            op,
            line: line.to_string(),
        }
    }
}

/// Compute a line-oriented diff of `a` against `b` using a longest-common-
/// subsequence alignment. Lines shared by both appear once as [`LineOp::Equal`];
/// lines only in `a` are [`LineOp::Delete`] and lines only in `b` are
/// [`LineOp::Insert`]. Inputs are split on `'\n'` (a trailing newline yields a
/// final empty line, matching Unix text semantics).
pub fn diff_lines(a: &str, b: &str) -> Vec<LineChange> {
    let a_lines: Vec<&str> = a.split('\n').collect();
    let b_lines: Vec<&str> = b.split('\n').collect();
    let n = a_lines.len();
    let m = b_lines.len();

    // lcs[i][j] = LCS length of a_lines[i..] and b_lines[j..].
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a_lines[i] == b_lines[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    let mut out = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a_lines[i] == b_lines[j] {
            out.push(LineChange::new(LineOp::Equal, a_lines[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(LineChange::new(LineOp::Delete, a_lines[i]));
            i += 1;
        } else {
            out.push(LineChange::new(LineOp::Insert, b_lines[j]));
            j += 1;
        }
    }
    while i < n {
        out.push(LineChange::new(LineOp::Delete, a_lines[i]));
        i += 1;
    }
    while j < m {
        out.push(LineChange::new(LineOp::Insert, b_lines[j]));
        j += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Unified diff
// ---------------------------------------------------------------------------

/// One annotated diff entry carrying 1-based source line numbers.
struct Annotated<'a> {
    op: LineOp,
    line: &'a str,
    a_no: Option<usize>,
    b_no: Option<usize>,
}

/// Render a unified diff of `a` against `b` with `context` lines of surrounding
/// context per hunk. Built from [`diff_lines`]; hunks are `@@ -as,ac +bs,bc @@`
/// headers followed by ` `/`-`/`+`-prefixed lines. Returns an empty string when
/// the inputs are identical.
pub fn unified_diff(a: &str, b: &str, context: usize) -> String {
    let changes = diff_lines(a, b);

    // Annotate with 1-based line numbers per side.
    let mut annotated: Vec<Annotated> = Vec::with_capacity(changes.len());
    let (mut a_no, mut b_no) = (0usize, 0usize);
    for ch in &changes {
        let (an, bn) = match ch.op {
            LineOp::Equal => {
                a_no += 1;
                b_no += 1;
                (Some(a_no), Some(b_no))
            }
            LineOp::Delete => {
                a_no += 1;
                (Some(a_no), None)
            }
            LineOp::Insert => {
                b_no += 1;
                (None, Some(b_no))
            }
        };
        annotated.push(Annotated {
            op: ch.op,
            line: &ch.line,
            a_no: an,
            b_no: bn,
        });
    }

    let change_idx: Vec<usize> = annotated
        .iter()
        .enumerate()
        .filter(|(_, e)| e.op != LineOp::Equal)
        .map(|(i, _)| i)
        .collect();
    if change_idx.is_empty() {
        return String::new();
    }

    // Group change indices into hunks, each padded by `context` and merged when
    // their padded ranges touch or overlap.
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    for &ci in &change_idx {
        let lo = ci.saturating_sub(context);
        let hi = (ci + context).min(annotated.len() - 1);
        match hunks.last_mut() {
            Some(last) if lo <= last.1 + 1 => last.1 = last.1.max(hi),
            _ => hunks.push((lo, hi)),
        }
    }

    let mut out = String::new();
    for (lo, hi) in hunks {
        let slice = &annotated[lo..=hi];
        let a_count = slice.iter().filter(|e| e.a_no.is_some()).count();
        let b_count = slice.iter().filter(|e| e.b_no.is_some()).count();
        let a_start = hunk_start(
            slice.iter().filter_map(|e| e.a_no).next(),
            a_count,
            lo,
            &annotated,
            true,
        );
        let b_start = hunk_start(
            slice.iter().filter_map(|e| e.b_no).next(),
            b_count,
            lo,
            &annotated,
            false,
        );

        // Header. `write!` to a String cannot fail; ignore the Result.
        let _ = writeln!(out, "@@ -{a_start},{a_count} +{b_start},{b_count} @@");
        for e in slice {
            let prefix = match e.op {
                LineOp::Equal => ' ',
                LineOp::Delete => '-',
                LineOp::Insert => '+',
            };
            let _ = writeln!(out, "{prefix}{}", e.line);
        }
    }
    out
}

/// The `@@` start field for one side of a hunk. When the hunk contains lines for
/// this side, that is the first such line number. When it does not (a pure
/// insert/delete for the other side), unified-diff convention uses the number of
/// the preceding line (0 at the very start), with a count of 0.
fn hunk_start(
    first_present: Option<usize>,
    count: usize,
    lo: usize,
    annotated: &[Annotated],
    side_a: bool,
) -> usize {
    if let Some(n) = first_present {
        return n;
    }
    debug_assert_eq!(count, 0);
    // Walk back from the hunk start to the last numbered line on this side.
    annotated[..lo]
        .iter()
        .rev()
        .find_map(|e| if side_a { e.a_no } else { e.b_no })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_bytes_equal_inputs() {
        let d = diff_bytes(b"hello", b"hello");
        assert!(d.equal);
        assert_eq!(d.a_len, 5);
        assert_eq!(d.b_len, 5);
        assert_eq!(d.common_prefix, 5);
        assert_eq!(d.common_suffix, 0); // capped: prefix already consumed all
        assert_eq!(d.first_diff_offset, None);
    }

    #[test]
    fn diff_bytes_empty_inputs() {
        let d = diff_bytes(b"", b"");
        assert!(d.equal);
        assert_eq!(d.first_diff_offset, None);
        assert_eq!(d.common_prefix, 0);
        assert_eq!(d.common_suffix, 0);
    }

    #[test]
    fn diff_bytes_middle_change() {
        let d = diff_bytes(b"abcXfg", b"abcYfg");
        assert!(!d.equal);
        assert_eq!(d.common_prefix, 3);
        assert_eq!(d.common_suffix, 2);
        assert_eq!(d.first_diff_offset, Some(3));
    }

    #[test]
    fn diff_bytes_prefix_insert() {
        // "abc" is a strict prefix of "abcd": first diff at the shorter length.
        let d = diff_bytes(b"abc", b"abcd");
        assert!(!d.equal);
        assert_eq!(d.common_prefix, 3);
        assert_eq!(d.common_suffix, 0);
        assert_eq!(d.first_diff_offset, Some(3));
        assert_eq!(d.a_len, 3);
        assert_eq!(d.b_len, 4);
    }

    #[test]
    fn diff_bytes_total_difference() {
        let d = diff_bytes(b"xxx", b"yyy");
        assert!(!d.equal);
        assert_eq!(d.common_prefix, 0);
        assert_eq!(d.common_suffix, 0);
        assert_eq!(d.first_diff_offset, Some(0));
    }

    #[test]
    fn diff_lines_equal() {
        let changes = diff_lines("a\nb\nc", "a\nb\nc");
        assert_eq!(changes.len(), 3);
        assert!(changes.iter().all(|c| c.op == LineOp::Equal));
        assert_eq!(changes[0], LineChange::new(LineOp::Equal, "a"));
    }

    #[test]
    fn diff_lines_pure_insert() {
        // Insert "X" between b and c.
        let changes = diff_lines("a\nb\nc", "a\nb\nX\nc");
        let ops: Vec<LineOp> = changes.iter().map(|c| c.op).collect();
        assert_eq!(
            ops,
            vec![LineOp::Equal, LineOp::Equal, LineOp::Insert, LineOp::Equal]
        );
        let inserted = changes.iter().find(|c| c.op == LineOp::Insert).unwrap();
        assert_eq!(inserted.line, "X");
    }

    #[test]
    fn diff_lines_pure_delete() {
        let changes = diff_lines("a\nb\nc", "a\nc");
        let ops: Vec<LineOp> = changes.iter().map(|c| c.op).collect();
        assert_eq!(ops, vec![LineOp::Equal, LineOp::Delete, LineOp::Equal]);
        let deleted = changes.iter().find(|c| c.op == LineOp::Delete).unwrap();
        assert_eq!(deleted.line, "b");
    }

    #[test]
    fn diff_lines_replace_is_delete_then_insert() {
        let changes = diff_lines("a\nb\nc", "a\nB\nc");
        // Equal a, (delete b / insert B in some order), Equal c.
        assert_eq!(changes.first().unwrap().op, LineOp::Equal);
        assert_eq!(changes.last().unwrap().op, LineOp::Equal);
        assert!(changes
            .iter()
            .any(|c| c.op == LineOp::Delete && c.line == "b"));
        assert!(changes
            .iter()
            .any(|c| c.op == LineOp::Insert && c.line == "B"));
    }

    #[test]
    fn diff_lines_from_empty() {
        // "" splits to one empty line; inserting content keeps the structure sane.
        let changes = diff_lines("", "x");
        assert!(changes
            .iter()
            .any(|c| c.op == LineOp::Insert && c.line == "x"));
    }

    #[test]
    fn unified_diff_identical_is_empty() {
        assert_eq!(unified_diff("a\nb", "a\nb", 3), "");
    }

    #[test]
    fn unified_diff_single_change_hunk() {
        let a = "l1\nl2\nl3\nl4\nl5";
        let b = "l1\nl2\nX\nl4\nl5";
        let diff = unified_diff(a, b, 1);
        let expected = "@@ -2,3 +2,3 @@\n l2\n-l3\n+X\n l4\n";
        assert_eq!(diff, expected);
    }

    #[test]
    fn unified_diff_zero_context_pure_insert() {
        // Insert a line between l1 and l2 with no context.
        let a = "l1\nl2";
        let b = "l1\nX\nl2";
        let diff = unified_diff(a, b, 0);
        // Pure insert after a-line 1: `-1,0`, one added line.
        assert_eq!(diff, "@@ -1,0 +2,1 @@\n+X\n");
    }

    #[test]
    fn unified_diff_merges_nearby_changes_into_one_hunk() {
        let a = "a\nb\nc\nd\ne";
        let b = "a\nB\nc\nD\ne";
        let diff = unified_diff(a, b, 1);
        // The two single-line changes are within 2*context, so one hunk.
        assert_eq!(diff.matches("@@").count(), 2); // one header has two @@ markers
        assert!(diff.contains("-b"));
        assert!(diff.contains("+B"));
        assert!(diff.contains("-d"));
        assert!(diff.contains("+D"));
    }

    #[test]
    fn line_change_serializes_snake_case_and_roundtrips() {
        let change = LineChange::new(LineOp::Insert, "hi");
        let json = serde_json::to_string(&change).unwrap();
        assert_eq!(json, r#"{"op":"insert","line":"hi"}"#);
        let back: LineChange = serde_json::from_str(&json).unwrap();
        assert_eq!(back, change);

        assert_eq!(serde_json::to_string(&LineOp::Equal).unwrap(), r#""equal""#);
        assert_eq!(
            serde_json::to_string(&LineOp::Delete).unwrap(),
            r#""delete""#
        );
    }

    #[test]
    fn byte_diff_serializes_and_roundtrips() {
        let d = diff_bytes(b"abcXfg", b"abcYfg");
        let json = serde_json::to_string(&d).unwrap();
        let back: ByteDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
        assert!(json.contains(r#""first_diff_offset":3"#));
    }
}
