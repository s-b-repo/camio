//! Insertion points (plan §8 "Automate" row: "payload positions"; plan §10
//! "Automatic input discovery and test matrix").
//!
//! An Intruder-style template marks the spans to fuzz with a pair of marker
//! characters (default `§`, Burp-style). The text between a pair is the
//! *baseline* value — what the request carries when that position is not being
//! varied. These are pure string operations: they locate and strip markers but
//! never send anything (the caller sends via `camio-request`).

use serde::{Deserialize, Serialize};

/// The default insertion-point marker, matching Burp's `§`. Chosen as a
/// non-ASCII character so it rarely collides with real request content; callers
/// that need a different delimiter pass their own to [`find_positions`] /
/// [`strip_markers`].
pub const DEFAULT_MARKER: char = '§';

/// A single insertion point located in a template string.
///
/// `start`/`end` are **byte** offsets into the string the position was found in:
/// `&s[start..end]` is the whole marked span *including both markers*
/// (`§baseline§`), which is exactly the region [`crate::generate`] substitutes a
/// payload into. `baseline` is the text strictly between the two markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// 0-based ordinal of this position within the string (or, in a
    /// [`CampaignPlan`](crate::CampaignPlan), across all fields in field order).
    pub index: usize,
    /// Byte offset of the opening marker.
    pub start: usize,
    /// Byte offset one past the closing marker (exclusive).
    pub end: usize,
    /// The text between the markers — the value sent when this position is held
    /// at baseline.
    pub baseline: String,
}

/// Locate every `marker`-delimited insertion point in `s`, left to right.
///
/// Markers are paired greedily: the 1st with the 2nd, the 3rd with the 4th, and
/// so on. A trailing unpaired marker yields no position (campaign planning in
/// [`crate::plan`] rejects such unbalanced templates up front; this lower-level
/// function stays lenient so it can be used for best-effort highlighting).
pub fn find_positions(s: &str, marker: char) -> Vec<Position> {
    // Byte span (start, end) of each marker occurrence.
    let marks: Vec<(usize, usize)> = s
        .char_indices()
        .filter(|&(_, ch)| ch == marker)
        .map(|(b, ch)| (b, b + ch.len_utf8()))
        .collect();

    let mut positions = Vec::with_capacity(marks.len() / 2);
    let mut index = 0;
    let mut i = 0;
    while i + 1 < marks.len() {
        let (open_start, open_end) = marks[i];
        let (close_start, close_end) = marks[i + 1];
        let baseline = s.get(open_end..close_start).unwrap_or("").to_string();
        positions.push(Position {
            index,
            start: open_start,
            end: close_end,
            baseline,
        });
        index += 1;
        i += 2;
    }
    positions
}

/// Remove every `marker` character from `s`, leaving the baselines in place —
/// the clean base request to send when nothing is being fuzzed.
///
/// With a well-formed (even-marker) template this is exactly the baselines plus
/// any literal text between position pairs; with a malformed one it still drops
/// all markers so no stray delimiter leaks onto the wire.
pub fn strip_markers(s: &str, marker: char) -> String {
    s.chars().filter(|&c| c != marker).collect()
}

/// Count the `marker` characters in `s` (used to reject unbalanced templates).
pub(crate) fn marker_count(s: &str, marker: char) -> usize {
    s.chars().filter(|&c| c == marker).count()
}

/// A single field's positions paired with their campaign-global indices (the
/// ordinal each position occupies across the whole base request). Internal glue
/// used by [`crate::plan`] / [`crate::generate`].
pub(crate) struct FieldPositions {
    pub(crate) positions: Vec<Position>,
    pub(crate) globals: Vec<usize>,
}

impl FieldPositions {
    pub(crate) fn empty() -> Self {
        FieldPositions {
            positions: Vec::new(),
            globals: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_position_at_right_byte_offsets() {
        // `§` is two bytes (0xC2 0xA7), so offsets are byte offsets, not chars.
        let s = "a=§v§";
        let pos = find_positions(s, '§');
        assert_eq!(pos.len(), 1);
        let p = &pos[0];
        assert_eq!(p.index, 0);
        assert_eq!(p.baseline, "v");
        // "a=" is 2 bytes, then the opening `§` starts at byte 2.
        assert_eq!(p.start, 2);
        // whole marked span is `§v§` = 2 + 1 + 2 = 5 bytes, ending at 7.
        assert_eq!(p.end, 7);
        // The span including markers round-trips.
        assert_eq!(&s[p.start..p.end], "§v§");
    }

    #[test]
    fn finds_multiple_positions_in_order() {
        let pos = find_positions("x=§1§&y=§22§&z=§333§", '§');
        assert_eq!(pos.len(), 3);
        assert_eq!(pos[0].baseline, "1");
        assert_eq!(pos[1].baseline, "22");
        assert_eq!(pos[2].baseline, "333");
        assert_eq!(pos[0].index, 0);
        assert_eq!(pos[1].index, 1);
        assert_eq!(pos[2].index, 2);
        // Offsets are strictly increasing and non-overlapping.
        assert!(pos[0].end <= pos[1].start);
        assert!(pos[1].end <= pos[2].start);
    }

    #[test]
    fn empty_baseline_between_adjacent_markers() {
        let pos = find_positions("q=§§", '§');
        assert_eq!(pos.len(), 1);
        assert_eq!(pos[0].baseline, "");
    }

    #[test]
    fn trailing_unpaired_marker_is_ignored() {
        // Three markers: one pair around "a", then a dangling marker.
        let pos = find_positions("§a§b§", '§');
        assert_eq!(pos.len(), 1);
        assert_eq!(pos[0].baseline, "a");
    }

    #[test]
    fn no_markers_yields_no_positions() {
        assert!(find_positions("nothing here", '§').is_empty());
    }

    #[test]
    fn custom_marker_char() {
        let pos = find_positions("id=[FUZZ]x", '[');
        // Only '[' is the marker here, so there is a single '[' — unpaired.
        assert!(pos.is_empty());
        let pos = find_positions("id=#7#", '#');
        assert_eq!(pos.len(), 1);
        assert_eq!(pos[0].baseline, "7");
    }

    #[test]
    fn strip_markers_leaves_baselines() {
        assert_eq!(strip_markers("a=§1§&b=§2§", '§'), "a=1&b=2");
        // Literal text between pairs survives; only markers are removed.
        assert_eq!(strip_markers("§a§b§c§", '§'), "abc");
        // A dangling marker is also removed.
        assert_eq!(strip_markers("§a§b§", '§'), "ab");
        assert_eq!(strip_markers("clean", '§'), "clean");
    }

    #[test]
    fn marker_count_is_accurate() {
        assert_eq!(marker_count("§a§§b§", '§'), 4);
        assert_eq!(marker_count("none", '§'), 0);
        assert_eq!(marker_count("§odd", '§'), 1);
    }

    #[test]
    fn position_serde_roundtrips() {
        let p = Position {
            index: 1,
            start: 2,
            end: 7,
            baseline: "v".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Position = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
