//! Attack types and bounded campaign planning (plan §8 "Automate" row:
//! "attack modes"; plan §10 "Automatic input discovery and test matrix",
//! "show projected request count and get approval").
//!
//! A [`Campaign`] pairs a base [`HttpRequest`] carrying `§…§` insertion points
//! with payload sets and an [`AttackType`]. [`plan`] reports how many requests
//! it would produce (so the operator can approve the volume before anything is
//! sent, plan §10), and [`generate`] expands it into concrete requests — pure
//! and offline; the caller sends them through the policy-gated request engine.

use crate::payloads::PayloadSet;
use crate::positions::{find_positions, marker_count, FieldPositions, Position, DEFAULT_MARKER};
use crate::AutomateError;
use camio_core::{Body, HeaderList, HttpRequest};
use serde::{Deserialize, Serialize};

/// How payloads are distributed across insertion points (Burp-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    /// One position varies at a time using the first set; all others stay at
    /// baseline.
    Sniper,
    /// The first set's payload is placed in every position at once.
    BatteringRam,
    /// One set per position, iterated in parallel (stops at the shortest set).
    Pitchfork,
    /// One set per position, every combination (cartesian product).
    ClusterBomb,
}

impl AttackType {
    pub fn as_str(self) -> &'static str {
        match self {
            AttackType::Sniper => "sniper",
            AttackType::BatteringRam => "battering_ram",
            AttackType::Pitchfork => "pitchfork",
            AttackType::ClusterBomb => "cluster_bomb",
        }
    }

    /// Whether this attack requires exactly one payload set per position.
    fn needs_one_set_per_position(self) -> bool {
        matches!(self, AttackType::Pitchfork | AttackType::ClusterBomb)
    }
}

/// Projected request count for an attack over `num_positions` positions whose
/// payload sets have the given sizes.
///
/// All arithmetic saturates, so an enormous ClusterBomb reports `u64::MAX`
/// rather than overflowing. Sniper and BatteringRam use only `set_sizes[0]`;
/// Pitchfork and ClusterBomb assume `set_sizes.len() == num_positions` (callers
/// validate this and surface [`AutomateError::SetCountMismatch`] otherwise).
pub fn count_requests(attack: AttackType, num_positions: usize, set_sizes: &[usize]) -> u64 {
    match attack {
        AttackType::Sniper => {
            let first = set_sizes.first().copied().unwrap_or(0) as u64;
            (num_positions as u64).saturating_mul(first)
        }
        AttackType::BatteringRam => set_sizes.first().copied().unwrap_or(0) as u64,
        AttackType::Pitchfork => set_sizes.iter().copied().min().unwrap_or(0) as u64,
        AttackType::ClusterBomb => {
            if set_sizes.is_empty() {
                0
            } else {
                set_sizes
                    .iter()
                    .fold(1u64, |acc, &n| acc.saturating_mul(n as u64))
            }
        }
    }
}

/// A fuzzing campaign: a marked base request, an attack type, the payload sets,
/// and an optional per-campaign request budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Campaign {
    /// Base request carrying `§…§` insertion points in its URL, header values,
    /// and/or UTF-8 body. Positions are enumerated left to right in that field
    /// order (URL, then each header value in order, then body).
    pub base: HttpRequest,
    pub attack: AttackType,
    pub sets: Vec<PayloadSet>,
    /// Maximum requests to generate; `None` is unbounded (discouraged, plan §10).
    pub budget: Option<u64>,
}

/// The outcome of [`plan`]: how big a campaign is before it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignPlan {
    pub num_positions: usize,
    pub projected_requests: u64,
    /// `true` when `projected_requests` fits the campaign's budget (always `true`
    /// with no budget).
    pub within_budget: bool,
    /// Every insertion point, re-indexed 0.. across all fields in field order.
    /// `start`/`end` are byte offsets within the position's own field.
    pub positions: Vec<Position>,
}

/// One expanded request plus the payloads that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedRequest {
    /// The request with all markers resolved (never contains a marker char).
    pub request: HttpRequest,
    /// The distinct payload(s) applied in this request (one for Sniper and
    /// BatteringRam; one per position for Pitchfork and ClusterBomb).
    pub payloads: Vec<String>,
    /// The global position indices that were varied (all of them except for
    /// Sniper, which varies exactly one).
    pub position_indices: Vec<usize>,
}

/// Where in the base request a group of positions was found.
struct Layout {
    url: FieldPositions,
    /// One entry per base header, aligned by index (empty when a header has no
    /// positions).
    headers: Vec<FieldPositions>,
    body: FieldPositions,
    /// Whether the base body was valid UTF-8 (only then can it carry positions).
    body_is_utf8: bool,
    /// The base body as text (empty when not UTF-8), the string positions index.
    body_text: String,
    /// Total positions across all fields.
    total: usize,
}

impl Layout {
    /// Flatten every field's positions into one list, re-indexed 0.. in field
    /// order.
    fn flatten_positions(&self) -> Vec<Position> {
        let mut out = Vec::with_capacity(self.total);
        push_reindexed(&self.url, &mut out);
        for header in &self.headers {
            push_reindexed(header, &mut out);
        }
        push_reindexed(&self.body, &mut out);
        out
    }
}

fn push_reindexed(fp: &FieldPositions, out: &mut Vec<Position>) {
    for (pos, &global) in fp.positions.iter().zip(fp.globals.iter()) {
        out.push(Position {
            index: global,
            start: pos.start,
            end: pos.end,
            baseline: pos.baseline.clone(),
        });
    }
}

/// Locate every insertion point in `base`, assigning each a global index in
/// field order. Rejects a field whose markers are unbalanced, and a base with
/// no positions at all.
fn build_layout(base: &HttpRequest, marker: char) -> Result<Layout, AutomateError> {
    let mut global = 0usize;

    let url = field_positions(&base.url, marker, &mut global)?;

    let mut headers = Vec::with_capacity(base.headers.len());
    for header in base.headers.iter() {
        headers.push(field_positions(&header.value, marker, &mut global)?);
    }

    let (body_is_utf8, body_text, body) = match std::str::from_utf8(base.body.as_bytes()) {
        Ok(text) => {
            let fp = field_positions(text, marker, &mut global)?;
            (true, text.to_string(), fp)
        }
        Err(_) => {
            // A marker on a non-UTF-8 body cannot be resolved. Report it rather
            // than silently dropping positions (or reporting "no insertion
            // points" for a request that visibly has them).
            if marker_count(&String::from_utf8_lossy(base.body.as_bytes()), marker) > 0 {
                return Err(AutomateError::Marker(
                    "the request body is not valid UTF-8, so §…§ markers in the body \
                     cannot be substituted; use a UTF-8 body or move the marker"
                        .to_string(),
                ));
            }
            (false, String::new(), FieldPositions::empty())
        }
    };

    let total = global;
    if total == 0 {
        return Err(AutomateError::NoPositions);
    }

    Ok(Layout {
        url,
        headers,
        body,
        body_is_utf8,
        body_text,
        total,
    })
}

/// Validate one field's markers and find its positions, advancing the global
/// index counter.
fn field_positions(
    s: &str,
    marker: char,
    global: &mut usize,
) -> Result<FieldPositions, AutomateError> {
    if marker_count(s, marker) % 2 != 0 {
        return Err(AutomateError::Marker(format!(
            "unbalanced '{marker}' markers (odd count) in a campaign field"
        )));
    }
    let positions = find_positions(s, marker);
    let n = positions.len();
    let globals = (*global..*global + n).collect();
    *global += n;
    Ok(FieldPositions { positions, globals })
}

/// Validate that the payload sets match what the attack needs.
fn validate_sets(
    attack: AttackType,
    num_positions: usize,
    set_count: usize,
    sets: &[PayloadSet],
) -> Result<(), AutomateError> {
    // A payload containing the marker char would leak a marker onto the wire
    // (and into every derived baseline), breaking the request's invariant.
    for set in sets {
        for payload in &set.payloads {
            if payload.contains(DEFAULT_MARKER) {
                return Err(AutomateError::Marker(format!(
                    "payload set `{}` contains the marker character {} — it would be \
                     substituted again on the wire",
                    set.name, DEFAULT_MARKER
                )));
            }
        }
    }
    if attack.needs_one_set_per_position() && set_count != num_positions {
        return Err(AutomateError::SetCountMismatch(format!(
            "{} needs one payload set per position: {num_positions} positions but {set_count} sets",
            attack.as_str()
        )));
    }
    Ok(())
}

/// Plan a campaign: compute its positions and projected request count without
/// generating anything (plan §10: show the count and get approval first).
pub fn plan(c: &Campaign) -> Result<CampaignPlan, AutomateError> {
    let layout = build_layout(&c.base, DEFAULT_MARKER)?;
    validate_sets(c.attack, layout.total, c.sets.len(), &c.sets)?;

    let set_sizes: Vec<usize> = c.sets.iter().map(|s| s.len()).collect();
    let projected = count_requests(c.attack, layout.total, &set_sizes);
    let within_budget = c.budget.map_or(true, |b| projected <= b);

    Ok(CampaignPlan {
        num_positions: layout.total,
        projected_requests: projected,
        within_budget,
        positions: layout.flatten_positions(),
    })
}

/// Expand a campaign into concrete requests.
///
/// Returns [`AutomateError::NoPositions`] if the base has no markers,
/// [`AutomateError::Marker`] for an unbalanced field,
/// [`AutomateError::SetCountMismatch`] if Pitchfork/ClusterBomb lack one set per
/// position, and [`AutomateError::BudgetExceeded`] if the projected count
/// exceeds the budget (so the caller must widen it, plan §10). On success the
/// returned vector's length equals [`count_requests`] for the same inputs.
pub fn generate(c: &Campaign) -> Result<Vec<GeneratedRequest>, AutomateError> {
    let layout = build_layout(&c.base, DEFAULT_MARKER)?;
    validate_sets(c.attack, layout.total, c.sets.len(), &c.sets)?;

    let set_sizes: Vec<usize> = c.sets.iter().map(|s| s.len()).collect();
    let projected = count_requests(c.attack, layout.total, &set_sizes);
    // A hard ceiling regardless of an explicit budget: `budget: None` must not
    // mean "materialize an unbounded request set in memory" (a ClusterBomb over
    // a large DB category saturates the count and then OOMs the process).
    const HARD_CEILING: u64 = 100_000;
    let effective_budget = c.budget.unwrap_or(HARD_CEILING).min(HARD_CEILING);
    if projected > effective_budget {
        return Err(AutomateError::BudgetExceeded {
            projected,
            budget: effective_budget,
        });
    }

    generate_from(c, 0)
}

/// Like [`generate`] but materializes only the work items from `start` onward.
///
/// This is the resume primitive: a campaign interrupted after `n` requests can
/// be restarted with `start = n` and executes only its unexecuted remainder. It
/// never replays uncertain mutating steps, and the caller's approval binding
/// still covers the plan (any drift changes the plan hash and is refused).
pub fn generate_from(c: &Campaign, start: usize) -> Result<Vec<GeneratedRequest>, AutomateError> {
    let layout = build_layout(&c.base, DEFAULT_MARKER)?;
    validate_sets(c.attack, layout.total, c.sets.len(), &c.sets)?;

    let set_sizes: Vec<usize> = c.sets.iter().map(|s| s.len()).collect();
    let projected = count_requests(c.attack, layout.total, &set_sizes);
    const HARD_CEILING: u64 = 100_000;
    let effective_budget = c.budget.unwrap_or(HARD_CEILING).min(HARD_CEILING);
    if projected > effective_budget {
        return Err(AutomateError::BudgetExceeded {
            projected,
            budget: effective_budget,
        });
    }
    if start as u64 >= projected {
        return Ok(Vec::new());
    }

    let items = build_items(c, layout.total);
    let generated = items
        .into_iter()
        .skip(start)
        .map(|item| GeneratedRequest {
            request: render_request(&c.base, &layout, &item.assign),
            payloads: item.payloads,
            position_indices: item.position_indices,
        })
        .collect();
    Ok(generated)
}

/// The total number of requests this campaign would issue (without generating).
pub fn projected_count(c: &Campaign) -> Result<u64, AutomateError> {
    let layout = build_layout(&c.base, DEFAULT_MARKER)?;
    validate_sets(c.attack, layout.total, c.sets.len(), &c.sets)?;
    let set_sizes: Vec<usize> = c.sets.iter().map(|s| s.len()).collect();
    Ok(count_requests(c.attack, layout.total, &set_sizes))
}

/// One generated request's work order: the per-position substitution plus the
/// reporting metadata.
struct Item {
    /// `assign[g]` is the payload at global position `g`, or `None` for baseline.
    assign: Vec<Option<String>>,
    payloads: Vec<String>,
    position_indices: Vec<usize>,
}

/// Build the per-attack list of substitutions. Set-count preconditions for
/// Pitchfork/ClusterBomb are already enforced by [`validate_sets`].
fn build_items(c: &Campaign, p: usize) -> Vec<Item> {
    match c.attack {
        AttackType::Sniper => {
            let mut items = Vec::new();
            if let Some(set) = c.sets.first() {
                for pos in 0..p {
                    for value in &set.payloads {
                        let mut assign = vec![None; p];
                        assign[pos] = Some(value.clone());
                        items.push(Item {
                            assign,
                            payloads: vec![value.clone()],
                            position_indices: vec![pos],
                        });
                    }
                }
            }
            items
        }
        AttackType::BatteringRam => {
            let mut items = Vec::new();
            if let Some(set) = c.sets.first() {
                for value in &set.payloads {
                    items.push(Item {
                        assign: vec![Some(value.clone()); p],
                        payloads: vec![value.clone()],
                        position_indices: (0..p).collect(),
                    });
                }
            }
            items
        }
        AttackType::Pitchfork => {
            let min = c.sets.iter().map(|s| s.len()).min().unwrap_or(0);
            let mut items = Vec::with_capacity(min);
            // `i` indexes payloads across DIFFERENT sets (`c.sets[j].payloads[i]`),
            // so a plain iterator cannot replace this range index.
            // `i` indexes into DIFFERENT payload sets (`c.sets[j].payloads[i]`), so no
            // single iterator can replace the range index.
            // audit-allow: C1
            #[allow(clippy::needless_range_loop)]
            for i in 0..min {
                let mut assign = vec![None; p];
                let mut payloads = Vec::with_capacity(p);
                for (j, slot) in assign.iter_mut().enumerate() {
                    let value = c.sets[j].payloads[i].clone();
                    *slot = Some(value.clone());
                    payloads.push(value);
                }
                items.push(Item {
                    assign,
                    payloads,
                    position_indices: (0..p).collect(),
                });
            }
            items
        }
        AttackType::ClusterBomb => {
            let sizes: Vec<usize> = c.sets.iter().map(|s| s.len()).collect();
            if sizes.is_empty() || sizes.contains(&0) {
                return Vec::new();
            }
            let mut items = Vec::new();
            let mut idx = vec![0usize; p];
            loop {
                let mut assign = vec![None; p];
                let mut payloads = Vec::with_capacity(p);
                for (j, slot) in assign.iter_mut().enumerate() {
                    let value = c.sets[j].payloads[idx[j]].clone();
                    *slot = Some(value.clone());
                    payloads.push(value);
                }
                items.push(Item {
                    assign,
                    payloads,
                    position_indices: (0..p).collect(),
                });

                // Odometer: the last position varies fastest.
                let mut k = p;
                let mut carried = true;
                while k > 0 {
                    k -= 1;
                    idx[k] += 1;
                    if idx[k] < sizes[k] {
                        carried = false;
                        break;
                    }
                    idx[k] = 0;
                }
                if carried {
                    break;
                }
            }
            items
        }
    }
}

/// Render a base request with one assignment, resolving every marked field.
fn render_request(base: &HttpRequest, layout: &Layout, assign: &[Option<String>]) -> HttpRequest {
    let url = render_field(&base.url, &layout.url, assign, FieldEncoding::Url);

    let mut headers = HeaderList::new();
    for (i, header) in base.headers.iter().enumerate() {
        let value = match layout.headers.get(i) {
            Some(fp) => render_field(&header.value, fp, assign, FieldEncoding::Header),
            None => header.value.clone(),
        };
        headers.push(header.name.clone(), value);
    }

    let body = if layout.body_is_utf8 {
        Body::from_text(render_field(
            &layout.body_text,
            &layout.body,
            assign,
            FieldEncoding::Body,
        ))
    } else {
        base.body.clone()
    };

    HttpRequest {
        method: base.method.clone(),
        url,
        version: base.version,
        headers,
        body,
    }
}

/// Rebuild one field string, substituting a payload (or the baseline) into each
/// of its marked spans. Panic-free: out-of-range slices yield empty strings.
/// How a substituted payload is encoded for the field it lands in (plan §10.2:
/// "Preserve input location/type so mutations round-trip correctly; add
/// per-context encodings").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldEncoding {
    /// Inside the request URL: percent-encode the payload so `#`, `&`, `=` and
    /// `%` cannot silently truncate or re-shape the request the URL re-parser
    /// produces. The wire form then matches the projected probe.
    Url,
    /// A header value: never allow CR/LF through (request splitting).
    Header,
    /// A body field: the payload is sent verbatim (raw SQLi/XSS strings must
    /// arrive intact).
    Body,
}

fn render_field(
    original: &str,
    fp: &FieldPositions,
    assign: &[Option<String>],
    encoding: FieldEncoding,
) -> String {
    let mut out = String::with_capacity(original.len());
    let mut cursor = 0usize;
    for (pos, &global) in fp.positions.iter().zip(fp.globals.iter()) {
        out.push_str(original.get(cursor..pos.start).unwrap_or(""));
        match assign.get(global).and_then(|o| o.as_deref()) {
            Some(payload) => out.push_str(&encode_for_field(payload, encoding)),
            None => out.push_str(&pos.baseline),
        }
        cursor = pos.end;
    }
    out.push_str(original.get(cursor..).unwrap_or(""));
    out
}

/// Percent-encode everything outside the RFC 3986 unreserved set, so a payload
/// cannot inject URL structure (`#fragment`, `&param`, `=value`) by accident.
fn percent_encode_payload(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    for b in payload.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn encode_for_field(payload: &str, encoding: FieldEncoding) -> String {
    match encoding {
        FieldEncoding::Url => percent_encode_payload(payload),
        // A header value carrying CR/LF is a request-splitting attempt; drop
        // the control bytes rather than emit an unbounded header.
        FieldEncoding::Header => payload
            .chars()
            .filter(|c| *c != '\r' && *c != '\n')
            .collect(),
        FieldEncoding::Body => payload.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(name: &str, items: &[&str]) -> PayloadSet {
        PayloadSet::new(name, items.iter().map(|s| s.to_string()).collect())
    }

    /// Base request with two URL positions: `a=§1§` and `b=§2§`.
    fn two_position_base() -> HttpRequest {
        HttpRequest::get("https://example.com/?a=§1§&b=§2§")
    }

    fn campaign(attack: AttackType, sets: Vec<PayloadSet>, budget: Option<u64>) -> Campaign {
        Campaign {
            base: two_position_base(),
            attack,
            sets,
            budget,
        }
    }

    #[test]
    fn count_requests_formulas() {
        assert_eq!(count_requests(AttackType::Sniper, 2, &[3, 2]), 6);
        assert_eq!(count_requests(AttackType::BatteringRam, 2, &[3, 2]), 3);
        assert_eq!(count_requests(AttackType::Pitchfork, 2, &[3, 2]), 2);
        assert_eq!(count_requests(AttackType::ClusterBomb, 2, &[3, 2]), 6);
    }

    #[test]
    fn count_requests_saturates_instead_of_overflowing() {
        let huge = [u32::MAX as usize + 1; 4];
        // Would overflow u64 if multiplied naively; saturates instead.
        assert_eq!(count_requests(AttackType::ClusterBomb, 4, &huge), u64::MAX);
    }

    #[test]
    fn count_matches_generate_len_for_all_attacks() {
        let sets = || vec![set("s0", &["a", "b", "c"]), set("s1", &["x", "y"])];
        for attack in [
            AttackType::Sniper,
            AttackType::BatteringRam,
            AttackType::Pitchfork,
            AttackType::ClusterBomb,
        ] {
            let c = campaign(attack, sets(), None);
            let set_sizes: Vec<usize> = c.sets.iter().map(|s| s.len()).collect();
            let expected = count_requests(attack, 2, &set_sizes);
            let generated = generate(&c).unwrap();
            assert_eq!(
                generated.len() as u64,
                expected,
                "mismatch for {:?}",
                attack
            );
        }
    }

    #[test]
    fn plan_reports_positions_and_projection() {
        let c = campaign(
            AttackType::ClusterBomb,
            vec![set("s0", &["a", "b", "c"]), set("s1", &["x", "y"])],
            None,
        );
        let plan = plan(&c).unwrap();
        assert_eq!(plan.num_positions, 2);
        assert_eq!(plan.projected_requests, 6);
        assert!(plan.within_budget);
        assert_eq!(plan.positions.len(), 2);
        assert_eq!(plan.positions[0].baseline, "1");
        assert_eq!(plan.positions[1].baseline, "2");
        assert_eq!(plan.positions[0].index, 0);
        assert_eq!(plan.positions[1].index, 1);
    }

    #[test]
    fn generated_requests_have_no_markers() {
        let c = campaign(AttackType::Sniper, vec![set("s", &["X"])], None);
        for gen in generate(&c).unwrap() {
            assert!(
                !gen.request.url.contains('§'),
                "marker leaked: {}",
                gen.request.url
            );
        }
    }

    #[test]
    fn sniper_varies_one_position_and_leaves_others_at_baseline() {
        let c = campaign(AttackType::Sniper, vec![set("s", &["PAYLOAD"])], None);
        let gens = generate(&c).unwrap();
        // One payload, two positions -> two requests.
        assert_eq!(gens.len(), 2);

        // Request varying position 0: url carries PAYLOAD for a, baseline 2 for b.
        let first = &gens[0];
        assert_eq!(first.position_indices, vec![0]);
        assert_eq!(first.payloads, vec!["PAYLOAD"]);
        assert_eq!(first.request.url, "https://example.com/?a=PAYLOAD&b=2");

        // Request varying position 1: baseline 1 for a, PAYLOAD for b.
        let second = &gens[1];
        assert_eq!(second.position_indices, vec![1]);
        assert_eq!(second.request.url, "https://example.com/?a=1&b=PAYLOAD");
    }

    #[test]
    fn battering_ram_puts_same_payload_in_all_positions() {
        let c = campaign(AttackType::BatteringRam, vec![set("s", &["Z"])], None);
        let gens = generate(&c).unwrap();
        assert_eq!(gens.len(), 1);
        assert_eq!(gens[0].position_indices, vec![0, 1]);
        assert_eq!(gens[0].request.url, "https://example.com/?a=Z&b=Z");
    }

    #[test]
    fn pitchfork_iterates_sets_in_parallel() {
        let c = campaign(
            AttackType::Pitchfork,
            vec![set("s0", &["a1", "a2", "a3"]), set("s1", &["b1", "b2"])],
            None,
        );
        let gens = generate(&c).unwrap();
        // Stops at the shortest set (2).
        assert_eq!(gens.len(), 2);
        assert_eq!(gens[0].payloads, vec!["a1", "b1"]);
        assert_eq!(gens[0].request.url, "https://example.com/?a=a1&b=b1");
        assert_eq!(gens[1].payloads, vec!["a2", "b2"]);
        assert_eq!(gens[1].request.url, "https://example.com/?a=a2&b=b2");
    }

    #[test]
    fn cluster_bomb_is_cartesian_with_last_position_fastest() {
        let c = campaign(
            AttackType::ClusterBomb,
            vec![set("s0", &["a1", "a2", "a3"]), set("s1", &["b1", "b2"])],
            None,
        );
        let gens = generate(&c).unwrap();
        assert_eq!(gens.len(), 6);
        let urls: Vec<&str> = gens.iter().map(|g| g.request.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://example.com/?a=a1&b=b1",
                "https://example.com/?a=a1&b=b2",
                "https://example.com/?a=a2&b=b1",
                "https://example.com/?a=a2&b=b2",
                "https://example.com/?a=a3&b=b1",
                "https://example.com/?a=a3&b=b2",
            ]
        );
    }

    #[test]
    fn pitchfork_wrong_set_count_errors() {
        let c = campaign(AttackType::Pitchfork, vec![set("only", &["a"])], None);
        assert!(matches!(
            generate(&c),
            Err(AutomateError::SetCountMismatch(_))
        ));
        assert!(matches!(plan(&c), Err(AutomateError::SetCountMismatch(_))));
    }

    #[test]
    fn cluster_bomb_wrong_set_count_errors() {
        let c = campaign(
            AttackType::ClusterBomb,
            vec![set("a", &["1"]), set("b", &["2"]), set("c", &["3"])],
            None,
        );
        assert!(matches!(
            generate(&c),
            Err(AutomateError::SetCountMismatch(_))
        ));
    }

    #[test]
    fn budget_overflow_errors_in_generate_but_not_plan() {
        let c = campaign(
            AttackType::ClusterBomb,
            vec![set("s0", &["a", "b", "c"]), set("s1", &["x", "y"])],
            Some(5),
        );
        // Projected 6 > budget 5.
        match generate(&c) {
            Err(AutomateError::BudgetExceeded { projected, budget }) => {
                assert_eq!(projected, 6);
                assert_eq!(budget, 5);
            }
            other => panic!("expected BudgetExceeded, got {other:?}"),
        }
        // plan does not error; it reports within_budget = false.
        let plan = plan(&c).unwrap();
        assert!(!plan.within_budget);
        assert_eq!(plan.projected_requests, 6);
    }

    #[test]
    fn budget_exactly_met_is_allowed() {
        let c = campaign(
            AttackType::ClusterBomb,
            vec![set("s0", &["a", "b", "c"]), set("s1", &["x", "y"])],
            Some(6),
        );
        assert_eq!(generate(&c).unwrap().len(), 6);
        assert!(plan(&c).unwrap().within_budget);
    }

    #[test]
    fn no_positions_errors() {
        let c = Campaign {
            base: HttpRequest::get("https://example.com/clean"),
            attack: AttackType::Sniper,
            sets: vec![set("s", &["x"])],
            budget: None,
        };
        assert!(matches!(generate(&c), Err(AutomateError::NoPositions)));
        assert!(matches!(plan(&c), Err(AutomateError::NoPositions)));
    }

    #[test]
    fn unbalanced_markers_error() {
        let c = Campaign {
            base: HttpRequest::get("https://example.com/?a=§oops"),
            attack: AttackType::Sniper,
            sets: vec![set("s", &["x"])],
            budget: None,
        };
        assert!(matches!(generate(&c), Err(AutomateError::Marker(_))));
    }

    #[test]
    fn positions_span_url_headers_and_body() {
        let mut base = HttpRequest::get("https://example.com/?u=§url§");
        base.method = "POST".into();
        base.headers.push("X-Test", "h=§hdr§");
        base.headers.push("Accept", "*/*"); // no markers
        base.body = Body::from_text("payload=§body§");
        let c = Campaign {
            base,
            attack: AttackType::BatteringRam,
            sets: vec![set("s", &["Z"])],
            budget: None,
        };

        let plan = plan(&c).unwrap();
        assert_eq!(plan.num_positions, 3);

        let gens = generate(&c).unwrap();
        assert_eq!(gens.len(), 1);
        let req = &gens[0].request;
        assert_eq!(req.url, "https://example.com/?u=Z");
        assert_eq!(req.headers.get("X-Test"), Some("h=Z"));
        // Untouched header preserved exactly.
        assert_eq!(req.headers.get("Accept"), Some("*/*"));
        assert_eq!(req.body.as_text(), "payload=Z");
        // Position order is url, then header, then body.
        assert_eq!(gens[0].position_indices, vec![0, 1, 2]);
    }

    #[test]
    fn header_order_and_casing_preserved_in_generated_requests() {
        let mut base = HttpRequest::get("https://example.com/?x=§1§");
        base.headers.push("X-Lower", "a");
        base.headers.push("User-Agent", "UA");
        base.headers.push("X-Lower", "b"); // duplicate name, kept
        let c = Campaign {
            base,
            attack: AttackType::Sniper,
            sets: vec![set("s", &["P"])],
            budget: None,
        };
        let gens = generate(&c).unwrap();
        let headers = &gens[0].request.headers;
        assert_eq!(headers.0[0].name, "X-Lower");
        assert_eq!(headers.0[0].value, "a");
        assert_eq!(headers.0[1].name, "User-Agent");
        assert_eq!(headers.0[2].name, "X-Lower");
        assert_eq!(headers.0[2].value, "b");
    }

    #[test]
    fn empty_payload_set_sniper_yields_no_requests() {
        // Consistent with count_requests (num_positions * 0 == 0).
        let c = campaign(AttackType::Sniper, vec![set("empty", &[])], None);
        assert_eq!(count_requests(AttackType::Sniper, 2, &[0]), 0);
        assert!(generate(&c).unwrap().is_empty());
    }

    #[test]
    fn attack_type_serde_is_snake_case() {
        let json = serde_json::to_string(&AttackType::ClusterBomb).unwrap();
        assert_eq!(json, "\"cluster_bomb\"");
        let back: AttackType = serde_json::from_str("\"battering_ram\"").unwrap();
        assert_eq!(back, AttackType::BatteringRam);
    }

    #[test]
    fn campaign_and_plan_serde_roundtrip() {
        let c = campaign(
            AttackType::Pitchfork,
            vec![set("s0", &["a"]), set("s1", &["b"])],
            Some(10),
        );
        let json = serde_json::to_string(&c).unwrap();
        let back: Campaign = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);

        let plan = plan(&c).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        let back: CampaignPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }
}

#[cfg(test)]
mod substitution_tests {
    use super::*;
    use crate::PayloadSet;

    fn base(url: &str) -> HttpRequest {
        HttpRequest::get(url)
    }

    fn set(name: &str, payloads: &[&str]) -> PayloadSet {
        PayloadSet::from_lines(name, &payloads.join("\n"))
    }

    #[test]
    fn url_payloads_are_percent_encoded_so_structure_survives() {
        // A payload with `#`/`&`/`=` must not truncate or reshape the request:
        // the wire form has to match the projected probe.
        let campaign = Campaign {
            base: base("https://ex.test/s?q=§x§"),
            attack: AttackType::Sniper,
            sets: vec![set("edge", &["a#b&c=d"])],
            budget: Some(10),
        };
        let generated = generate(&campaign).unwrap();
        assert_eq!(generated.len(), 1);
        let url = &generated[0].request.url;
        assert!(url.contains("q=a%23b%26c%3Dd"), "url was {url}");
        // Re-parsing through the canonical parser must still find exactly one
        // query parameter with the whole payload as its value.
        let parsed = HttpRequest::get(url);
        assert_eq!(parsed.query().as_deref(), Some("q=a%23b%26c%3Dd"));
    }

    #[test]
    fn body_payloads_stay_verbatim() {
        let mut req = base("https://ex.test/");
        req.method = "POST".to_string();
        req.body = Body::from_text("q=§x§");
        let campaign = Campaign {
            base: req,
            attack: AttackType::Sniper,
            sets: vec![set("sqli", &["' OR 1=1--"])],
            budget: Some(10),
        };
        let generated = generate(&campaign).unwrap();
        assert_eq!(
            generated[0].request.body.as_text(),
            "q=' OR 1=1--",
            "body payloads must arrive intact"
        );
    }

    #[test]
    fn a_payload_containing_the_marker_is_refused() {
        let campaign = Campaign {
            base: base("https://ex.test/s?q=§x§"),
            attack: AttackType::Sniper,
            sets: vec![set("evil", &["ok", "§recursive§"])],
            budget: Some(10),
        };
        let err = generate(&campaign).unwrap_err();
        assert!(
            matches!(err, AutomateError::Marker(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn markers_on_a_binary_body_are_reported_not_dropped() {
        let mut req = base("https://ex.test/");
        // § in a non-UTF-8 body cannot be substituted.
        req.body = Body::from_bytes(vec![0xff, 0xfe, 0xc2, 0xa7]);
        let campaign = Campaign {
            base: req,
            attack: AttackType::Sniper,
            sets: vec![set("x", &["a"])],
            budget: Some(10),
        };
        let err = generate(&campaign).unwrap_err();
        assert!(
            matches!(err, AutomateError::Marker(ref m) if m.contains("UTF-8")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn an_unbounded_campaign_is_ceilinged() {
        // budget: None must not mean "materialize an unbounded request set".
        // Two insertion points so ClusterBomb is legal, and 400×400 payloads.
        let campaign = Campaign {
            base: base("https://ex.test/s?a=§x§&b=§y§"),
            attack: AttackType::ClusterBomb,
            sets: vec![set("a", &["a"; 400]), set("b", &["b"; 400])],
            budget: None,
        };
        let err = generate(&campaign).unwrap_err();
        assert!(
            matches!(
                err,
                AutomateError::BudgetExceeded { projected, budget } if projected > budget
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn header_payloads_cannot_inject_crlf() {
        let mut req = base("https://ex.test/");
        req.headers.push("X-Test", "§h§");
        let campaign = Campaign {
            base: req,
            attack: AttackType::Sniper,
            sets: vec![set("crlf", &["a\\r\\nX-Evil: 1"])],
            budget: Some(10),
        };
        let generated = generate(&campaign).unwrap();
        let value = generated[0].request.headers.get("x-test").unwrap();
        assert!(
            !value.contains('\r') && !value.contains('\n'),
            "header was {value:?}"
        );
    }
}

#[cfg(test)]
mod resume_tests {
    use super::*;
    use crate::PayloadSet;

    fn campaign() -> Campaign {
        let set = PayloadSet::from_lines("p", "a\nb\nc");
        Campaign {
            base: HttpRequest::get("https://ex.test/?q=§x§"),
            attack: AttackType::Sniper,
            sets: vec![set],
            budget: Some(10),
        }
    }

    #[test]
    fn generate_from_skips_already_sent_work() {
        let c = campaign();
        let full = generate(&c).unwrap();
        let projected = projected_count(&c).unwrap();
        assert_eq!(full.len() as u64, projected);

        // Resume after the first item: the remainder, in the same order.
        let rest = generate_from(&c, 1).unwrap();
        assert_eq!(rest.len(), full.len() - 1);
        assert_eq!(rest[0].payloads, full[1].payloads);

        // Resuming past the end yields nothing rather than replaying work.
        assert!(generate_from(&c, full.len()).unwrap().is_empty());
        assert!(generate_from(&c, full.len() + 5).unwrap().is_empty());
    }

    #[test]
    fn the_resume_sequence_covers_every_request_exactly_once() {
        let c = campaign();
        let total = projected_count(&c).unwrap() as usize;
        let mut seen: Vec<String> = Vec::new();
        for chunk_start in (0..total).step_by(2) {
            for g in generate_from(&c, chunk_start).unwrap().into_iter().take(2) {
                seen.push(format!("{:?}", g.payloads));
            }
        }
        let all: Vec<String> = generate(&c)
            .unwrap()
            .into_iter()
            .map(|g| format!("{:?}", g.payloads))
            .collect();
        assert_eq!(seen, all, "chunked resume must equal one full run");
    }
}
