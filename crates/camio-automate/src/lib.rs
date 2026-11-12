//! `camio-automate` — Intruder-class fuzzing primitives (plan §8 "Automate"
//! row: "payload positions/sources/attack modes, … results table/filters";
//! plan §10 "Automatic input discovery and test matrix").
//!
//! This crate is **pure and offline**: it turns a marked base request and some
//! payload sets into concrete requests, and classifies the results that come
//! back. It never sends anything itself — the caller sends the generated
//! requests through the fingerprint-matched, policy-gated engine
//! (`camio-request`), which enforces scope, rate, and confirmation (plan §16).
//!
//! The pieces, mirroring Burp's Intruder but under Camio's one roof:
//!
//! * [`positions`] — `§…§` insertion points: [`find_positions`], [`strip_markers`].
//! * [`payloads`] — [`PayloadSet`]s and small curated [`builtin_pack`]s.
//! * [`campaign`] — [`AttackType`]s, [`count_requests`], bounded [`plan`]ning
//!   with a projected request count, and [`generate`].
//! * [`classify`] — [`Baseline`] comparison and flagged [`ClassifiedResult`]s.
//! * [`discover`] — [`discover_inputs`] enumerates a request's injectable inputs.
//!
//! ## Safety
//!
//! Everything here is for **authorized testing only** (plan §2). Campaigns are
//! bounded: [`plan`] reports the projected request count so the operator can
//! approve the volume, and [`generate`] refuses to expand past the campaign's
//! budget (plan §10: "show projected request count and get approval"). The
//! built-in payload packs are short, inert, standard probe strings (see
//! [`payloads`]); they are not exploits.

pub mod campaign;
pub mod classify;
pub mod discover;
pub mod payloads;
pub mod positions;

pub use campaign::{
    count_requests, generate, plan, AttackType, Campaign, CampaignPlan, GeneratedRequest,
};
pub use classify::{classify, Baseline, ClassifiedResult};
pub use discover::{discover_inputs, DiscoveredInput, InputKind};
pub use payloads::{builtin_pack, builtin_packs, PayloadSet};
pub use positions::{find_positions, strip_markers, Position, DEFAULT_MARKER};

use std::fmt;

/// Errors from campaign planning and generation.
///
/// `BudgetExceeded` is a deliberate addition to the originally specified set
/// (`NoPositions`, `SetCountMismatch`, `Marker`): the spec requires [`generate`]
/// to error when the projected count exceeds the budget, but listed no budget
/// variant, so a typed one is provided rather than overloading `SetCountMismatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomateError {
    /// The campaign's base request carries no `§…§` insertion points.
    NoPositions,
    /// An attack needs one payload set per position and did not get it.
    SetCountMismatch(String),
    /// A field's markers are unbalanced (an odd number of marker characters).
    Marker(String),
    /// The projected request count exceeds the campaign budget; widen the budget
    /// or narrow the attack (plan §10).
    BudgetExceeded { projected: u64, budget: u64 },
}

impl fmt::Display for AutomateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutomateError::NoPositions => {
                write!(
                    f,
                    "no insertion points: the base request has no '§…§' markers"
                )
            }
            AutomateError::SetCountMismatch(m) => write!(f, "payload set count mismatch: {m}"),
            AutomateError::Marker(m) => write!(f, "marker error: {m}"),
            AutomateError::BudgetExceeded { projected, budget } => write!(
                f,
                "projected {projected} requests exceeds budget {budget}; \
                 widen the budget or narrow the attack"
            ),
        }
    }
}

impl std::error::Error for AutomateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_informative() {
        assert!(AutomateError::NoPositions
            .to_string()
            .contains("no insertion points"));
        assert!(AutomateError::SetCountMismatch("x".into())
            .to_string()
            .contains("set count mismatch"));
        assert!(AutomateError::Marker("x".into())
            .to_string()
            .contains("marker"));
        assert!(AutomateError::BudgetExceeded {
            projected: 9,
            budget: 4
        }
        .to_string()
        .contains("exceeds budget 4"));
    }

    #[test]
    fn error_is_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&AutomateError::NoPositions);
    }

    #[test]
    fn end_to_end_discover_plan_generate_classify() {
        use camio_core::{
            Body, HeaderList, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Source,
        };

        // Discover inputs on a captured request.
        let mut captured = HttpRequest::get("https://shop.test/search?q=shoes");
        captured.headers.push("Cookie", "sid=abc");
        let inputs = discover_inputs(&captured);
        assert!(inputs
            .iter()
            .any(|i| i.kind == InputKind::QueryParam && i.name == "q"));

        // Build and plan a campaign off a marked base.
        let base = HttpRequest::get("https://shop.test/search?q=§shoes§");
        let xss = builtin_pack("xss").unwrap();
        let c = Campaign {
            base,
            attack: AttackType::Sniper,
            sets: vec![xss.clone()],
            budget: Some(100),
        };
        let planned = plan(&c).unwrap();
        assert_eq!(planned.num_positions, 1);
        assert_eq!(planned.projected_requests, xss.len() as u64);

        // Generate and (pretend to) classify one reflected result.
        let gens = generate(&c).unwrap();
        assert_eq!(gens.len(), xss.len());
        let payload = gens[0].payloads[0].clone();
        let resp = HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            reason: None,
            headers: HeaderList::new(),
            body: Body::from_text(format!("results for {payload}")),
        };
        let ex = HttpExchange::new(gens[0].request.clone(), Source::Automate).with_response(resp);
        let classified = classify(&[(gens[0].payloads.clone(), ex)], None, None);
        assert!(classified[0].flags.contains(&"reflected".to_string()));
    }
}
