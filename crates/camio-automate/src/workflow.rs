//! Typed, versioned workflow documents (plan §F12).
//!
//! A [`WorkflowDoc`] is an ordered list of named [`Step`]s, each carrying a typed
//! [`Action`]. The serde form (JSON) **is** the versioned text representation the
//! plan calls for: it round-trips losslessly and is reviewable in git. This module
//! owns the document and its [`validate`](WorkflowDoc::validate) pass only — the
//! executor lives in the CLI, where the scope-gated sender and the scan/transform
//! capabilities are already wired (keeping this crate free of a dependency cycle
//! with `camio-active`/`camio-scan`).
//!
//! Validation is pure and total: it never touches the network. It checks that step
//! ids are present and unique, that cross-step references (`on`, and `$id.field`
//! inputs) resolve to an *earlier* step (so a workflow is a forward-only pipeline
//! with no dangling or cyclic references), and that each action's own parameters
//! are well-formed. Execution is only attempted on a document that validates.

use serde::{Deserialize, Serialize};

/// Transform operations a `transform` step may name. These mirror the reusable
/// `camio-convert` transforms the executor dispatches to; kept as a plain list
/// here so document validation stays dependency-light.
pub const KNOWN_TRANSFORM_OPS: &[&str] = &[
    "base64-encode",
    "base64-decode",
    "base32-encode",
    "base32-decode",
    "hex-encode",
    "hex-decode",
    "url-encode",
    "url-decode",
    "html-encode",
    "html-decode",
    "rot13",
];

fn default_version() -> u32 {
    1
}

fn default_method() -> String {
    "GET".to_string()
}

/// A typed, versioned workflow document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowDoc {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: u32,
    pub steps: Vec<Step>,
}

/// One named step: a stable `id` plus its typed action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    #[serde(flatten)]
    pub action: Action,
}

/// The typed action a step performs. The `action` tag selects the variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Send an HTTP request (scope-gated at execution time).
    Request {
        url: String,
        #[serde(default = "default_method")]
        method: String,
        #[serde(default)]
        headers: Vec<String>,
        #[serde(default)]
        body: Option<String>,
    },
    /// Run the passive checks over the response captured by an earlier `request`
    /// step named by `on`.
    PassiveScan { on: String },
    /// Run the active checks against a URL.
    ActiveScan { url: String },
    /// Apply a reusable transform (`op`) to `input`. `input` is a literal, or a
    /// `$step_id.field` reference to an earlier step's output (e.g. `$seed.body`).
    Transform { input: String, op: String },
}

impl Action {
    /// The action's tag, for diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Request { .. } => "request",
            Action::PassiveScan { .. } => "passive_scan",
            Action::ActiveScan { .. } => "active_scan",
            Action::Transform { .. } => "transform",
        }
    }
}

/// If `input` is a `$step_id.field` reference, return `(step_id, field)`; else
/// `None` (a literal). Exposed so the executor resolves references the same way
/// validation checks them.
pub fn parse_reference(input: &str) -> Option<(&str, &str)> {
    let rest = input.strip_prefix('$')?;
    let (id, field) = rest.split_once('.')?;
    if id.is_empty() || field.is_empty() {
        None
    } else {
        Some((id, field))
    }
}

impl WorkflowDoc {
    /// Validate the document. Returns every problem found (not just the first) so
    /// an author can fix them in one pass. `Ok(())` means the document is a
    /// well-formed forward-only pipeline safe to execute.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.name.trim().is_empty() {
            errs.push("workflow name is empty".to_string());
        }
        if self.steps.is_empty() {
            errs.push("workflow has no steps".to_string());
        }

        // Ids defined by steps *before* the current one — a reference is valid
        // only if its target is already in here (forward-only, so no cycles).
        let mut defined: Vec<&str> = Vec::new();
        for (i, step) in self.steps.iter().enumerate() {
            let sid = step.id.trim();
            if sid.is_empty() {
                errs.push(format!("step {i}: empty id"));
            } else if defined.contains(&step.id.as_str()) {
                errs.push(format!("duplicate step id `{}`", step.id));
            }

            match &step.action {
                Action::Request { url, method, .. } => {
                    if url.trim().is_empty() {
                        errs.push(format!("step `{}`: request url is empty", step.id));
                    }
                    if method.trim().is_empty() {
                        errs.push(format!("step `{}`: request method is empty", step.id));
                    }
                }
                Action::PassiveScan { on } => {
                    if on.starts_with('$') {
                        // Common mix-up with the `$id.field` *input* syntax: the
                        // `on` field names a step directly, with no `$` and no
                        // `.field`. Point the author straight at the fix.
                        let suggested = on.trim_start_matches('$').split('.').next().unwrap_or("");
                        let hint = if suggested.is_empty() {
                            String::new()
                        } else {
                            format!(" — did you mean `{suggested}`?")
                        };
                        errs.push(format!(
                            "step `{}`: passive_scan `on` takes a bare step id, not a `$ref`{hint}",
                            step.id
                        ));
                    } else if !defined.contains(&on.as_str()) {
                        errs.push(format!(
                            "step `{}`: passive_scan `on` must name an earlier step; `{on}` is not defined above it",
                            step.id
                        ));
                    }
                }
                Action::ActiveScan { url } => {
                    if url.trim().is_empty() {
                        errs.push(format!("step `{}`: active_scan url is empty", step.id));
                    }
                }
                Action::Transform { input, op } => {
                    if !KNOWN_TRANSFORM_OPS.contains(&op.as_str()) {
                        errs.push(format!(
                            "step `{}`: unknown transform op `{op}` (known: {})",
                            step.id,
                            KNOWN_TRANSFORM_OPS.join(", ")
                        ));
                    }
                    // A `$id.field` input must reference an earlier step.
                    if let Some((ref_id, _)) = parse_reference(input) {
                        if !defined.contains(&ref_id) {
                            errs.push(format!(
                                "step `{}`: transform input references `{ref_id}`, which is not an earlier step",
                                step.id
                            ));
                        }
                    }
                }
            }

            // The id becomes referenceable only for the steps that follow it.
            if !sid.is_empty() {
                defined.push(step.id.as_str());
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Parse a workflow document from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to pretty JSON (the versioned text representation).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(steps: Vec<Step>) -> WorkflowDoc {
        WorkflowDoc {
            name: "wf".into(),
            version: 1,
            steps,
        }
    }

    fn step(id: &str, action: Action) -> Step {
        Step {
            id: id.into(),
            action,
        }
    }

    fn req(url: &str) -> Action {
        Action::Request {
            url: url.into(),
            method: "GET".into(),
            headers: vec![],
            body: None,
        }
    }

    #[test]
    fn a_well_formed_pipeline_validates() {
        let d = doc(vec![
            step("seed", req("https://x.test/")),
            step("scan", Action::PassiveScan { on: "seed".into() }),
            step(
                "enc",
                Action::Transform {
                    input: "$seed.body".into(),
                    op: "base64-encode".into(),
                },
            ),
        ]);
        assert!(d.validate().is_ok(), "{:?}", d.validate());
    }

    #[test]
    fn empty_name_and_no_steps_are_errors() {
        let d = WorkflowDoc {
            name: "  ".into(),
            version: 1,
            steps: vec![],
        };
        let errs = d.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("name is empty")));
        assert!(errs.iter().any(|e| e.contains("no steps")));
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let d = doc(vec![
            step("a", req("https://x.test/")),
            step("a", req("https://x.test/2")),
        ]);
        assert!(d
            .validate()
            .unwrap_err()
            .iter()
            .any(|e| e.contains("duplicate step id `a`")));
    }

    #[test]
    fn a_forward_or_missing_reference_is_rejected() {
        // `scan` references `seed`, which is defined AFTER it — not allowed.
        let d = doc(vec![
            step("scan", Action::PassiveScan { on: "seed".into() }),
            step("seed", req("https://x.test/")),
        ]);
        assert!(d
            .validate()
            .unwrap_err()
            .iter()
            .any(|e| e.contains("not defined above it")));

        // A reference to a step that does not exist at all.
        let d2 = doc(vec![step("scan", Action::PassiveScan { on: "ghost".into() })]);
        assert!(d2.validate().is_err());
    }

    #[test]
    fn a_step_may_not_reference_itself() {
        // Self-reference is a forward reference (id not yet defined) — rejected.
        let d = doc(vec![step(
            "t",
            Action::Transform {
                input: "$t.body".into(),
                op: "rot13".into(),
            },
        )]);
        assert!(d.validate().is_err());
    }

    #[test]
    fn a_dollar_ref_in_passive_on_is_caught_with_a_hint() {
        // `on` takes a bare step id; the `$id.field` syntax belongs to transform
        // `input`. Mixing them up is easy, so the error must name the fix.
        let d = doc(vec![
            step("seed", req("https://x.test/")),
            step("scan", Action::PassiveScan { on: "$seed".into() }),
        ]);
        let errs = d.validate().unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("bare step id") && e.contains("did you mean `seed`?")),
            "{errs:?}"
        );
        // The `.field` form is stripped down to the step id in the suggestion.
        let d2 = doc(vec![
            step("seed", req("https://x.test/")),
            step("scan", Action::PassiveScan { on: "$seed.body".into() }),
        ]);
        assert!(d2
            .validate()
            .unwrap_err()
            .iter()
            .any(|e| e.contains("did you mean `seed`?")));
    }

    #[test]
    fn unknown_transform_op_is_rejected() {
        let d = doc(vec![step(
            "t",
            Action::Transform {
                input: "hello".into(),
                op: "enigma".into(),
            },
        )]);
        assert!(d
            .validate()
            .unwrap_err()
            .iter()
            .any(|e| e.contains("unknown transform op `enigma`")));
    }

    #[test]
    fn parse_reference_distinguishes_literals_from_refs() {
        assert_eq!(parse_reference("$seed.body"), Some(("seed", "body")));
        assert_eq!(parse_reference("$seed.status"), Some(("seed", "status")));
        assert_eq!(parse_reference("literal"), None);
        assert_eq!(parse_reference("$nofield"), None);
        assert_eq!(parse_reference("$.body"), None);
    }

    #[test]
    fn json_round_trips_losslessly() {
        let d = doc(vec![
            step("seed", req("https://x.test/")),
            step("scan", Action::PassiveScan { on: "seed".into() }),
        ]);
        let json = d.to_json();
        let back = WorkflowDoc::from_json(&json).unwrap();
        assert_eq!(d, back);
        // The tagged form is stable/readable.
        assert!(json.contains("\"action\": \"request\""));
        assert!(json.contains("\"action\": \"passive_scan\""));
    }

    #[test]
    fn default_method_and_version_fill_in() {
        let json = r#"{"name":"w","steps":[{"id":"s","action":"request","url":"https://x.test/"}]}"#;
        let d = WorkflowDoc::from_json(json).unwrap();
        assert_eq!(d.version, 1);
        match &d.steps[0].action {
            Action::Request { method, .. } => assert_eq!(method, "GET"),
            other => panic!("expected request, got {}", other.kind()),
        }
    }
}
