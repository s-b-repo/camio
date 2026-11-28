//! CVSS v3.1 base-score calculator (FIRST.org specification).
//!
//! Turns a vector string such as
//! `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` into the numeric base score
//! (`9.8`) and a qualitative [`Severity`]. Only the **base** metric group is
//! scored; temporal / environmental metrics in the vector are ignored. Pure
//! arithmetic — no I/O — so findings from any source (Nuclei, manual, imported)
//! can be ranked consistently.

use crate::model::Severity;

/// Why a vector string could not be scored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CvssError {
    /// The string did not start with `CVSS:3.0` or `CVSS:3.1`.
    BadPrefix,
    /// A required base metric was absent (e.g. `AV`).
    MissingMetric(&'static str),
    /// A metric had a value outside its allowed set (e.g. `AV:Z`).
    BadMetricValue(String),
}

impl std::fmt::Display for CvssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CvssError::BadPrefix => write!(f, "not a CVSS v3.0/v3.1 vector"),
            CvssError::MissingMetric(m) => write!(f, "missing required base metric {m}"),
            CvssError::BadMetricValue(v) => write!(f, "invalid metric value: {v}"),
        }
    }
}

impl std::error::Error for CvssError {}

/// A scored CVSS v3.1 base vector.
#[derive(Debug, Clone, PartialEq)]
pub struct Cvss {
    /// The base score, `0.0..=10.0`, rounded per the CVSS spec.
    pub base_score: f64,
    /// The qualitative rating for [`Cvss::base_score`].
    pub severity: Severity,
    /// The (trimmed) vector that was scored.
    pub vector: String,
}

impl Cvss {
    /// Parse and score a CVSS v3.0/v3.1 base vector.
    pub fn parse(vector: &str) -> Result<Cvss, CvssError> {
        let base_score = base_score(vector)?;
        Ok(Cvss {
            base_score,
            severity: severity(base_score),
            vector: vector.trim().to_string(),
        })
    }
}

/// Map a CVSS base score to its qualitative severity (CVSS v3.1 §5, Table 14).
pub fn severity(score: f64) -> Severity {
    match score {
        s if s <= 0.0 => Severity::Info,
        s if s < 4.0 => Severity::Low,
        s if s < 7.0 => Severity::Medium,
        s if s < 9.0 => Severity::High,
        _ => Severity::Critical,
    }
}

/// Compute just the numeric base score for a CVSS v3.0/v3.1 vector.
pub fn base_score(vector: &str) -> Result<f64, CvssError> {
    let vector = vector.trim();
    let mut parts = vector.split('/');
    match parts.next() {
        Some("CVSS:3.1") | Some("CVSS:3.0") => {}
        _ => return Err(CvssError::BadPrefix),
    }

    let mut av = None;
    let mut ac = None;
    let mut pr = None;
    let mut ui = None;
    let mut scope_changed = None;
    let mut c = None;
    let mut i = None;
    let mut a = None;

    for part in parts {
        let (key, val) = match part.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        match key {
            "AV" => {
                av = Some(match val {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.20,
                    _ => return Err(CvssError::BadMetricValue(part.to_string())),
                })
            }
            "AC" => {
                ac = Some(match val {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return Err(CvssError::BadMetricValue(part.to_string())),
                })
            }
            // PR weight depends on Scope, so store the raw letter and resolve below.
            "PR" => {
                pr = Some(match val {
                    "N" | "L" | "H" => val,
                    _ => return Err(CvssError::BadMetricValue(part.to_string())),
                })
            }
            "UI" => {
                ui = Some(match val {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return Err(CvssError::BadMetricValue(part.to_string())),
                })
            }
            "S" => {
                scope_changed = Some(match val {
                    "U" => false,
                    "C" => true,
                    _ => return Err(CvssError::BadMetricValue(part.to_string())),
                })
            }
            "C" => c = Some(cia(val, part)?),
            "I" => i = Some(cia(val, part)?),
            "A" => a = Some(cia(val, part)?),
            _ => {} // temporal / environmental / unknown — ignored for the base score
        }
    }

    let av = av.ok_or(CvssError::MissingMetric("AV"))?;
    let ac = ac.ok_or(CvssError::MissingMetric("AC"))?;
    let pr_letter = pr.ok_or(CvssError::MissingMetric("PR"))?;
    let ui = ui.ok_or(CvssError::MissingMetric("UI"))?;
    let scope_changed = scope_changed.ok_or(CvssError::MissingMetric("S"))?;
    let c = c.ok_or(CvssError::MissingMetric("C"))?;
    let i = i.ok_or(CvssError::MissingMetric("I"))?;
    let a = a.ok_or(CvssError::MissingMetric("A"))?;

    // Resolve the PR weight against scope. The letter was validated while parsing,
    // so the fallback below is unreachable *today*; it returns the same error a
    // malformed vector produces rather than panicking on a score computed from
    // input the operator supplied.
    let pr = match (pr_letter, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        other => {
            return Err(CvssError::BadMetricValue(format!(
                "PR:{:?} with scope changed = {}",
                other.0, other.1
            )))
        }
    };

    // Impact sub-score.
    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };

    if impact <= 0.0 {
        return Ok(0.0);
    }

    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Ok(roundup(raw))
}

fn cia(val: &str, part: &str) -> Result<f64, CvssError> {
    Ok(match val {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.00,
        _ => return Err(CvssError::BadMetricValue(part.to_string())),
    })
}

/// CVSS v3.1 "Roundup": round *up* to one decimal place, with the spec's
/// integer trick so that e.g. `4.02` → `4.1` but an exact `4.0` stays `4.0`.
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        base_score(v).unwrap()
    }

    #[test]
    fn known_vectors_match_first_org() {
        // Canonical examples from the CVSS v3.1 specification / calculator.
        assert!((score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") - 9.8).abs() < 1e-9);
        assert!((score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") - 10.0).abs() < 1e-9);
        assert!((score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") - 5.3).abs() < 1e-9);
        // No impact at all → 0.0 regardless of exploitability.
        assert!((score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") - 0.0).abs() < 1e-9);
    }

    #[test]
    fn scope_changed_uses_higher_pr_weight() {
        // Same metrics except Scope; Changed must score >= Unchanged.
        let u = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
        let c = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
        assert!(c > u, "scope-changed {c} should exceed unchanged {u}");
    }

    #[test]
    fn cvss_30_prefix_is_accepted() {
        assert!(base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_ok());
    }

    #[test]
    fn severity_bands() {
        assert_eq!(severity(0.0), Severity::Info);
        assert_eq!(severity(3.9), Severity::Low);
        assert_eq!(severity(4.0), Severity::Medium);
        assert_eq!(severity(6.9), Severity::Medium);
        assert_eq!(severity(7.0), Severity::High);
        assert_eq!(severity(8.9), Severity::High);
        assert_eq!(severity(9.0), Severity::Critical);
        assert_eq!(severity(10.0), Severity::Critical);
    }

    #[test]
    fn parse_roundtrips_and_rates() {
        let c = Cvss::parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((c.base_score - 9.8).abs() < 1e-9);
        assert_eq!(c.severity, Severity::Critical);
        assert!(c.vector.starts_with("CVSS:3.1/"));
    }

    #[test]
    fn errors_are_reported() {
        assert_eq!(base_score("nope"), Err(CvssError::BadPrefix));
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
            Err(CvssError::MissingMetric("A"))
        );
        assert!(matches!(
            base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Err(CvssError::BadMetricValue(_))
        ));
    }
}
