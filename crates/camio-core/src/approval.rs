//! Approval binding (plan §4.3: "Bind approval to the plan hash, exact target
//! set, action class, tool/template versions, session reference, maximum
//! requests, rates, time limits, and policy revision. Reuse that approval only
//! inside those bounds; changing them invalidates it.").
//!
//! An [`Approval`] is a machine-checkable record of what the operator actually
//! authorized. Everything that materially changes the work is folded into a
//! canonical string that is hashed (sha-256); a candidate plan is allowed only
//! when its hash matches the approval's, its targets are a subset of the
//! approved set, it does not exceed the approved limits, and the approval has
//! not expired. This stops the classic failure mode where an approval granted
//! for one bounded run is reused after the plan, scope, tool, or limits drifted.

use crate::policy::{ActionClass, Policy};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// The exact facts an approval is bound to. Every field that changes what will
/// actually be executed must appear here — a missing field is a hole an
/// approval could be replayed through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSummary {
    /// Normalized, exact target set (`scheme://host[:port]` plus path prefix
    /// where the plan is path-scoped). Order-insensitive; duplicates dropped.
    pub targets: Vec<String>,
    /// The action class the approval covers.
    pub class: ActionClass,
    /// External tool and pinned version (`"nuclei 3.3.0"`, `"httpx 1.6.0"`) or
    /// the reviewed template/module revision, when a tool is involved.
    pub tool: Option<String>,
    /// Session reference used for authenticated runs, when any.
    pub session: Option<String>,
    /// Maximum requests the approval permits.
    pub max_requests: Option<u64>,
    /// Maximum wall-clock seconds the approval permits.
    pub max_seconds: Option<u64>,
    /// Maximum requests per second the approval permits.
    pub rate_per_second: Option<u32>,
    /// The policy posture revision the approval was granted under.
    pub policy_revision: u32,
}

impl PlanSummary {
    /// Build a summary with sorted, deduplicated targets.
    pub fn new(class: ActionClass, targets: Vec<String>) -> Self {
        PlanSummary {
            targets: normalize_targets(targets),
            class,
            tool: None,
            session: None,
            max_requests: None,
            max_seconds: None,
            rate_per_second: None,
            policy_revision: Policy::safe().revision(),
        }
    }

    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    pub fn with_session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    pub fn with_max_requests(mut self, n: u64) -> Self {
        self.max_requests = Some(n);
        self
    }

    pub fn with_max_seconds(mut self, s: u64) -> Self {
        self.max_seconds = Some(s);
        self
    }

    pub fn with_rate(mut self, rps: u32) -> Self {
        self.rate_per_second = Some(rps);
        self
    }

    pub fn with_policy(mut self, policy: &Policy) -> Self {
        self.policy_revision = policy.revision();
        self
    }

    /// The canonical string that is hashed. Targets are sorted and
    /// deduplicated; optional fields use a stable `field=value` framing so a
    /// value can never collide with a field boundary.
    fn canonical(&self) -> String {
        let mut s = String::new();
        s.push_str("targets=");
        s.push_str(&self.targets.join(","));
        s.push('\n');
        s.push_str("class=");
        s.push_str(self.class.as_str());
        s.push('\n');
        s.push_str("tool=");
        s.push_str(self.tool.as_deref().unwrap_or("-"));
        s.push('\n');
        s.push_str("session=");
        s.push_str(self.session.as_deref().unwrap_or("-"));
        s.push('\n');
        s.push_str("max_requests=");
        s.push_str(&opt_u64(self.max_requests));
        s.push('\n');
        s.push_str("max_seconds=");
        s.push_str(&opt_u64(self.max_seconds));
        s.push('\n');
        s.push_str("rate_per_second=");
        s.push_str(&opt_u32(self.rate_per_second));
        s.push('\n');
        s.push_str("policy_revision=");
        s.push_str(&self.policy_revision.to_string());
        s
    }

    /// The sha-256 (hex) of this plan's canonical description.
    pub fn plan_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical().as_bytes());
        hex(&digest)
    }
}

/// An operator approval: a plan hash plus the exact bounds it was granted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// sha-256 of the approved [`PlanSummary`].
    pub plan_hash: String,
    /// The summary that produced `plan_hash`, kept for explicit target/limit
    /// checks and display.
    pub summary: PlanSummary,
    /// When the approval was granted (epoch ms).
    pub granted_at_ms: i64,
    /// Optional expiry (epoch ms); after it the approval is dead.
    pub expires_at_ms: Option<i64>,
    /// Who/what granted it (operator name, UI surface, CLI invocation).
    pub granted_by: Option<String>,
}

impl Approval {
    /// Bind an approval to `summary`, stamped at `granted_at_ms`.
    pub fn bind(summary: PlanSummary, granted_at_ms: i64) -> Self {
        Approval {
            plan_hash: summary.plan_hash(),
            summary,
            granted_at_ms,
            expires_at_ms: None,
            granted_by: None,
        }
    }

    pub fn expiring(mut self, expires_at_ms: i64) -> Self {
        self.expires_at_ms = Some(expires_at_ms);
        self
    }

    pub fn granted_by(mut self, who: impl Into<String>) -> Self {
        self.granted_by = Some(who.into());
        self
    }

    /// Whether `plan` is covered by this approval at `now_ms`.
    ///
    /// Fails closed. The approval is a bound: the candidate must be the same
    /// class, run against targets the approved set covers (a bare
    /// `scheme://host[:port]` approval also covers paths beneath it), stay
    /// within the approved request/time/rate limits, run under the same policy
    /// revision, and use the same tool and session. A plan that is *narrower*
    /// (fewer targets, inside the same limits) is still inside the bound; a
    /// plan that adds a target, raises a limit, or changes the tool, session,
    /// class, or policy is not.
    pub fn allows(&self, plan: &PlanSummary, now_ms: i64) -> Result<(), String> {
        if let Some(exp) = self.expires_at_ms {
            if now_ms > exp {
                return Err("approval has expired".to_string());
            }
        }
        let approved = &self.summary;
        if plan.plan_hash() == self.plan_hash {
            // Fast path: the plan is literally the approved plan.
            return Ok(());
        }
        if plan.class != approved.class {
            return Err(format!(
                "approval covers {} actions, not {}",
                approved.class.as_str(),
                plan.class.as_str()
            ));
        }
        for t in &plan.targets {
            if !approved.targets.iter().any(|a| target_covers(a, t)) {
                return Err(format!(
                    "target {t} is not covered by the approved target set"
                ));
            }
        }
        if plan.max_requests.unwrap_or(u64::MAX) > approved.max_requests.unwrap_or(u64::MAX) {
            return Err("plan requests more attempts than the approval allows".to_string());
        }
        if plan.max_seconds.unwrap_or(u64::MAX) > approved.max_seconds.unwrap_or(u64::MAX) {
            return Err("plan allows more time than the approval allows".to_string());
        }
        if plan.rate_per_second.unwrap_or(u32::MAX) > approved.rate_per_second.unwrap_or(u32::MAX) {
            return Err("plan requests a higher rate than the approval allows".to_string());
        }
        if plan.policy_revision != approved.policy_revision {
            return Err("policy has changed since the approval was granted".to_string());
        }
        if plan.tool != approved.tool {
            return Err("approval was bound to a different tool version".to_string());
        }
        if plan.session != approved.session {
            return Err("approval was bound to a different session".to_string());
        }
        // Everything material matches; the remaining difference is a strictly
        // narrower target set, which stays inside the approved bound.
        Ok(())
    }
}

/// Whether `approved` covers `candidate` at or below its path prefix.
fn target_covers(approved: &str, candidate: &str) -> bool {
    if approved == candidate {
        return true;
    }
    // A bare `scheme://host[:port]` covers every path under it.
    let bare = approved.split('#').next().unwrap_or(approved);
    candidate == bare || candidate.starts_with(&format!("{bare}/"))
}

fn opt_u64(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string())
}

fn opt_u32(v: Option<u32>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string())
}

/// Sort + dedupe targets so plan hashes are order-insensitive.
pub fn normalize_targets(mut targets: Vec<String>) -> Vec<String> {
    targets.sort();
    targets.dedup();
    targets
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Current wall-clock epoch milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> PlanSummary {
        PlanSummary::new(
            ActionClass::Active,
            vec!["https://target.test/".to_string()],
        )
        .with_tool("nuclei 3.3.0")
        .with_max_requests(1_000)
        .with_rate(5)
        .with_max_seconds(600)
        .with_policy(&Policy {
            allow_active: true,
            require_confirmation: false,
            ..Policy::safe()
        })
    }

    #[test]
    fn identical_plans_hash_equal_and_are_allowed() {
        let p = plan();
        assert_eq!(p.plan_hash(), plan().plan_hash());
        let a = Approval::bind(p.clone(), 1_000);
        assert!(a.allows(&plan(), 1_001).is_ok());
    }

    #[test]
    fn target_order_does_not_change_the_hash() {
        let mut a = plan();
        a.targets = normalize_targets(vec![
            "https://b.test/".into(),
            "https://a.test/".into(),
            "https://a.test/".into(),
        ]);
        let mut b = plan();
        b.targets = normalize_targets(vec!["https://a.test/".into(), "https://b.test/".into()]);
        assert_eq!(a.plan_hash(), b.plan_hash());
    }

    #[test]
    fn changed_tool_version_invalidates_the_approval() {
        let a = Approval::bind(plan(), 1_000);
        let drifted = plan().with_tool("nuclei 3.4.0");
        assert!(a.allows(&drifted, 1_001).is_err());
    }

    #[test]
    fn new_target_is_not_covered() {
        let a = Approval::bind(plan(), 1_000);
        let drifted =
            PlanSummary::new(ActionClass::Active, vec!["https://other.test/".to_string()])
                .with_tool("nuclei 3.3.0")
                .with_max_requests(1_000)
                .with_rate(5)
                .with_max_seconds(600)
                .with_policy(&Policy {
                    allow_active: true,
                    require_confirmation: false,
                    ..Policy::safe()
                });
        let err = a.allows(&drifted, 1_001).unwrap_err();
        assert!(err.contains("not covered"), "unexpected error: {err}");
    }

    #[test]
    fn larger_limits_are_rejected() {
        let a = Approval::bind(plan(), 1_000);
        let bigger = plan().with_max_requests(5_000);
        let err = a.allows(&bigger, 1_001).unwrap_err();
        assert!(err.contains("attempts"), "unexpected error: {err}");
        let faster = plan().with_rate(50);
        assert!(a.allows(&faster, 1_001).is_err());
        let longer = plan().with_max_seconds(9_999);
        assert!(a.allows(&longer, 1_001).is_err());
    }

    #[test]
    fn class_downgrade_is_rejected_with_a_reason() {
        let a = Approval::bind(plan(), 1_000);
        let mut downgraded = plan();
        downgraded.class = ActionClass::Destructive;
        let err = a.allows(&downgraded, 1_001).unwrap_err();
        assert!(err.contains("active"), "unexpected error: {err}");
    }

    #[test]
    fn expired_approval_is_dead() {
        let a = Approval::bind(plan(), 1_000).expiring(2_000);
        assert!(a.allows(&plan(), 1_500).is_ok());
        assert!(a.allows(&plan(), 2_001).is_err());
    }

    #[test]
    fn policy_change_invalidates() {
        let a = Approval::bind(plan(), 1_000);
        let stricter = plan().with_policy(&Policy::safe());
        assert!(a.allows(&stricter, 1_001).is_err());
    }

    #[test]
    fn bare_host_approval_covers_subpaths() {
        let a = Approval::bind(
            PlanSummary::new(ActionClass::Active, vec!["https://target.test".to_string()]),
            1_000,
        );
        let sub = PlanSummary::new(
            ActionClass::Active,
            vec!["https://target.test/app/login".to_string()],
        );
        assert!(a.allows(&sub, 1_001).is_ok());
    }
}
