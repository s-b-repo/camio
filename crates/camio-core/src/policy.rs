//! The shared authorization policy (plan §16: "one shared authorization/scope/
//! rate/confirmation/audit policy for UI, MCP, plugins, automation, and the
//! request engine"). The UI, the MCP server, and (later) plugins all route
//! mutating actions through [`Policy::gate`] so none of them can bypass scope or
//! the confirmation requirement.

use crate::model::{HttpExchange, ScopeDecision};
use crate::scope::Scope;

/// How impactful an action is. Drives confirmation and enablement requirements
/// (plan §10: "Default to safe checks; active/destructive require explicit
/// enablement").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Read-only: queries, inspection. Always allowed in scope.
    Read,
    /// Sends a request / changes state but is not an attack (e.g. Replay).
    Mutating,
    /// Active testing: scanning, fuzzing campaigns.
    Active,
    /// Destructive: credential guessing, writes that can damage the target.
    Destructive,
}

impl ActionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionClass::Read => "read",
            ActionClass::Mutating => "mutating",
            ActionClass::Active => "active",
            ActionClass::Destructive => "destructive",
        }
    }
}

/// The policy posture for a project/session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Allow active checks (scanning, fuzzing). Off by default.
    pub allow_active: bool,
    /// Allow destructive checks. Off by default and gated per target.
    pub allow_destructive: bool,
    /// Require explicit confirmation before executing mutating/active/destructive
    /// actions (plan §11: report preview + require confirmation first).
    pub require_confirmation: bool,
}

impl Policy {
    /// A revision number for this posture, used to bind approvals to the
    /// policy they were granted under (plan §4.3). Any change to the posture
    /// changes the revision, so a stored approval cannot outlive it.
    pub fn revision(&self) -> u32 {
        let mut h: u32 = 0;
        for (i, on) in [
            self.allow_active,
            self.allow_destructive,
            self.require_confirmation,
        ]
        .into_iter()
        .enumerate()
        {
            if on {
                h |= 1 << i;
            }
        }
        h
    }

    /// The safe default: read freely, confirm anything that sends, and keep
    /// active/destructive testing disabled until explicitly enabled.
    pub fn safe() -> Self {
        Policy {
            allow_active: false,
            allow_destructive: false,
            require_confirmation: true,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy::safe()
    }
}

/// The result of gating an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyOutcome {
    /// Proceed.
    Allow,
    /// Blocked; the string explains why (out of scope, disabled class, SSRF).
    Deny(String),
    /// Permitted but a confirmation is required first; the string is the reason
    /// to surface in the preview.
    NeedsConfirmation(String),
}

impl PolicyOutcome {
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyOutcome::Allow)
    }
}

impl Policy {
    /// Decide whether an action of `class` toward a destination with the given
    /// `scope` decision may proceed. `confirmed` is whether the operator has
    /// already approved this specific action.
    ///
    /// Order of checks: the SSRF/scope guard is absolute, then class enablement,
    /// then the confirmation requirement.
    pub fn gate(&self, class: ActionClass, scope: ScopeDecision, confirmed: bool) -> PolicyOutcome {
        // The safety guard is absolute and applies to every non-read action.
        if scope == ScopeDecision::Blocked {
            return PolicyOutcome::Deny("destination blocked by the SSRF/safety guard".to_string());
        }

        if class == ActionClass::Read {
            return PolicyOutcome::Allow;
        }

        // Anything that sends must be in scope.
        if scope != ScopeDecision::InScope {
            return PolicyOutcome::Deny(format!(
                "destination is {} — only in-scope targets may be {}",
                scope.as_str(),
                class.as_str()
            ));
        }

        // Class enablement.
        if class == ActionClass::Destructive && !self.allow_destructive {
            return PolicyOutcome::Deny(
                "destructive testing is disabled; enable it per authorized target".to_string(),
            );
        }
        if class == ActionClass::Active && !self.allow_active {
            return PolicyOutcome::Deny(
                "active testing is disabled; enable it for this project".to_string(),
            );
        }

        // Confirmation requirement.
        if self.require_confirmation && !confirmed {
            return PolicyOutcome::NeedsConfirmation(format!(
                "{} action requires confirmation before executing",
                class.as_str()
            ));
        }

        PolicyOutcome::Allow
    }

    /// Decide an action against a full [`Scope`] (plan §4.3). This is the
    /// authoritative authorization path shared by every entry point: the
    /// SSRF/scope guard wins absolutely, then automated classes require
    /// explicit project targets (an empty include list is not permission to
    /// discover or scan), then class enablement and confirmation apply.
    pub fn gate_action(
        &self,
        class: ActionClass,
        scope: &Scope,
        ex: &HttpExchange,
        confirmed: bool,
    ) -> PolicyOutcome {
        let decision = scope.decide(ex);
        self.gate_action_with(class, scope, decision, confirmed)
    }

    /// [`Policy::gate_action`] with a precomputed scope decision (for callers
    /// already deciding, e.g. iterating many exchanges of one campaign).
    pub fn gate_action_with(
        &self,
        class: ActionClass,
        scope: &Scope,
        decision: ScopeDecision,
        confirmed: bool,
    ) -> PolicyOutcome {
        // The safety guard is absolute and applies to every non-read action.
        if decision == ScopeDecision::Blocked {
            return PolicyOutcome::Deny("destination blocked by the SSRF/safety guard".to_string());
        }

        // Explicit targets are required before automated network tasks.
        if matches!(class, ActionClass::Active | ActionClass::Destructive)
            && !scope.has_explicit_targets()
        {
            return PolicyOutcome::Deny(
                "automated testing requires explicit project targets — add an include rule \
                 to the project scope before running discovery, scans, or campaigns"
                    .to_string(),
            );
        }

        self.gate(class, decision, confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HttpExchange;
    use crate::model::{HttpRequest, Source};
    use crate::scope::ScopeRule;

    fn ex(url: &str) -> HttpExchange {
        HttpExchange::new(HttpRequest::get(url), Source::Automate)
    }

    #[test]
    fn revision_changes_with_posture() {
        assert_ne!(
            Policy::safe().revision(),
            Policy::default().revision().wrapping_add(1)
        );
        let mut p = Policy::safe();
        let base = p.revision();
        p.allow_active = true;
        assert_ne!(p.revision(), base);
    }

    #[test]
    fn automation_requires_explicit_targets() {
        let p = Policy {
            allow_active: true,
            require_confirmation: false,
            ..Policy::safe()
        };
        // Empty include list is not permission to scan (plan §4.3).
        let bare = Scope::new();
        assert!(matches!(
            p.gate_action(
                ActionClass::Active,
                &bare,
                &ex("https://target.test/"),
                true
            ),
            PolicyOutcome::Deny(_)
        ));
        // Exclude-only scope is still no explicit target.
        let excl =
            Scope::new().with_rule(ScopeRule::exclude(r#"req.path.cont:"/logout""#).unwrap());
        assert!(matches!(
            p.gate_action(
                ActionClass::Destructive,
                &excl,
                &ex("https://target.test/"),
                true
            ),
            PolicyOutcome::Deny(_)
        ));
    }

    #[test]
    fn automation_allowed_once_targets_are_explicit() {
        let p = Policy {
            allow_active: true,
            require_confirmation: false,
            ..Policy::safe()
        };
        let scoped =
            Scope::new().with_rule(ScopeRule::include(r#"req.host.cont:"target.test""#).unwrap());
        assert!(p
            .gate_action(
                ActionClass::Active,
                &scoped,
                &ex("https://target.test/a"),
                true
            )
            .is_allow());
    }

    #[test]
    fn guard_wins_over_targets_and_confirmation() {
        let p = Policy {
            allow_active: true,
            require_confirmation: false,
            ..Policy::safe()
        };
        // An include rule matching a loopback host does not unlock it: the
        // SSRF guard beats even an explicit target unless a lab profile opts in.
        let scoped = Scope::new().with_rule(ScopeRule::include("req.host.cont:127").unwrap());
        let outcome = p.gate_action(ActionClass::Active, &scoped, &ex("http://127.0.0.1/"), true);
        assert!(
            matches!(outcome, PolicyOutcome::Deny(ref m) if m.contains("SSRF")),
            "unexpected outcome: {outcome:?}"
        );
    }

    #[test]
    fn lab_profile_can_scan_an_explicit_private_target() {
        let p = Policy {
            allow_active: true,
            require_confirmation: false,
            ..Policy::safe()
        };
        let scoped = Scope::new()
            .allowing_private()
            .with_rule(ScopeRule::include(r#"req.host.cont:"127.0.0.1""#).unwrap());
        assert!(p
            .gate_action(
                ActionClass::Active,
                &scoped,
                &ex("http://127.0.0.1:3000/app"),
                true
            )
            .is_allow());
    }

    #[test]
    fn mutating_sends_still_work_without_include_rules() {
        // Manual Replay is not "automated network tasks"; one confirmed send is
        // still permitted by the plain gate.
        let p = Policy::safe();
        let bare = Scope::new();
        assert!(p
            .gate_action(
                ActionClass::Mutating,
                &bare,
                &ex("https://target.test/"),
                true
            )
            .is_allow());
    }

    #[test]
    fn reads_always_allowed_in_or_out_of_scope() {
        let p = Policy::safe();
        assert!(p
            .gate(ActionClass::Read, ScopeDecision::OutOfScope, false)
            .is_allow());
        assert!(p
            .gate(ActionClass::Read, ScopeDecision::InScope, false)
            .is_allow());
    }

    #[test]
    fn blocked_destination_denies_even_reads_context() {
        let p = Policy::safe();
        // A blocked destination denies non-reads outright.
        assert!(matches!(
            p.gate(ActionClass::Mutating, ScopeDecision::Blocked, true),
            PolicyOutcome::Deny(_)
        ));
    }

    #[test]
    fn mutating_in_scope_needs_confirmation_then_allows() {
        let p = Policy::safe();
        assert!(matches!(
            p.gate(ActionClass::Mutating, ScopeDecision::InScope, false),
            PolicyOutcome::NeedsConfirmation(_)
        ));
        assert!(p
            .gate(ActionClass::Mutating, ScopeDecision::InScope, true)
            .is_allow());
    }

    #[test]
    fn out_of_scope_send_denied() {
        let p = Policy::safe();
        assert!(matches!(
            p.gate(ActionClass::Mutating, ScopeDecision::OutOfScope, true),
            PolicyOutcome::Deny(_)
        ));
    }

    #[test]
    fn active_and_destructive_require_enablement() {
        let p = Policy::safe();
        assert!(matches!(
            p.gate(ActionClass::Active, ScopeDecision::InScope, true),
            PolicyOutcome::Deny(_)
        ));
        let p2 = Policy {
            allow_active: true,
            require_confirmation: false,
            ..Policy::safe()
        };
        assert!(p2
            .gate(ActionClass::Active, ScopeDecision::InScope, false)
            .is_allow());
        // Destructive still disabled.
        assert!(matches!(
            p2.gate(ActionClass::Destructive, ScopeDecision::InScope, true),
            PolicyOutcome::Deny(_)
        ));
    }
}
