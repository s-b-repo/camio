//! The shared authorization policy (plan §16: "one shared authorization/scope/
//! rate/confirmation/audit policy for UI, MCP, plugins, automation, and the
//! request engine"). The UI, the MCP server, and (later) plugins all route
//! mutating actions through [`Policy::gate`] so none of them can bypass scope or
//! the confirmation requirement.

use crate::model::ScopeDecision;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
