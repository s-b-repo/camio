//! AI-safe chain authorization — wraps a materialized chain in a binding
//! check so a rogue model cannot repoint a step at an unauthorized host.
//!
//! Workflow (server side):
//!
//! 1. The AI submits a [`Chain`] spec by value (through MCP, the CLI, or
//!    a workflow runner).
//! 2. The server calls [`authorize_chain_steps`] with the live
//!    [`SessionBinding`] and [`SessionKey`]. That function:
//!    * verifies the binding tag,
//!    * materializes the chain,
//!    * checks every substituted step URL is one of the binding's
//!      authorized hosts,
//!    * returns the `Vec<MaterializedStep>` ready to send.
//! 3. The chain runner may still refuse individual steps via
//!    [`crate::chain::materialize`] errors or the scope gate; the guard
//!    is **additional** to those checks, not a replacement.
//!
//! Crucially this check is re-run on each extractor-produced variable: a
//! chain can extract `${next}` from a response, but if `next` points at a
//! host the binding never authorized, the step is refused — the guard
//! stops data-flow attacks where a compromised server tries to redirect
//! the AI at a fresh target.

use crate::chain::{materialize, Chain, ChainError, ChainState, MaterializedStep};
use camio_core::ai_guard::{target_authorized, verify_binding, AiGuardError, SessionKey};
use camio_core::SessionBinding;

/// Errors from AI-mediated chain execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiChainError {
    Guard(AiGuardError),
    Chain(ChainError),
}

impl std::fmt::Display for AiChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AiChainError::Guard(e) => write!(f, "ai-chain guard: {e}"),
            AiChainError::Chain(e) => write!(f, "ai-chain build: {e}"),
        }
    }
}

impl std::error::Error for AiChainError {}

impl From<AiGuardError> for AiChainError {
    fn from(e: AiGuardError) -> Self {
        AiChainError::Guard(e)
    }
}
impl From<ChainError> for AiChainError {
    fn from(e: ChainError) -> Self {
        AiChainError::Chain(e)
    }
}

/// Verify the binding, materialize the chain, and check every emitted
/// step's URL against the binding's authorized target hashes. Returns the
/// list of ready-to-send steps.
///
/// The returned steps are already filtered to those whose target is
/// authorized; a step whose URL is not authorized causes the whole
/// operation to fail with [`AiGuardError::TargetNotAuthorized`] — the
/// server never partially runs a chain that a rogue AI tried to escape.
pub fn authorize_chain_steps(
    chain: &Chain,
    state: &ChainState,
    binding: &SessionBinding,
    key: &SessionKey,
) -> Result<Vec<MaterializedStep>, AiChainError> {
    verify_binding(binding, key)?;
    let steps = materialize(chain, state)?;
    for s in &steps {
        if !target_authorized(binding, &s.request.url)? {
            return Err(AiChainError::Guard(AiGuardError::TargetNotAuthorized(
                s.request.url.clone(),
            )));
        }
    }
    Ok(steps)
}

/// Variant used when a step's response has fed an extractor-sourced
/// variable into [`ChainState`] — re-checks a single new URL against the
/// binding before the chain runner sends it. Call this between steps so a
/// compromised response can't redirect the chain at an unauthorized host.
pub fn authorize_next_url(
    url: &str,
    binding: &SessionBinding,
    key: &SessionKey,
) -> Result<(), AiChainError> {
    verify_binding(binding, key)?;
    if !target_authorized(binding, url)? {
        return Err(AiChainError::Guard(AiGuardError::TargetNotAuthorized(
            url.to_string(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Chain, ChainStep, Extractor};
    use crate::payloads::PayloadSet;
    use camio_core::ai_guard::{bind_session, SessionKey};
    use camio_core::policy::ActionClass;
    use camio_core::{HttpRequest, ScopeRule};

    fn key() -> SessionKey {
        SessionKey::from_bytes([7u8; 32])
    }

    fn binding_for(hosts: &[&str]) -> SessionBinding {
        let targets: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        bind_session(
            "ai-s1",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &targets,
            &[ActionClass::Read, ActionClass::Mutating],
            0,
            &key(),
        )
        .unwrap()
    }

    #[test]
    fn authorized_chain_is_returned_in_full() {
        let b = binding_for(&["https://example.com"]);
        let chain = Chain::new()
            .push(ChainStep::new(
                "one",
                HttpRequest::get("https://example.com/a"),
            ))
            .push(ChainStep::new(
                "two",
                HttpRequest::get("https://example.com/b"),
            ));
        let steps = authorize_chain_steps(&chain, &ChainState::new(), &b, &key()).unwrap();
        assert_eq!(steps.len(), 2);
    }

    #[test]
    fn unauthorized_host_refuses_the_whole_chain() {
        let b = binding_for(&["https://example.com"]);
        let chain = Chain::new()
            .push(ChainStep::new(
                "one",
                HttpRequest::get("https://example.com/a"),
            ))
            .push(ChainStep::new(
                "two",
                HttpRequest::get("https://evil.test/b"),
            ));
        let err = authorize_chain_steps(&chain, &ChainState::new(), &b, &key()).unwrap_err();
        assert!(matches!(
            err,
            AiChainError::Guard(AiGuardError::TargetNotAuthorized(_))
        ));
    }

    #[test]
    fn tampered_binding_rejected() {
        let mut b = binding_for(&["https://example.com"]);
        b.tag.replace_range(..4, "dead");
        let chain = Chain::new().push(ChainStep::new(
            "x",
            HttpRequest::get("https://example.com/a"),
        ));
        let err = authorize_chain_steps(&chain, &ChainState::new(), &b, &key()).unwrap_err();
        assert!(matches!(err, AiChainError::Guard(AiGuardError::InvalidTag)));
    }

    #[test]
    fn next_url_check_blocks_extractor_redirect() {
        let b = binding_for(&["https://example.com"]);
        authorize_next_url("https://example.com/path", &b, &key()).unwrap();
        let err = authorize_next_url("https://evil.test/", &b, &key()).unwrap_err();
        assert!(matches!(
            err,
            AiChainError::Guard(AiGuardError::TargetNotAuthorized(_))
        ));
    }

    #[test]
    fn chain_with_variable_url_still_checks_the_substituted_value() {
        let b = binding_for(&["https://example.com"]);
        let mut state = ChainState::new();
        // The AI might try to feed a rogue value into the state and hope
        // the substitution is unchecked. The authorize call must catch it.
        state.insert("next".into(), "https://evil.test/".into());
        let chain = Chain::new().push(ChainStep::new("two", HttpRequest::get("${next}")));
        let err = authorize_chain_steps(&chain, &state, &b, &key()).unwrap_err();
        assert!(matches!(
            err,
            AiChainError::Guard(AiGuardError::TargetNotAuthorized(_))
        ));
    }

    #[test]
    fn empty_payloads_bubble_the_chain_error() {
        let b = binding_for(&["https://example.com"]);
        let chain = Chain::new().push(
            ChainStep::new("bad", HttpRequest::get("https://example.com/?q=${payload}"))
                .with_payloads(PayloadSet::new("empty", vec![])),
        );
        let err = authorize_chain_steps(&chain, &ChainState::new(), &b, &key()).unwrap_err();
        assert!(matches!(
            err,
            AiChainError::Chain(ChainError::MissingPayloads(_))
        ));
    }

    #[test]
    fn extractor_still_present_after_authorization() {
        // Making sure authorization doesn't drop extractors — a runner
        // relies on them to populate ChainState for later steps.
        let b = binding_for(&["https://example.com"]);
        let chain = Chain::new().push(
            ChainStep::new("one", HttpRequest::get("https://example.com/login")).with_extractor(
                Extractor::Cookie {
                    name: "sess".into(),
                    var: "session".into(),
                },
            ),
        );
        let steps = authorize_chain_steps(&chain, &ChainState::new(), &b, &key()).unwrap();
        assert_eq!(steps.len(), 1);
    }
}
