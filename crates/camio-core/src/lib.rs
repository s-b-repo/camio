//! `camio-core` — the shared domain model and query language for Camio.
//!
//! This crate is the single source of truth every other component agrees on
//! (plan §13, §16):
//!
//! * [`model`] — the canonical [`HttpExchange`](model::HttpExchange), project,
//!   scope-decision, finding and task types. Raw bytes and structured views are
//!   kept separate; header order and casing are preserved on the wire.
//! * [`camioql`] — CamioQL, the HTTPQL-compatible query language used for
//!   search, filtering, scope, intercept and workflows (plan §7.1).
//! * [`scope`] — the one scope-decision path, CamioQL-backed, with an SSRF guard
//!   that runs first and always wins.
//! * [`fingerprint`] — anti-detection fingerprint profiles/policy for the
//!   managed Camoufox browser and the matched request engine (plan §6).

pub mod ai_guard;
pub mod ai_tools;
pub mod approval;
pub mod camioql;
pub mod cvss;
pub mod fingerprint;
pub mod matchreplace;
pub mod model;
pub mod policy;
pub mod rate;
pub mod rng;
pub mod sbom;
pub mod scope;
pub mod secretbox;
pub mod sitemap;
pub mod sync;
pub mod user_agent;

pub use fingerprint::{
    AudioMode, BrowserOs, CanvasMode, ClientHintsMode, FingerprintPolicy, FingerprintProfile,
    FontMode, MediaDeviceMode, Persona, PrefValue, RefererPolicy, ScreenSize, WebRtcMode,
    WebglMode, ALIGNED_FIREFOX_MAJOR,
};
pub use rng::SplitMix64;
pub use user_agent::{
    random_user_agent, random_user_agent_for, random_user_agent_from_entropy, BrowserFamily,
    UaOs, UserAgent, UserAgentRotator,
};

pub use ai_guard::{
    action_allowed, authorize_findings, bind_session, bind_session_with_integrity,
    default_integrity_paths, integrity_manifest_hash, target_authorized,
    verify_and_authorize_action, verify_and_authorize_target, verify_binding, verify_integrity,
    AiGuardError, SessionBinding, SessionKey,
};
pub use ai_tools::{
    default_catalog, resolve_tool_call, ResolveRequest, ToolCatalog, ToolResolution, ToolSpec,
    ToolSuggestion,
};
pub use approval::{normalize_targets, Approval, PlanSummary};
pub use camioql::{Query, QueryTarget};
pub use cvss::{Cvss, CvssError};
pub use matchreplace::{Find, MatchReplaceRule, RuleSet, Target as MatchTarget};
pub use model::{
    resolve_redirect, Body, Confidence, ExchangeId, Finding, FindingId, Header, HeaderList,
    HttpExchange, HttpRequest, HttpResponse, HttpVersion, Project, ProjectId, ScopeDecision,
    Severity, Source, Target, Task, TaskId, TaskState, Timings,
};
pub use policy::{ActionClass, Policy, PolicyOutcome};
pub use rate::RateLimiter;
pub use scope::{Scope, ScopeRule};
pub use secretbox::{SecretboxError, DEFAULT_PBKDF2_ITERS};
pub use sitemap::{SiteMap, SiteNode};
pub use sync::{
    describe_panic, expected, note_failure, reap, recovered_lock, try_lock, unpoisoned,
};
