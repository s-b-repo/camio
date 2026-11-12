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

pub mod camioql;
pub mod fingerprint;
pub mod matchreplace;
pub mod model;
pub mod policy;
pub mod scope;
pub mod sitemap;

pub use fingerprint::{
    FingerprintPolicy, FingerprintProfile, MediaDeviceMode, Persona, PrefValue, RefererPolicy,
    ScreenSize, WebRtcMode, WebglMode, ALIGNED_FIREFOX_MAJOR,
};

pub use camioql::{Query, QueryTarget};
pub use matchreplace::{Find, MatchReplaceRule, RuleSet, Target as MatchTarget};
pub use model::{
    Body, Confidence, ExchangeId, Finding, FindingId, Header, HeaderList, HttpExchange,
    HttpRequest, HttpResponse, HttpVersion, Project, ProjectId, ScopeDecision, Severity, Source,
    Target, Task, TaskId, TaskState, Timings,
};
pub use policy::{ActionClass, Policy, PolicyOutcome};
pub use scope::{Scope, ScopeRule};
pub use sitemap::{SiteMap, SiteNode};
