//! `camio-integrations` — adapters for external security tools (plan §F16).
//!
//! Each adapter is two separable halves: a **pure parser** that normalizes the
//! tool's machine output into Camio's model (unit-tested with fixtures, no tool
//! required), and a **bounded runner** that executes the tool as a subprocess
//! with a timeout and an output cap and feeds the parser. Keeping them apart
//! means the normalization is always testable, and the result becomes searchable
//! project data rather than terminal text.
//!
//! External binaries are strictly optional — a missing tool yields
//! [`IntegrationError::NotInstalled`], never a crash — and the runner enforces
//! Camio's "bounded, cancellable" contract (plan §4.2) at the process boundary.

pub mod httpx;
pub mod nuclei;
pub mod registry;
pub mod subfinder;

pub use registry::{probe_tool, registry, ToolInfo, ToolStatus, KNOWN_TOOLS};

pub use httpx::{
    parse_httpx_jsonl, run_httpx, run_httpx_cancellable, run_httpx_raw,
    summarize as summarize_probe, HttpxOptions, ProbeResult,
};

pub use nuclei::{
    nuclei_to_findings, parse_nuclei_jsonl, run_nuclei, run_nuclei_cancellable, NucleiFinding,
    NucleiOptions,
};
pub use subfinder::{
    parse_subfinder_jsonl, run_subfinder, unique_hosts, Subdomain, SubfinderOptions,
};

use std::fmt;

/// An error from running or parsing an external tool.
#[derive(Debug, Clone)]
pub enum IntegrationError {
    /// The tool binary was not found on `PATH`.
    NotInstalled(String),
    /// The tool failed to start or run.
    Run(String),
    /// Output was produced but could not be used.
    Parse(String),
    /// A binary with the tool's name exists but is not the tool the adapter
    /// drives (e.g. a different `httpx` implementation earlier on `PATH`).
    Incompatible { tool: String, detail: String },
}

impl fmt::Display for IntegrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegrationError::NotInstalled(t) => {
                write!(f, "{t} is not installed or not on PATH")
            }
            IntegrationError::Run(e) => write!(f, "tool run failed: {e}"),
            IntegrationError::Parse(e) => write!(f, "tool output parse failed: {e}"),
            IntegrationError::Incompatible { tool, detail } => {
                write!(f, "{tool} on PATH is incompatible: {detail}")
            }
        }
    }
}

impl std::error::Error for IntegrationError {}

/// Hard cap on captured tool stdout (16 MiB) so a runaway tool can't exhaust
/// memory; output past this is dropped and parsing proceeds on what was kept.
pub(crate) const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
