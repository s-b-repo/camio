//! `camio-core` — shared types for Camio.
//!
//! This crate holds the dependency-free domain model. Today it centers on the
//! [`fingerprint`] module (plan §6). As the workbench grows, HTTP exchange,
//! scope and finding models land here too so the UI, MCP server, request engine
//! and proxy all agree on one representation (plan §13 "one canonical model").

pub mod fingerprint;

pub use fingerprint::{
    FingerprintPolicy, FingerprintProfile, MediaDeviceMode, Persona, PrefValue, RefererPolicy,
    ScreenSize, WebRtcMode, WebglMode, ALIGNED_FIREFOX_MAJOR,
};
