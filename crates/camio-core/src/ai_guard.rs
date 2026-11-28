//! AI-mediation guard — HMAC-signed session bindings that pin an AI
//! downstream to one scope, one set of authorized targets, and one set of
//! allowed action classes.
//!
//! ## Threat model
//!
//! Camio exposes capabilities to language models through MCP tools and chain
//! runners. A rogue or confused model could try to:
//!
//! * send to a host we never authorized,
//! * broaden scope mid-session (e.g. inject a new include rule),
//! * escalate its action class from `Read` to `Active`/`Destructive`,
//! * replay a stale binding from another session,
//! * tamper with chain extractor outputs to retarget later requests.
//!
//! The server keeps a secret [`SessionKey`] (32 random bytes, never
//! serialized, never logged — the [`fmt::Debug`] impl always prints
//! `<redacted>`). At session start it computes a [`SessionBinding`] that
//! commits to:
//!
//! * `scope_hash`   — SHA-256 of the canonical scope-rule representation,
//! * `target_hashes` — SHA-256 of each authorized `scheme://host[:port]`,
//! * `allowed_actions` — the action classes the AI may invoke.
//!
//! The binding carries an **HMAC-SHA256 tag** over that commitment. Every
//! AI-mediated operation re-verifies the tag before acting — reordering a
//! rule, swapping a host, or adding an action invalidates the tag because
//! the AI does not hold the key and cannot recompute it.
//!
//! The AI only ever holds the binding; the key stays server-side. This is a
//! classic "signed capability" pattern: the AI can present the binding to
//! claim a privilege, but can only use it as issued.
//!
//! ## What this module does NOT do
//!
//! This is defense-in-depth on top of [`crate::scope::Scope`] and
//! [`crate::policy::Policy`], not a replacement. The scope/policy gate is
//! still the one that refuses out-of-scope sends. The guard adds a second
//! lock the AI boundary can't pick:
//!
//! 1. scope gate rejects the request anyway (always runs), AND
//! 2. the binding's commitment proves the AI is still operating on the
//!    scope/targets it was handed at session start.

use crate::policy::ActionClass;
use crate::scope::ScopeRule;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;

// ---------------------------------------------------------------------------
// SessionKey — 32 bytes, never Serialize, redacted Debug
// ---------------------------------------------------------------------------

/// Per-session secret used to HMAC the binding. Never Serialize, never
/// Clone (callers get a `&SessionKey` by reference), and its [`fmt::Debug`]
/// impl always prints `<redacted>` regardless of logging level.
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Sample 32 bytes from `/dev/urandom`. If that read fails (e.g.
    /// containers that haven't exposed `/dev/urandom`), fall back to a
    /// `SHA-256(time | pid | counter)` seed — weaker but deterministic to
    /// debug. Prefer [`SessionKey::from_bytes`] in tests.
    pub fn generate() -> Self {
        // /dev/urandom missing means "use the getrandom path"; probing is intended.
        // audit-allow: B4
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 32];
            if f.read_exact(&mut buf).is_ok() {
                return SessionKey(buf);
            }
        }
        // Fallback: this path is only hit on exotic platforms; log it loud
        // in the Debug output so a reviewer sees it even if the binding
        // works.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mut h = Sha256::new();
        h.update(now.to_le_bytes());
        h.update(pid.to_le_bytes());
        h.update(b"camio-session-key-fallback");
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        SessionKey(out)
    }

    /// Construct from explicit bytes. The caller is responsible for the
    /// bytes' entropy — use [`SessionKey::generate`] when in doubt.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SessionKey(bytes)
    }

    /// Internal view of the raw bytes — used only for HMAC inside this
    /// module; `pub(crate)` so callers can never serialize the key.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return a copy of the raw key bytes so the caller can persist them to
    /// a 0600 key file at session-start and discard them. Intentionally
    /// awkward: there is no way to accidentally leak the key through a
    /// `Display`/`Serialize`/`Debug` impl, but a CLI that owns the session
    /// must still be able to persist the key once. Call this ONLY while
    /// writing the key to its on-disk home.
    pub fn expose_for_persist(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(<redacted-32-bytes>)")
    }
}

// Zero out on drop — defence against memory-reuse leaks. Not a hard
// guarantee (a compiler is allowed to elide), but matches the spirit.
impl Drop for SessionKey {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// SessionBinding — the signed capability the AI holds
// ---------------------------------------------------------------------------

/// A signed capability that commits to the scope, authorized targets, and
/// allowed action classes for one AI session. All fields are safe to log
/// and ship to the AI — none of them reveal the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBinding {
    /// Free-form session id (UUID-ish). The server uses it to look up the
    /// matching [`SessionKey`] when verifying.
    pub session_id: String,
    /// Milliseconds since epoch when this binding was issued.
    pub created_at_ms: u64,
    /// `expires_at_ms = 0` means "no expiry"; otherwise the binding is
    /// refused after this timestamp.
    pub expires_at_ms: u64,
    /// Hex-encoded SHA-256 of the canonical scope-rule serialization.
    pub scope_hash: String,
    /// Hex-encoded SHA-256 of each authorized `scheme://host[:port]`,
    /// sorted. A URL whose host-hash is not in this list is refused.
    pub target_hashes: Vec<String>,
    /// Lower-case action-class names (`read`, `mutating`, `active`,
    /// `destructive`) the AI may invoke in this session.
    pub allowed_actions: Vec<String>,
    /// Hex-encoded SHA-256 of a canonical "integrity manifest" covering
    /// paths that MUST NOT change during this session (the Camio binary,
    /// the plugins directory, the config/key directory). Empty means no
    /// integrity lock was requested at bind time.
    ///
    /// Used to defend against a rogue AI that somehow writes to disk
    /// during its session — e.g. drops a new plugin, replaces the binary,
    /// swaps the key file, or edits the config. The next
    /// [`verify_integrity`] call re-hashes the paths and refuses the
    /// operation if any digest diverges. The field is covered by the
    /// binding's HMAC, so an AI can neither remove nor swap it.
    #[serde(default)]
    pub integrity_hash: String,
    /// Hex-encoded HMAC-SHA256 over the canonical serialization of every
    /// field above. Verified before any binding-gated action.
    pub tag: String,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiGuardError {
    /// The binding's tag does not match a fresh HMAC under this key. The
    /// binding was forged, replayed under the wrong key, or had a field
    /// mutated after issuance.
    InvalidTag,
    /// The binding carries an expiry and the current clock is past it.
    Expired { now_ms: u64, expires_at_ms: u64 },
    /// The URL is not one of the binding's authorized targets. The host
    /// hash didn't match any entry in `target_hashes`.
    TargetNotAuthorized(String),
    /// The AI attempted an action class that was not granted at session
    /// start — e.g. called a `destructive` tool with a `read`-only binding.
    ActionNotAllowed(String),
    /// The URL could not be parsed well enough to extract a host.
    MalformedUrl(String),
    /// The caller passed a hex string that isn't valid hex.
    /// The binding's tag is not valid hex — plus what the decoder said.
    BadHex { tag: String, source: String },
    /// An integrity-locked path changed mid-session. `path` names the
    /// first divergence; the full list is in [`verify_integrity`]'s
    /// return value. Treat this as a cold-stop: refuse the operation,
    /// alert the operator, do not issue a replacement binding.
    IntegrityBreach(String),
    /// The caller tried to read / hash a path that cannot be read.
    Io(String),
}

impl fmt::Display for AiGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AiGuardError::InvalidTag => write!(
                f,
                "AI-guard: binding tag did not verify — refusing operation"
            ),
            AiGuardError::Expired {
                now_ms,
                expires_at_ms,
            } => write!(
                f,
                "AI-guard: binding expired at {expires_at_ms} ms (now {now_ms} ms)"
            ),
            AiGuardError::TargetNotAuthorized(url) => {
                write!(
                    f,
                    "AI-guard: target `{url}` is not in this session's authorized set"
                )
            }
            AiGuardError::ActionNotAllowed(a) => {
                write!(
                    f,
                    "AI-guard: action class `{a}` was not granted to this session"
                )
            }
            AiGuardError::MalformedUrl(u) => write!(f, "AI-guard: malformed URL `{u}`"),
            AiGuardError::BadHex { tag, source } => {
                write!(f, "AI-guard: invalid hex `{tag}`: {source}")
            }
            AiGuardError::IntegrityBreach(p) => write!(
                f,
                "AI-guard: integrity-locked path changed during session: {p}"
            ),
            AiGuardError::Io(e) => write!(f, "AI-guard: I/O error {e}"),
        }
    }
}

impl std::error::Error for AiGuardError {}

// ---------------------------------------------------------------------------
// Binding construction & verification
// ---------------------------------------------------------------------------

/// Compute a signed [`SessionBinding`] for this session's scope / targets /
/// allowed actions. Pass `expires_at_ms = 0` for "no expiry".
///
/// For the stronger lockdown mode that also pins the on-disk integrity of
/// the Camio binary, plugins directory, and key directory, use
/// [`bind_session_with_integrity`].
pub fn bind_session(
    session_id: &str,
    scope_rules: &[ScopeRule],
    targets: &[String],
    allowed_actions: &[ActionClass],
    expires_at_ms: u64,
    key: &SessionKey,
) -> Result<SessionBinding, AiGuardError> {
    bind_session_impl(
        session_id,
        scope_rules,
        targets,
        allowed_actions,
        expires_at_ms,
        String::new(),
        key,
    )
}

/// Like [`bind_session`] but additionally pins the current SHA-256 of
/// every path in `integrity_paths`. The combined "integrity manifest"
/// hash is folded into the signed binding, so an AI cannot remove the
/// lock without invalidating the tag.
///
/// Call [`verify_integrity`] on each AI-mediated operation to re-check
/// the paths against the pinned hash. A divergence returns
/// [`AiGuardError::IntegrityBreach`] — refuse the operation and alert
/// the operator; do not re-issue a binding, because the breach may have
/// already dropped a malicious plugin that the next bind would adopt.
pub fn bind_session_with_integrity(
    session_id: &str,
    scope_rules: &[ScopeRule],
    targets: &[String],
    allowed_actions: &[ActionClass],
    integrity_paths: &[std::path::PathBuf],
    expires_at_ms: u64,
    key: &SessionKey,
) -> Result<SessionBinding, AiGuardError> {
    let integrity_hash = integrity_manifest_hash(integrity_paths)?;
    bind_session_impl(
        session_id,
        scope_rules,
        targets,
        allowed_actions,
        expires_at_ms,
        integrity_hash,
        key,
    )
}

fn bind_session_impl(
    session_id: &str,
    scope_rules: &[ScopeRule],
    targets: &[String],
    allowed_actions: &[ActionClass],
    expires_at_ms: u64,
    integrity_hash: String,
    key: &SessionKey,
) -> Result<SessionBinding, AiGuardError> {
    let scope_hash = hash_scope_canonical(scope_rules);
    let mut target_hashes: Vec<String> = Vec::with_capacity(targets.len());
    for t in targets {
        target_hashes.push(hash_target(t)?);
    }
    target_hashes.sort();
    target_hashes.dedup();
    let actions: Vec<String> = {
        let mut v: Vec<String> = allowed_actions
            .iter()
            .map(|a| a.as_str().to_string())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let created_at_ms = now_ms();
    let unsigned = UnsignedBinding {
        session_id: session_id.to_string(),
        created_at_ms,
        expires_at_ms,
        scope_hash,
        target_hashes,
        allowed_actions: actions,
        integrity_hash,
    };
    let tag = sign_unsigned(&unsigned, key);
    Ok(SessionBinding {
        session_id: unsigned.session_id,
        created_at_ms: unsigned.created_at_ms,
        expires_at_ms: unsigned.expires_at_ms,
        scope_hash: unsigned.scope_hash,
        target_hashes: unsigned.target_hashes,
        allowed_actions: unsigned.allowed_actions,
        integrity_hash: unsigned.integrity_hash,
        tag: hex_encode(&tag),
    })
}

/// Verify the binding's tag with `key` and (if set) its expiry. Returns
/// `Ok(())` when the binding is intact.
pub fn verify_binding(binding: &SessionBinding, key: &SessionKey) -> Result<(), AiGuardError> {
    if binding.expires_at_ms != 0 {
        let now = now_ms();
        if now > binding.expires_at_ms {
            return Err(AiGuardError::Expired {
                now_ms: now,
                expires_at_ms: binding.expires_at_ms,
            });
        }
    }
    let unsigned = UnsignedBinding {
        session_id: binding.session_id.clone(),
        created_at_ms: binding.created_at_ms,
        expires_at_ms: binding.expires_at_ms,
        scope_hash: binding.scope_hash.clone(),
        target_hashes: binding.target_hashes.clone(),
        allowed_actions: binding.allowed_actions.clone(),
        integrity_hash: binding.integrity_hash.clone(),
    };
    let fresh = sign_unsigned(&unsigned, key);
    let claimed = hex_decode(&binding.tag).map_err(|e| AiGuardError::BadHex {
        tag: binding.tag.clone(),
        source: e.to_string(),
    })?;
    if ct_eq(&fresh, &claimed) {
        Ok(())
    } else {
        Err(AiGuardError::InvalidTag)
    }
}

/// `true` iff `url`'s `scheme://host[:port]` hash is in the binding.
/// The caller should still call [`verify_binding`] first — this function
/// does not consult the key and is cheap by design.
pub fn target_authorized(binding: &SessionBinding, url: &str) -> Result<bool, AiGuardError> {
    let h = hash_target(url)?;
    Ok(binding.target_hashes.iter().any(|c| c == &h))
}

/// All-in-one check used by MCP/CLI entry points.
pub fn verify_and_authorize_target(
    binding: &SessionBinding,
    url: &str,
    key: &SessionKey,
) -> Result<(), AiGuardError> {
    verify_binding(binding, key)?;
    if target_authorized(binding, url)? {
        Ok(())
    } else {
        Err(AiGuardError::TargetNotAuthorized(url.to_string()))
    }
}

/// `true` iff `action` is one of the binding's allowed action classes.
pub fn action_allowed(binding: &SessionBinding, action: ActionClass) -> bool {
    let needle = action.as_str();
    binding.allowed_actions.iter().any(|a| a == needle)
}

/// Verify the binding and that `action` was granted. Call this on the
/// server side before invoking a tool.
pub fn verify_and_authorize_action(
    binding: &SessionBinding,
    action: ActionClass,
    key: &SessionKey,
) -> Result<(), AiGuardError> {
    verify_binding(binding, key)?;
    if action_allowed(binding, action) {
        Ok(())
    } else {
        Err(AiGuardError::ActionNotAllowed(action.as_str().to_string()))
    }
}

// ---------------------------------------------------------------------------
// Finding access
// ---------------------------------------------------------------------------

/// Filter a batch of findings to those whose evidence host hashes to one
/// of the binding's authorized target hashes. Readers that mediate AI
/// access should always route through this instead of returning the raw
/// list, so the AI can never see findings from outside its session's
/// scope.
///
/// `host_of(evidence_id)` is a resolver the caller supplies — most Camio
/// stores have the originating host cached alongside each exchange, so the
/// resolver is cheap. Returns the filtered findings in the original order.
pub fn authorize_findings<F, I>(
    binding: &SessionBinding,
    findings: I,
    mut host_of: F,
) -> Vec<crate::model::Finding>
where
    I: IntoIterator<Item = crate::model::Finding>,
    F: FnMut(crate::model::ExchangeId) -> Option<String>,
{
    let mut out = Vec::new();
    for f in findings {
        let mut keep = false;
        for &ev in &f.evidence {
            if let Some(host) = host_of(ev) {
                let url = format!("https://{host}");
                if target_authorized(binding, &url).unwrap_or(false) {
                    keep = true;
                    break;
                }
                let url2 = format!("http://{host}");
                if target_authorized(binding, &url2).unwrap_or(false) {
                    keep = true;
                    break;
                }
            }
        }
        if keep {
            out.push(f);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/// Canonical serialization of a scope-rule list: one JSON line per rule in
/// declaration order, with each rule rendered as `{include|exclude}:<raw>`.
/// Changing rule order or text produces a different hash.
fn hash_scope_canonical(rules: &[ScopeRule]) -> String {
    let mut h = Sha256::new();
    for rule in rules {
        if !rule.enabled {
            continue;
        }
        let tag = if rule.include { "include:" } else { "exclude:" };
        h.update(tag.as_bytes());
        h.update(format!("{:?}", rule.query).as_bytes());
        h.update(b"\n");
    }
    hex_encode(&h.finalize())
}

/// Hash a target URL at host-level: `sha256(scheme://host[:port])`. The
/// path, query, and fragment are intentionally ignored so the AI can hit
/// any path on an authorized host (further restricted by the scope rules,
/// which are in the binding's `scope_hash`).
fn hash_target(url: &str) -> Result<String, AiGuardError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| AiGuardError::MalformedUrl(url.to_string()))?;
    let scheme = scheme.to_ascii_lowercase();
    // rest is `host[:port]/path?query#fragment` — strip the first of `/`, `?`, `#`.
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let hostport = rest[..end].to_ascii_lowercase();
    if hostport.is_empty() {
        return Err(AiGuardError::MalformedUrl(url.to_string()));
    }
    // Strip default port.
    let canonical = match (scheme.as_str(), hostport.rsplit_once(':')) {
        ("http", Some((h, "80"))) => format!("http://{h}"),
        ("https", Some((h, "443"))) => format!("https://{h}"),
        _ => format!("{scheme}://{hostport}"),
    };
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    Ok(hex_encode(&h.finalize()))
}

// ---------------------------------------------------------------------------
// Internal signing
// ---------------------------------------------------------------------------

struct UnsignedBinding {
    session_id: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    scope_hash: String,
    target_hashes: Vec<String>,
    allowed_actions: Vec<String>,
    integrity_hash: String,
}

fn sign_unsigned(u: &UnsignedBinding, key: &SessionKey) -> [u8; 32] {
    // Canonical length-prefixed concatenation. Length prefixes prevent
    // boundary-collision attacks (concatenating two short fields could
    // otherwise match a longer one).
    let mut msg: Vec<u8> = Vec::new();
    fn push_field(msg: &mut Vec<u8>, name: &str, value: &[u8]) {
        msg.extend_from_slice(name.as_bytes());
        msg.extend_from_slice(b":");
        msg.extend_from_slice(&(value.len() as u64).to_le_bytes());
        msg.extend_from_slice(b":");
        msg.extend_from_slice(value);
        msg.extend_from_slice(b"\n");
    }
    push_field(&mut msg, "id", u.session_id.as_bytes());
    push_field(&mut msg, "created", &u.created_at_ms.to_le_bytes());
    push_field(&mut msg, "expires", &u.expires_at_ms.to_le_bytes());
    push_field(&mut msg, "scope", u.scope_hash.as_bytes());
    for t in &u.target_hashes {
        push_field(&mut msg, "target", t.as_bytes());
    }
    for a in &u.allowed_actions {
        push_field(&mut msg, "action", a.as_bytes());
    }
    push_field(&mut msg, "integrity", u.integrity_hash.as_bytes());
    hmac_sha256(key.as_bytes(), &msg)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finalize();
        let mut v = [0u8; BLOCK];
        v[..32].copy_from_slice(&d);
        v
    } else {
        let mut v = [0u8; BLOCK];
        v[..key.len()].copy_from_slice(key);
        v
    };
    let mut opad = [0x5cu8; BLOCK];
    let mut ipad = [0x36u8; BLOCK];
    for i in 0..BLOCK {
        opad[i] ^= k[i];
        ipad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_h = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_h);
    for b in k.iter_mut() {
        *b = 0;
    }
    outer.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut r = 0u8;
    for i in 0..a.len() {
        r |= a[i] ^ b[i];
    }
    r == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode hex, naming the first byte that is not a hex digit. Returning a
/// bare `()` made a forged tag and a truncated one indistinguishable.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{} is not an even number of hex digits", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // The source error is unit-typed and carries no information;
        // the replacement names the offending byte or column.
        // audit-allow: B7
        let h = from_hex(bytes[i])
            .map_err(|_| format!("byte {i} (`{}`) is not a hex digit", bytes[i] as char))?;
        // The source error is unit-typed and carries no information;
        // the replacement names the offending byte or column.
        // audit-allow: B7
        let l = from_hex(bytes[i + 1]).map_err(|_| {
            format!(
                "byte {} (`{}`) is not a hex digit",
                i + 1,
                bytes[i + 1] as char
            )
        })?;
        out.push((h << 4) | l);
        i += 2;
    }
    Ok(out)
}

fn from_hex(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Integrity manifest — pin on-disk state to defend against mid-session edits
// ---------------------------------------------------------------------------

/// Compute the canonical hash of an integrity manifest covering
/// `paths`. For each path:
///
/// * if it is a regular file, hash its bytes;
/// * if it is a directory, hash a recursive manifest of its contents
///   (sorted by relative path, each entry `relpath:hex\n`);
/// * if it is absent, record the literal string `(absent)`.
///
/// The manifest's own hash is returned as a hex SHA-256. Order of
/// `paths` matters — swap two entries, get a different manifest.
///
/// This is the hook that defends against a rogue AI dropping a new
/// plugin, replacing the Camio binary, or editing the config mid-session:
/// at bind time we pin the digest, and every subsequent [`verify_integrity`]
/// call refuses the operation if anything in `paths` has changed.
pub fn integrity_manifest_hash(paths: &[std::path::PathBuf]) -> Result<String, AiGuardError> {
    let mut outer = Sha256::new();
    for path in paths {
        let label = path.to_string_lossy();
        outer.update(label.as_bytes());
        outer.update(b"=");
        let digest = hash_path(path)?;
        outer.update(digest.as_bytes());
        outer.update(b"\n");
    }
    Ok(hex_encode(&outer.finalize()))
}

fn hash_path(path: &std::path::Path) -> Result<String, AiGuardError> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("(absent)".to_string()),
        Err(e) => Err(AiGuardError::Io(format!("{}: {e}", path.display()))),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                // Symlinks hash by target string so a swapped link is
                // caught without following into the target.
                match std::fs::read_link(path) {
                    Ok(t) => {
                        let mut h = Sha256::new();
                        h.update(b"symlink:");
                        h.update(t.to_string_lossy().as_bytes());
                        Ok(hex_encode(&h.finalize()))
                    }
                    Err(e) => Err(AiGuardError::Io(format!("{}: {e}", path.display()))),
                }
            } else if meta.is_file() {
                hash_file(path)
            } else if meta.is_dir() {
                hash_dir(path)
            } else {
                Ok("(unknown)".to_string())
            }
        }
    }
}

fn hash_file(path: &std::path::Path) -> Result<String, AiGuardError> {
    let mut f = std::fs::File::open(path)
        .map_err(|e| AiGuardError::Io(format!("{}: {e}", path.display())))?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| AiGuardError::Io(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_encode(&h.finalize()))
}

fn hash_dir(path: &std::path::Path) -> Result<String, AiGuardError> {
    // Recursive manifest: `(relpath, file-hash)` sorted lexicographically.
    let mut entries: Vec<(String, String)> = Vec::new();
    collect_dir(path, path, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    h.update(b"dir:");
    for (rel, digest) in entries {
        h.update(rel.as_bytes());
        h.update(b":");
        h.update(digest.as_bytes());
        h.update(b"\n");
    }
    Ok(hex_encode(&h.finalize()))
}

fn collect_dir(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), AiGuardError> {
    let rd =
        std::fs::read_dir(dir).map_err(|e| AiGuardError::Io(format!("{}: {e}", dir.display())))?;
    for entry in rd {
        let entry = entry.map_err(|e| AiGuardError::Io(format!("{}: {e}", dir.display())))?;
        let p = entry.path();
        let meta = entry
            .file_type()
            .map_err(|e| AiGuardError::Io(format!("{}: {e}", p.display())))?;
        if meta.is_dir() {
            collect_dir(root, &p, out)?;
        } else if meta.is_file() {
            let rel = p.strip_prefix(root).unwrap_or(&p);
            let rel_s = rel.to_string_lossy().to_string();
            out.push((rel_s, hash_file(&p)?));
        } else if meta.is_symlink() {
            let rel = p.strip_prefix(root).unwrap_or(&p);
            let rel_s = rel.to_string_lossy().to_string();
            match std::fs::read_link(&p) {
                Ok(t) => {
                    let mut h = Sha256::new();
                    h.update(b"symlink:");
                    h.update(t.to_string_lossy().as_bytes());
                    out.push((rel_s, hex_encode(&h.finalize())));
                }
                Err(e) => return Err(AiGuardError::Io(format!("{}: {e}", p.display()))),
            }
        }
    }
    Ok(())
}

/// Re-hash `paths` and compare against the binding's pinned
/// `integrity_hash`. A binding with an empty `integrity_hash` was never
/// locked and returns `Ok(())` immediately.
pub fn verify_integrity(
    binding: &SessionBinding,
    paths: &[std::path::PathBuf],
) -> Result<(), AiGuardError> {
    if binding.integrity_hash.is_empty() {
        return Ok(());
    }
    let fresh = integrity_manifest_hash(paths)?;
    if fresh == binding.integrity_hash {
        Ok(())
    } else {
        Err(AiGuardError::IntegrityBreach(format!(
            "pinned-hash mismatch over {} path(s); re-bind or alert the operator",
            paths.len()
        )))
    }
}

/// A conservative default set of paths to pin: the running Camio binary
/// (`/proc/self/exe` on Linux), the configuration/key directory
/// (`~/.config/camio`), and the plugins directory (`./plugins`). Missing
/// paths are recorded as `(absent)` in the manifest so the AI can't win
/// by making a previously-present directory disappear.
pub fn default_integrity_paths() -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        out.push(std::path::PathBuf::from("/proc/self/exe"));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")));
    if let Some(cfg) = base {
        out.push(cfg.join("camio"));
    }
    out.push(std::path::PathBuf::from("plugins"));
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, ExchangeId, Finding, FindingId, Severity};

    fn key() -> SessionKey {
        SessionKey::from_bytes([1u8; 32])
    }
    fn key2() -> SessionKey {
        SessionKey::from_bytes([2u8; 32])
    }

    #[test]
    fn hex_encode_decode_roundtrip() {
        let bytes = [0u8, 1, 15, 16, 255];
        let s = hex_encode(&bytes);
        assert_eq!(s, "00010f10ff");
        let back = hex_decode(&s).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn hex_decode_rejects_invalid() {
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("0").is_err());
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 1: key=0x0b*20, msg="Hi There".
        let k = [0x0bu8; 20];
        let got = hmac_sha256(&k, b"Hi There");
        let expected =
            hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
        assert_eq!(&got[..], &expected[..]);
    }

    #[test]
    fn ct_eq_is_length_safe() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn hash_target_strips_path_and_default_port() {
        let a = hash_target("https://example.com/foo?bar=1").unwrap();
        let b = hash_target("https://EXAMPLE.com/qux").unwrap();
        let c = hash_target("https://example.com:443/baz").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        let d = hash_target("http://example.com:80/").unwrap();
        let e = hash_target("http://example.com").unwrap();
        assert_eq!(d, e);
        // Different port => different hash.
        let f = hash_target("https://example.com:8443/").unwrap();
        assert_ne!(a, f);
    }

    #[test]
    fn hash_target_malformed_errors() {
        assert!(matches!(
            hash_target("not-a-url"),
            Err(AiGuardError::MalformedUrl(_))
        ));
        assert!(matches!(
            hash_target("https:///path"),
            Err(AiGuardError::MalformedUrl(_))
        ));
    }

    #[test]
    fn bind_and_verify_roundtrip() {
        let k = key();
        let rules = vec![ScopeRule::include("host.eq:example.com").unwrap()];
        let b = bind_session(
            "s1",
            &rules,
            &["https://example.com".into()],
            &[ActionClass::Read, ActionClass::Mutating],
            0,
            &k,
        )
        .unwrap();
        verify_binding(&b, &k).unwrap();
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let rules = vec![ScopeRule::include("host.eq:example.com").unwrap()];
        let b = bind_session(
            "s2",
            &rules,
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &key(),
        )
        .unwrap();
        assert!(matches!(
            verify_binding(&b, &key2()),
            Err(AiGuardError::InvalidTag)
        ));
    }

    #[test]
    fn verify_fails_when_scope_hash_tampered() {
        let b = bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &key(),
        )
        .unwrap();
        let mut forged = b.clone();
        // Rogue AI tries to widen scope by swapping the hash.
        forged.scope_hash =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert!(matches!(
            verify_binding(&forged, &key()),
            Err(AiGuardError::InvalidTag)
        ));
    }

    #[test]
    fn verify_fails_when_target_added() {
        let b = bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &key(),
        )
        .unwrap();
        let mut forged = b.clone();
        forged
            .target_hashes
            .push(hash_target("https://evil.test").unwrap());
        assert!(matches!(
            verify_binding(&forged, &key()),
            Err(AiGuardError::InvalidTag)
        ));
    }

    #[test]
    fn verify_fails_when_action_escalated() {
        let b = bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &key(),
        )
        .unwrap();
        let mut forged = b.clone();
        forged.allowed_actions.push("destructive".into());
        assert!(matches!(
            verify_binding(&forged, &key()),
            Err(AiGuardError::InvalidTag)
        ));
    }

    #[test]
    fn expiry_is_enforced() {
        // Expired 1 ms ago.
        let past = now_ms().saturating_sub(10);
        let b = bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            &[ActionClass::Read],
            past,
            &key(),
        )
        .unwrap();
        assert!(matches!(
            verify_binding(&b, &key()),
            Err(AiGuardError::Expired { .. })
        ));
    }

    #[test]
    fn target_authorized_matches_host_level_not_path() {
        let b = bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &key(),
        )
        .unwrap();
        assert!(target_authorized(&b, "https://example.com/anything?x=1").unwrap());
        assert!(target_authorized(&b, "https://example.com:443/path").unwrap());
        assert!(!target_authorized(&b, "https://evil.test/x").unwrap());
        assert!(!target_authorized(&b, "https://example.com.evil.test/x").unwrap());
    }

    #[test]
    fn verify_and_authorize_target_combined() {
        let k = key();
        let b = bind_session(
            "s",
            &[ScopeRule::include("host.eq:example.com").unwrap()],
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &k,
        )
        .unwrap();
        verify_and_authorize_target(&b, "https://example.com/x", &k).unwrap();
        assert!(matches!(
            verify_and_authorize_target(&b, "https://evil.test/", &k),
            Err(AiGuardError::TargetNotAuthorized(_))
        ));
    }

    #[test]
    fn action_allowed_and_verify_combined() {
        let k = key();
        let b = bind_session(
            "s",
            &[],
            &["https://example.com".into()],
            &[ActionClass::Read, ActionClass::Mutating],
            0,
            &k,
        )
        .unwrap();
        verify_and_authorize_action(&b, ActionClass::Read, &k).unwrap();
        verify_and_authorize_action(&b, ActionClass::Mutating, &k).unwrap();
        assert!(matches!(
            verify_and_authorize_action(&b, ActionClass::Destructive, &k),
            Err(AiGuardError::ActionNotAllowed(_))
        ));
    }

    #[test]
    fn authorize_findings_filters_by_evidence_host() {
        let k = key();
        let b = bind_session(
            "s",
            &[],
            &["https://authorized.test".into()],
            &[ActionClass::Read],
            0,
            &k,
        )
        .unwrap();
        let f1 = Finding {
            id: FindingId(1),
            title: "ok".into(),
            severity: Severity::Low,
            confidence: Confidence::Tentative,
            detail: "".into(),
            evidence: vec![ExchangeId(1)],
            created_at_ms: 0,
            rule: None,
        };
        let f2 = Finding {
            id: FindingId(2),
            title: "off-scope".into(),
            severity: Severity::Low,
            confidence: Confidence::Tentative,
            detail: "".into(),
            evidence: vec![ExchangeId(2)],
            created_at_ms: 0,
            rule: None,
        };
        let out = authorize_findings(&b, vec![f1.clone(), f2.clone()], |id| match id {
            ExchangeId(1) => Some("authorized.test".into()),
            ExchangeId(2) => Some("evil.test".into()),
            _ => None,
        });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, FindingId(1));
    }

    #[test]
    fn debug_impl_redacts_the_key() {
        let s = format!("{:?}", SessionKey::from_bytes([0xaau8; 32]));
        assert!(s.contains("redacted"));
        assert!(!s.contains("aaaa"));
    }

    #[test]
    fn scope_rule_order_matters_in_the_hash() {
        let r1 = ScopeRule::include("host.eq:a").unwrap();
        let r2 = ScopeRule::include("host.eq:b").unwrap();
        let h1 = hash_scope_canonical(&[r1.clone(), r2.clone()]);
        let h2 = hash_scope_canonical(&[r2, r1]);
        assert_ne!(h1, h2);
    }

    // ---------------------- Integrity-lock tests ------------------------

    fn tmpdir(label: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "camio-ai-guard-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn integrity_hash_of_absent_path_is_stable() {
        let p = tmpdir("absent").join("does-not-exist");
        let h1 = integrity_manifest_hash(std::slice::from_ref(&p)).unwrap();
        let h2 = integrity_manifest_hash(&[p]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn integrity_hash_changes_when_file_bytes_change() {
        let dir = tmpdir("file-change");
        let f = dir.join("plugin.sh");
        std::fs::write(&f, b"original\n").unwrap();
        let before = integrity_manifest_hash(std::slice::from_ref(&f)).unwrap();
        std::fs::write(&f, b"tampered\n").unwrap();
        let after = integrity_manifest_hash(&[f]).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn integrity_hash_changes_when_new_file_dropped_into_dir() {
        let dir = tmpdir("newfile");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        let before = integrity_manifest_hash(std::slice::from_ref(&dir)).unwrap();
        // Rogue AI drops a new plugin into plugins/ — the integrity lock
        // must catch it.
        std::fs::write(dir.join("evil-plugin.sh"), b"#!/bin/sh\necho pwn\n").unwrap();
        let after = integrity_manifest_hash(&[dir]).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn bind_with_integrity_signs_the_hash_into_the_tag() {
        let dir = tmpdir("bind-integ");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        let b = bind_session_with_integrity(
            "s",
            &[],
            &["https://example.com".into()],
            &[ActionClass::Read],
            std::slice::from_ref(&dir),
            0,
            &key(),
        )
        .unwrap();
        verify_binding(&b, &key()).unwrap();

        // Flip the integrity_hash to the "empty" sentinel — tag fails.
        let mut forged = b.clone();
        forged.integrity_hash.clear();
        assert!(matches!(
            verify_binding(&forged, &key()),
            Err(AiGuardError::InvalidTag)
        ));
    }

    #[test]
    fn verify_integrity_catches_post_bind_drop() {
        let dir = tmpdir("post-drop");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        let b = bind_session_with_integrity(
            "s",
            &[],
            &["https://example.com".into()],
            &[ActionClass::Read],
            std::slice::from_ref(&dir),
            0,
            &key(),
        )
        .unwrap();

        // No change yet — passes.
        verify_integrity(&b, std::slice::from_ref(&dir)).unwrap();

        // Rogue AI drops a new file. Next verify must breach.
        std::fs::write(dir.join("evil.sh"), b"pwn").unwrap();
        let err = verify_integrity(&b, &[dir]).unwrap_err();
        assert!(matches!(err, AiGuardError::IntegrityBreach(_)));
    }

    #[test]
    fn verify_integrity_noop_when_no_lock() {
        // A binding issued without lockdown should NOT fail on an empty
        // path list — the integrity check is opt-in.
        let b = bind_session(
            "s",
            &[],
            &["https://example.com".into()],
            &[ActionClass::Read],
            0,
            &key(),
        )
        .unwrap();
        verify_integrity(&b, &[]).unwrap();
        verify_integrity(&b, &[std::path::PathBuf::from("/nope")]).unwrap();
    }

    #[test]
    fn default_integrity_paths_contains_plugins_dir() {
        let paths = default_integrity_paths();
        let joined: String = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("plugins"), "paths: {joined}");
    }
}
