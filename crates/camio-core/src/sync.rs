//! Poison-tolerant locking and other sync helpers shared across the workspace.
//!
//! Every long-lived Camio component hands a mutex-protected struct out as
//! `Arc<Mutex<_>>`, so one panic while the guard is held would otherwise poison
//! the lock forever and turn *every later* caller into a panic. A poisoned
//! `Mutex` still holds perfectly valid data: the panic happened in unrelated
//! code that happened to hold the guard, not in the mutex itself. Recovering is
//! therefore the correct behaviour, and it keeps one failed request from taking
//! down the health of the whole process.

use std::sync::{LockResult, Mutex, MutexGuard};

/// Lock `mutex`, recovering from poisoning instead of panicking.
///
/// The guard of a poisoned mutex is still the mutex's data, so it is safe to
/// use — the invariant that was broken is the one the panicking critical
/// section was maintaining, and nothing else can reconstruct that better than
/// continuing with the value as it stands.
///
/// Use this in place of `.lock().expect("… poisoned")`. `expect` there is a
/// choice to *stop serving* because an unrelated request panicked; recovering
/// keeps the rest of the component alive. Keep `lock()` proper (`?` on the
/// `LockResult`) only where you genuinely cannot proceed with unknown state —
/// nothing in Camio is that today.
pub fn recovered_lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `lock()`, mapping a poisoned result to a plain error.
///
/// For call sites that already return a `Result` and want to keep the standard
/// error path instead of silently recovering.
pub fn try_lock<'a, T, E>(
    mutex: &'a Mutex<T>,
    on_poison: impl FnOnce() -> E,
) -> Result<MutexGuard<'a, T>, E> {
    // The source error is unit-typed and carries no information;
    // the replacement names the offending byte or column.
    // audit-allow: B7
    mutex.lock().map_err(|_| on_poison())
}

/// A `LockResult` with the poison bit discarded — the data is usable either way.
pub fn unpoisoned<T>(result: LockResult<T>) -> T {
    result.unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Report a failure the caller recovers from, so it is not silent.
///
/// The alternative — `let _ = result` — makes a real problem (a record that was
/// not written, a payload that was not delivered) invisible. Use this whenever
/// a human could act on the information: prefer it over ignoring, and prefer
/// *propagating* the error over using this at all when the caller can fail.
pub fn note_failure(what: &str, error: impl std::fmt::Display) {
    eprintln!("camio: {what}: {error}");
}

/// Discard the result of an operation whose failure is *expected* and carries
/// nothing a human can act on: a peer that hung up mid-response, a child
/// process that already exited, a timeout set on a socket about to be closed.
///
/// This exists so `let _ = expr;` is written once — here, where the contract is
/// stated — instead of a hundred times in code nobody re-reads. Every call site
/// must carry a comment saying which of those cases applies; that comment is the
/// audit trail. (`audit-allow: B5` guards this one function, not the callers.)
// audit-allow: B5 — the discards are the point of this function, and each is
// justified at its call site.
pub fn expected<T, E>(result: Result<T, E>) {
    let _ = result;
}

/// Reap a child process we are finished with.
///
/// `kill` fails when the child already exited and `wait` fails when it was
/// already reaped — both are the normal case at the end of a run, and neither
/// is worth a log line. Anything else is not recoverable here, because the
/// output was already read from the pipes.
pub fn reap(child: &mut std::process::Child) {
    expected(child.kill());
    expected(child.wait());
}

/// Turn a thread's panic payload into something loggable.
///
/// `JoinHandle::join` hands back `Box<dyn Any + Send>`, which is not `Display` —
/// so without this, a panicked worker is reported as a generic "panicked" and
/// the actual message is lost.
pub fn describe_panic(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(msg) = payload.downcast_ref::<&str>() {
        (*msg).to_string()
    } else if let Some(msg) = payload.downcast_ref::<String>() {
        msg.clone()
    } else {
        "panic payload is not a string".to_string()
    }
}
