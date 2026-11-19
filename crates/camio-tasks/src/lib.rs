//! `camio-tasks` — the background-task runtime (plan §4.2, §F03).
//!
//! Long operations (campaigns, scans, imports, external-tool runs) must return a
//! task ID immediately and report ordered progress, be cancellable cooperatively,
//! and record a distinct terminal outcome — success, failure, or cancellation —
//! rather than blocking a UI thread or swallowing errors.
//!
//! This is the in-process core of that contract: a [`TaskManager`] spawns each
//! job on its own thread, tracks a [`TaskRecord`] (state + progress + result),
//! and hands the job a [`TaskContext`] to report progress and poll for
//! cancellation. It is storage-agnostic — a caller can snapshot [`TaskRecord`]s
//! into the store for durability — and reuses [`camio_core::TaskState`] so the
//! UI, CLI, and MCP all speak the same lifecycle.
//!
//! What this layer does *not* yet do (honest scope): persist across process
//! restart or reconcile interrupted jobs. Those build on top of these records.

use camio_core::{TaskId, TaskState};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// A snapshot of one task's lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub id: TaskId,
    pub kind: String,
    pub state: TaskState,
    /// Units of work completed.
    pub progress_done: u64,
    /// Total units, when known.
    pub progress_total: Option<u64>,
    /// Latest human-readable status line.
    pub message: String,
    /// Summary on success.
    pub result: Option<String>,
    /// Reason on failure.
    pub error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl TaskRecord {
    /// Whether the task has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            TaskState::Completed
                | TaskState::Failed
                | TaskState::Cancelled
                | TaskState::Interrupted
        )
    }

    /// Fractional progress in `[0,1]`, when a total is known.
    pub fn fraction(&self) -> Option<f32> {
        self.progress_total.and_then(|t| {
            if t == 0 {
                None
            } else {
                Some((self.progress_done as f32 / t as f32).clamp(0.0, 1.0))
            }
        })
    }
}

struct Entry {
    record: TaskRecord,
    cancel: Arc<AtomicBool>,
}

#[derive(Default)]
struct Shared {
    tasks: HashMap<i64, Entry>,
    next_id: i64,
}

/// A thread-backed manager for background tasks.
#[derive(Clone, Default)]
pub struct TaskManager {
    shared: Arc<Mutex<Shared>>,
}

impl TaskManager {
    pub fn new() -> Self {
        TaskManager::default()
    }

    /// Spawn `job` as a background task of the given `kind`. Returns the task ID
    /// immediately; the job runs on its own thread. The job receives a
    /// [`TaskContext`] to report progress and poll cancellation, and returns the
    /// success summary or an error string.
    pub fn spawn<F>(&self, kind: impl Into<String>, job: F) -> TaskId
    where
        F: FnOnce(&TaskContext) -> Result<String, String> + Send + 'static,
    {
        let kind = kind.into();
        let cancel = Arc::new(AtomicBool::new(false));
        let now = now_ms();

        let id = {
            let mut g = self.shared.lock().expect("task manager poisoned");
            g.next_id += 1;
            let id = g.next_id;
            g.tasks.insert(
                id,
                Entry {
                    record: TaskRecord {
                        id: TaskId(id),
                        kind: kind.clone(),
                        state: TaskState::Pending,
                        progress_done: 0,
                        progress_total: None,
                        message: String::new(),
                        result: None,
                        error: None,
                        created_at_ms: now,
                        updated_at_ms: now,
                    },
                    cancel: cancel.clone(),
                },
            );
            id
        };

        let shared = self.shared.clone();
        let ctx = TaskContext {
            id: TaskId(id),
            cancel: cancel.clone(),
            shared: shared.clone(),
        };
        std::thread::Builder::new()
            .name(format!("camio-task-{id}"))
            .spawn(move || {
                set_state(&shared, id, TaskState::Running);
                let outcome = job(&ctx);
                let cancelled = cancel.load(Ordering::Acquire);
                finish(&shared, id, outcome, cancelled);
            })
            // If the OS refuses a thread, fail the task rather than panic.
            .unwrap_or_else(|e| {
                finish(
                    &self.shared,
                    id,
                    Err(format!("could not start task thread: {e}")),
                    false,
                );
                std::thread::spawn(|| {})
            });

        TaskId(id)
    }

    /// Request cooperative cancellation. The job observes it via
    /// [`TaskContext::is_cancelled`] and should stop promptly; the final state
    /// becomes [`TaskState::Cancelled`] unless it already finished.
    pub fn cancel(&self, id: TaskId) -> bool {
        let g = self.shared.lock().expect("task manager poisoned");
        match g.tasks.get(&id.0) {
            Some(e) if !e.record.is_terminal() => {
                e.cancel.store(true, Ordering::Release);
                true
            }
            _ => false,
        }
    }

    /// A snapshot of one task's record.
    pub fn status(&self, id: TaskId) -> Option<TaskRecord> {
        self.shared
            .lock()
            .expect("task manager poisoned")
            .tasks
            .get(&id.0)
            .map(|e| e.record.clone())
    }

    /// Snapshots of all tasks, newest first.
    pub fn list(&self) -> Vec<TaskRecord> {
        let g = self.shared.lock().expect("task manager poisoned");
        let mut out: Vec<TaskRecord> = g.tasks.values().map(|e| e.record.clone()).collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.id.0));
        out
    }

    /// Remove finished task records, returning how many were cleared.
    pub fn clear_finished(&self) -> usize {
        let mut g = self.shared.lock().expect("task manager poisoned");
        let before = g.tasks.len();
        g.tasks.retain(|_, e| !e.record.is_terminal());
        before - g.tasks.len()
    }
}

/// Handed to a job so it can report progress and observe cancellation.
pub struct TaskContext {
    id: TaskId,
    cancel: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
}

impl TaskContext {
    pub fn id(&self) -> TaskId {
        self.id
    }

    /// Whether cancellation has been requested. A cooperative job checks this
    /// between units of work and returns promptly when it is `true`.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    /// Report progress (`done` of optional `total`).
    pub fn set_progress(&self, done: u64, total: Option<u64>) {
        let mut g = self.shared.lock().expect("task manager poisoned");
        if let Some(e) = g.tasks.get_mut(&self.id.0) {
            e.record.progress_done = done;
            e.record.progress_total = total;
            e.record.updated_at_ms = now_ms();
        }
    }

    /// Set the latest status message.
    pub fn set_message(&self, msg: impl Into<String>) {
        let mut g = self.shared.lock().expect("task manager poisoned");
        if let Some(e) = g.tasks.get_mut(&self.id.0) {
            e.record.message = msg.into();
            e.record.updated_at_ms = now_ms();
        }
    }
}

fn set_state(shared: &Arc<Mutex<Shared>>, id: i64, state: TaskState) {
    let mut g = shared.lock().expect("task manager poisoned");
    if let Some(e) = g.tasks.get_mut(&id) {
        e.record.state = state;
        e.record.updated_at_ms = now_ms();
    }
}

fn finish(shared: &Arc<Mutex<Shared>>, id: i64, outcome: Result<String, String>, cancelled: bool) {
    let mut g = shared.lock().expect("task manager poisoned");
    if let Some(e) = g.tasks.get_mut(&id) {
        match outcome {
            // Cancellation wins even if the job returned a value/error.
            _ if cancelled => {
                e.record.state = TaskState::Cancelled;
                if e.record.message.is_empty() {
                    e.record.message = "cancelled".to_string();
                }
            }
            Ok(summary) => {
                e.record.state = TaskState::Completed;
                e.record.result = Some(summary);
            }
            Err(err) => {
                e.record.state = TaskState::Failed;
                e.record.error = Some(err);
            }
        }
        e.record.updated_at_ms = now_ms();
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Block until the task reaches a terminal state (bounded).
    fn wait_terminal(mgr: &TaskManager, id: TaskId) -> TaskRecord {
        for _ in 0..500 {
            if let Some(r) = mgr.status(id) {
                if r.is_terminal() {
                    return r;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("task did not finish in time");
    }

    #[test]
    fn completes_with_progress_and_result() {
        let mgr = TaskManager::new();
        let id = mgr.spawn("demo", |ctx| {
            for i in 1..=5 {
                ctx.set_progress(i, Some(5));
                ctx.set_message(format!("step {i}"));
            }
            Ok("done 5 steps".to_string())
        });
        let rec = wait_terminal(&mgr, id);
        assert_eq!(rec.state, TaskState::Completed);
        assert_eq!(rec.result.as_deref(), Some("done 5 steps"));
        assert_eq!(rec.progress_done, 5);
        assert_eq!(rec.fraction(), Some(1.0));
    }

    #[test]
    fn failing_job_is_failed() {
        let mgr = TaskManager::new();
        let id = mgr.spawn("demo", |_ctx| Err("boom".to_string()));
        let rec = wait_terminal(&mgr, id);
        assert_eq!(rec.state, TaskState::Failed);
        assert_eq!(rec.error.as_deref(), Some("boom"));
    }

    #[test]
    fn cooperative_cancel_marks_cancelled() {
        let mgr = TaskManager::new();
        let id = mgr.spawn("long", |ctx| {
            for i in 0..10_000 {
                if ctx.is_cancelled() {
                    return Ok("stopped early".to_string());
                }
                ctx.set_progress(i, Some(10_000));
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok("finished".to_string())
        });
        // Let it start, then cancel.
        std::thread::sleep(Duration::from_millis(30));
        assert!(mgr.cancel(id));
        let rec = wait_terminal(&mgr, id);
        // Cancellation wins even though the job returned Ok.
        assert_eq!(rec.state, TaskState::Cancelled);
    }

    #[test]
    fn list_and_clear_finished() {
        let mgr = TaskManager::new();
        let a = mgr.spawn("a", |_| Ok("ok".into()));
        let _b = mgr.spawn("b", |_| Err("no".into()));
        wait_terminal(&mgr, a);
        // Both terminal shortly.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(mgr.list().len(), 2);
        let cleared = mgr.clear_finished();
        assert_eq!(cleared, 2);
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn cancel_unknown_or_finished_is_false() {
        let mgr = TaskManager::new();
        assert!(!mgr.cancel(TaskId(999)));
        let id = mgr.spawn("x", |_| Ok("done".into()));
        wait_terminal(&mgr, id);
        assert!(!mgr.cancel(id)); // already terminal
    }
}
