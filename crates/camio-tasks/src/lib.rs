//! `camio-tasks` — the background-task runtime (plan §4.2, §F03).
//!
//! Long operations (campaigns, scans, imports, external-tool runs) must return a
//! task ID immediately and report ordered progress, be cancellable cooperatively,
//! and record a distinct terminal outcome — success, timeout, cancellation,
//! scope denial, parser/tool/storage failure — rather than blocking a UI thread
//! or swallowing errors.
//!
//! This is the in-process core of that contract: a [`TaskManager`] spawns each
//! job on its own thread, tracks a [`TaskRecord`] (state + progress + result +
//! outcome), and hands the job a [`TaskContext`] to report progress and poll for
//! cancellation. Transitions are validated with [`TaskState::can_transition_to`]
//! and a cancellation request moves the task through `Cancelling` while the job
//! winds down. It is storage-agnostic — a caller can snapshot [`TaskRecord`]s
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

/// Why a task ended (plan §4.2: "Record success, timeout, cancellation, parser
/// failure, scope denial, tool failure, and storage failure distinctly. Remove
/// silent error swallowing from execution paths.").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskOutcome {
    Success,
    /// The task hit its time limit.
    Timeout,
    /// The operator cancelled it.
    Cancelled,
    /// A destination was denied by scope/policy.
    ScopeDenied,
    /// Tool or artifact output could not be parsed.
    ParserFailure,
    /// The external tool failed.
    ToolFailure,
    /// The store could not persist results.
    StorageFailure,
    /// Anything else.
    Failed,
}

impl TaskOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskOutcome::Success => "success",
            TaskOutcome::Timeout => "timeout",
            TaskOutcome::Cancelled => "cancelled",
            TaskOutcome::ScopeDenied => "scope_denied",
            TaskOutcome::ParserFailure => "parser_failure",
            TaskOutcome::ToolFailure => "tool_failure",
            TaskOutcome::StorageFailure => "storage_failure",
            TaskOutcome::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "success" => Some(TaskOutcome::Success),
            "timeout" => Some(TaskOutcome::Timeout),
            "cancelled" | "canceled" => Some(TaskOutcome::Cancelled),
            "scope_denied" => Some(TaskOutcome::ScopeDenied),
            "parser_failure" => Some(TaskOutcome::ParserFailure),
            "tool_failure" => Some(TaskOutcome::ToolFailure),
            "storage_failure" => Some(TaskOutcome::StorageFailure),
            "failed" => Some(TaskOutcome::Failed),
            _ => None,
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, TaskOutcome::Success)
    }
}

impl std::fmt::Display for TaskOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
    /// The distinct terminal reason, once finished.
    pub outcome: Option<TaskOutcome>,
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
    sink: Option<Arc<dyn TaskSink>>,
}

/// A persistence sink for task records (plan §4.2 durable jobs + restart
/// recovery). Implemented by callers over their storage handle; a failed save
/// must never take down the running job, so implementations report problems
/// without panicking.
pub trait TaskSink: Send + Sync + 'static {
    fn save(&self, rec: &TaskRecord);
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

    /// A manager that mirrors every state change into `sink` (plan §4.2).
    pub fn with_sink<S: TaskSink>(sink: S) -> Self {
        TaskManager {
            shared: Arc::new(Mutex::new(Shared {
                tasks: HashMap::new(),
                next_id: 0,
                sink: Some(Arc::new(sink)),
            })),
        }
    }

    /// Persist one record through the configured sink, if any.
    fn persist(&self, rec: &TaskRecord) {
        let sink = {
            let g = self.shared.lock().expect("task manager poisoned");
            g.sink.clone()
        };
        if let Some(sink) = sink {
            sink.save(rec);
        }
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
                        state: TaskState::Queued,
                        progress_done: 0,
                        progress_total: None,
                        message: String::new(),
                        result: None,
                        error: None,
                        outcome: None,
                        created_at_ms: now,
                        updated_at_ms: now,
                    },
                    cancel: cancel.clone(),
                },
            );
            id
        };

        let mgr = self.clone();
        let ctx = TaskContext {
            id: TaskId(id),
            cancel: cancel.clone(),
            mgr: mgr.clone(),
        };
        // Persist the queued record so the task exists durably before it runs.
        let queued = mgr.status(TaskId(id));
        if let Some(rec) = queued {
            mgr.persist(&rec);
        }
        std::thread::Builder::new()
            .name(format!("camio-task-{id}"))
            .spawn(move || {
                mgr.set_state(id, TaskState::Running);
                let outcome = job(&ctx);
                let cancelled = cancel.load(Ordering::Acquire);
                mgr.finish(id, outcome, cancelled);
            })
            // If the OS refuses a thread, fail the task rather than panic.
            .unwrap_or_else(|e| {
                self.finish(id, Err(format!("could not start task thread: {e}")), false);
                std::thread::spawn(|| {})
            });

        TaskId(id)
    }

    /// Apply `state` (validated) and mirror the change to the sink.
    fn set_state(&self, id: i64, state: TaskState) {
        let snapshot = {
            let mut g = self.shared.lock().expect("task manager poisoned");
            let Some(e) = g.tasks.get_mut(&id) else {
                return;
            };
            set_record_state(e, state);
            Some(e.record.clone())
        };
        if let Some(rec) = snapshot {
            self.persist(&rec);
        }
    }

    /// Record the terminal state and outcome, then mirror to the sink.
    fn finish(&self, id: i64, outcome: Result<String, String>, cancelled: bool) {
        let snapshot = {
            let mut g = self.shared.lock().expect("task manager poisoned");
            let Some(e) = g.tasks.get_mut(&id) else {
                return;
            };
            let declared = e.record.outcome;
            let (state, kind, detail) = if cancelled {
                (
                    TaskState::Cancelled,
                    TaskOutcome::Cancelled,
                    "cancelled".to_string(),
                )
            } else {
                match outcome {
                    Ok(summary) => (
                        TaskState::Completed,
                        declared.unwrap_or(TaskOutcome::Success),
                        summary,
                    ),
                    Err(err) => (
                        TaskState::Failed,
                        declared.unwrap_or(TaskOutcome::Failed),
                        err,
                    ),
                }
            };
            e.record.state = state;
            e.record.outcome = Some(kind);
            match kind {
                TaskOutcome::Success => e.record.result = Some(detail),
                _ => e.record.error = Some(detail),
            }
            if e.record.message.is_empty() {
                e.record.message = kind.as_str().to_string();
            }
            e.record.updated_at_ms = now_ms();
            Some(e.record.clone())
        };
        if let Some(rec) = snapshot {
            self.persist(&rec);
        }
    }

    /// Request cooperative cancellation. The job observes it via
    /// [`TaskContext::is_cancelled`] and should stop promptly; the task moves
    /// through [`TaskState::Cancelling`] while it winds down and ends as
    /// [`TaskState::Cancelled`] (unless it already finished).
    pub fn cancel(&self, id: TaskId) -> bool {
        let snapshot = {
            let mut g = self.shared.lock().expect("task manager poisoned");
            match g.tasks.get_mut(&id.0) {
                Some(e) if !e.record.is_terminal() => {
                    e.cancel.store(true, Ordering::Release);
                    set_record_state(e, TaskState::Cancelling);
                    Some(e.record.clone())
                }
                _ => None,
            }
        };
        match snapshot {
            Some(rec) => {
                self.persist(&rec);
                true
            }
            None => false,
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
    mgr: TaskManager,
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
        let snapshot = {
            let mut g = self.mgr.shared.lock().expect("task manager poisoned");
            if let Some(e) = g.tasks.get_mut(&self.id.0) {
                e.record.progress_done = done;
                e.record.progress_total = total;
                e.record.updated_at_ms = now_ms();
                Some(e.record.clone())
            } else {
                None
            }
        };
        if let Some(rec) = snapshot {
            self.mgr.persist(&rec);
        }
    }

    /// Set the latest status message.
    pub fn set_message(&self, msg: impl Into<String>) {
        let snapshot = {
            let mut g = self.mgr.shared.lock().expect("task manager poisoned");
            if let Some(e) = g.tasks.get_mut(&self.id.0) {
                e.record.message = msg.into();
                e.record.updated_at_ms = now_ms();
                Some(e.record.clone())
            } else {
                None
            }
        };
        if let Some(rec) = snapshot {
            self.mgr.persist(&rec);
        }
    }

    /// Declare the distinct reason this task is ending (plan §4.2). Use before
    /// returning, so `Ok`/`Err` alone does not flatten a timeout, tool
    /// failure, parser failure, scope denial, or storage failure into a
    /// generic "failed".
    pub fn set_outcome(&self, outcome: TaskOutcome) {
        let mut g = self.mgr.shared.lock().expect("task manager poisoned");
        if let Some(e) = g.tasks.get_mut(&self.id.0) {
            if !e.record.is_terminal() {
                e.record.outcome = Some(outcome);
                e.record.updated_at_ms = now_ms();
            }
        }
    }

    /// Convenience: declare `outcome` and return it as the job's error.
    pub fn fail(&self, outcome: TaskOutcome, msg: impl Into<String>) -> Result<String, String> {
        self.set_outcome(outcome);
        Err(msg.into())
    }
}

/// Apply `state` only if the transition is valid (plan §4.2 validated
/// transitions); an invalid transition is refused rather than corrupting the
/// record. Timestamps refresh on every accepted change.
fn set_record_state(entry: &mut Entry, state: TaskState) {
    if entry.record.state == state || entry.record.state.can_transition_to(state) {
        entry.record.state = state;
        entry.record.updated_at_ms = now_ms();
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

    #[test]
    fn declared_outcomes_stay_distinct() {
        let mgr = TaskManager::new();
        let timeout = mgr.spawn("tool", |ctx| {
            ctx.fail(TaskOutcome::Timeout, "exceeded the 30s limit".to_string())
        });
        let parser = mgr.spawn("import", |ctx| {
            ctx.fail(
                TaskOutcome::ParserFailure,
                "malformed JSONL at line 4".to_string(),
            )
        });
        let denied = mgr.spawn("campaign", |ctx| {
            ctx.fail(TaskOutcome::ScopeDenied, "host not in scope".to_string())
        });
        let rec_t = wait_terminal(&mgr, timeout);
        let rec_p = wait_terminal(&mgr, parser);
        let rec_d = wait_terminal(&mgr, denied);
        for rec in [&rec_t, &rec_p, &rec_d] {
            assert_eq!(rec.state, TaskState::Failed);
        }
        assert_eq!(rec_t.outcome, Some(TaskOutcome::Timeout));
        assert_eq!(rec_p.outcome, Some(TaskOutcome::ParserFailure));
        assert_eq!(rec_d.outcome, Some(TaskOutcome::ScopeDenied));
        assert!(rec_t.error.as_deref().unwrap().contains("30s"));
    }

    #[test]
    fn success_defaults_to_success_outcome() {
        let mgr = TaskManager::new();
        let id = mgr.spawn("scan", |_| Ok("12 checks".into()));
        let rec = wait_terminal(&mgr, id);
        assert_eq!(rec.outcome, Some(TaskOutcome::Success));
        assert!(rec.outcome.map(|o| o.is_success()).unwrap_or(false));
        assert_eq!(rec.result.as_deref(), Some("12 checks"));
    }

    #[test]
    fn cancellation_winds_down_through_cancelling() {
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
        std::thread::sleep(Duration::from_millis(30));
        assert!(mgr.cancel(id));
        // The wind-down state is observable before the terminal record.
        let mut saw_cancelling = false;
        for _ in 0..100 {
            if let Some(r) = mgr.status(id) {
                if r.state == TaskState::Cancelling {
                    saw_cancelling = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(saw_cancelling, "cancel must move the task to cancelling");
        let rec = wait_terminal(&mgr, id);
        assert_eq!(rec.state, TaskState::Cancelled);
        assert_eq!(rec.outcome, Some(TaskOutcome::Cancelled));
    }

    #[test]
    fn terminal_states_never_transition() {
        use camio_core::TaskState as S;
        for t in [S::Completed, S::Cancelled, S::Failed, S::Interrupted] {
            for n in [S::Queued, S::Running, S::Completed, S::Failed] {
                assert!(!t.can_transition_to(n), "{t} -> {n} must be refused");
            }
        }
        assert!(S::Running.can_transition_to(S::Cancelling));
        assert!(!S::Running.can_transition_to(S::AwaitingApproval));
        assert!(S::Cancelling.can_transition_to(S::Completed));
    }

    /// A recording sink (what a durable store would implement).
    #[derive(Clone, Default)]
    struct Recorder {
        seen: Arc<Mutex<Vec<TaskRecord>>>,
    }

    impl TaskSink for Recorder {
        fn save(&self, rec: &TaskRecord) {
            self.seen.lock().unwrap().push(rec.clone());
        }
    }

    #[test]
    fn sink_mirrors_the_lifecycle_for_durability() {
        let sink = Recorder::default();
        let mgr = TaskManager::with_sink(sink.clone());
        let id = mgr.spawn("scan", |ctx| {
            ctx.set_progress(1, Some(2));
            Ok("checks passed".into())
        });
        wait_terminal(&mgr, id);
        let seen = sink.seen.lock().unwrap();
        // The record exists durably before the job starts, every accepted
        // transition is mirrored, and progress updates ride along.
        let states: Vec<TaskState> = seen.iter().map(|r| r.state).collect();
        assert_eq!(states.first(), Some(&TaskState::Queued), "got {states:?}");
        assert!(states.contains(&TaskState::Running), "got {states:?}");
        assert_eq!(states.last(), Some(&TaskState::Completed), "got {states:?}");
        assert!(
            states.len() >= 3,
            "progress should be mirrored too, got {states:?}"
        );
        let last = seen.last().unwrap();
        assert_eq!(last.outcome, Some(TaskOutcome::Success));
        assert_eq!(last.result.as_deref(), Some("checks passed"));
        assert_eq!(last.progress_done, 1);
    }
}
