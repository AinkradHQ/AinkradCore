//! The platform scheduler (E2-11): jobs a module declares through `Module::jobs`, kept in the
//! `core_jobs` table so they survive a restart, and run by the [`Engine`].
//!
//! - **Schedules**: cron (UTC), a fixed interval, a one-shot time, or `Wake` (no schedule: it
//!   runs when something calls [`wake`], the wake queue agents use to resume a session).
//! - **Missed runs**: a schedule that came due while the Core was down follows the job's
//!   [`Missed`] policy: one run, or none (`job.missed` is audited).
//! - **At-least-once**: each occurrence is one `core_job_runs` row with an idempotency key,
//!   unique per job, so it is queued once however often the schedule is evaluated. A worker
//!   claims a run with a lease and extends it while it works; if the process dies, the lease
//!   expires and the run is retried, with the same key, which the handler dedupes on. A leader
//!   is not needed: the Core is one process and the claim is one write transaction.
//! - **Bounded retries**: a failed attempt waits out an exponential backoff, and the run is
//!   `dead` after `max_attempts`, a crash-looping handler included.
//! - **Visible**: every attempt's end is an audit row (`job.ran`, `job.failed`), which is also an
//!   event on the stream; a run that called [`Run::idle`] and succeeded writes none.
//!
//! Time comes from the [`Clock`](crate::scheduler::Clock), so tests drive it with a fake one.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;

mod cron;
mod engine;
mod store;

pub use cron::Cron;
pub use engine::{Config, Engine};
pub use store::{
    Cap, Claimed, Queued, claim, finish, fire_due, heartbeat, prune, register, wake, wake_platform,
};

#[cfg(test)]
mod tests;

/// When a job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schedule {
    /// A five-field cron expression, UTC (`jobs::Cron`).
    Cron(String),
    /// Every this many seconds (at least 1).
    Every(u64),
    /// Once, at this RFC 3339 UTC time (`2026-11-01T09:00:00Z`); a time already past runs at once.
    Once(String),
    /// Only when woken.
    Wake,
}

/// What happens to an occurrence that came due while the Core was down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missed {
    /// One run, however many were missed.
    RunOnce,
    /// None, if it is more than the job's grace late.
    Skip,
}

/// One run of a job, as its handler sees it.
#[derive(Debug, Clone)]
pub struct Run {
    pub owner: String,
    pub job: String,
    pub id: i64,
    /// Stable across retries and restarts of this occurrence: dedupe side effects on it.
    pub key: String,
    /// 1 on the first try.
    pub attempt: u32,
    /// The occurrence this run is for.
    pub due_at: String,
    /// What the wake carried; `{}` for a scheduled run.
    pub payload: Value,
    idle: Arc<AtomicBool>,
}

impl Run {
    /// Says this run found nothing to do: a run that succeeds having called it writes no
    /// `job.ran` audit row (a frequent poll would otherwise fill the audit chain, which cannot
    /// be pruned). A failure is always audited.
    pub fn idle(&self) {
        self.idle.store(true, Ordering::SeqCst);
    }

    pub(crate) fn was_idle(&self) -> bool {
        self.idle.load(Ordering::SeqCst)
    }
}

pub type Done<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// The work of a job. An error is a failed attempt (retried within the job's bounds); it should
/// not carry a secret, as it is stored and audited.
pub trait JobHandler: Send + Sync {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a>;
}

/// A job a module declares (`Module::jobs`). `name` is unique within the module.
#[derive(Clone)]
pub struct Job {
    pub name: &'static str,
    pub schedule: Schedule,
    pub missed: Missed,
    /// How late a `Skip` job may start and still run (seconds).
    pub grace_secs: u32,
    /// Attempts per run, 1 to 10.
    pub max_attempts: u32,
    /// The wait after the first failure (seconds, 1 to 3600); it doubles for each one after.
    pub backoff_secs: u32,
    pub handler: Arc<dyn JobHandler>,
}

impl Job {
    /// A job that runs once on a miss, with a minute's grace and three attempts 30 s apart.
    pub fn new(name: &'static str, schedule: Schedule, handler: Arc<dyn JobHandler>) -> Self {
        Self {
            name,
            schedule,
            missed: Missed::RunOnce,
            grace_secs: 60,
            max_attempts: 3,
            backoff_secs: 30,
            handler,
        }
    }
}
