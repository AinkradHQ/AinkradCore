//! The wake queue for agent sessions (E2-11.3): `POST /agent-sessions/{id}/wake` queues a
//! durable wake on the platform scheduler (`jobs`, owner `core`), and the job resumes the idle
//! session on its runner, continuing the harness's own session, optionally with `text` as the
//! next turn.
//!
//! - **Idle** is a session that finished a turn (`succeeded`) or was lost or interrupted; one
//!   still running is not idle, so the job retries within its bounds and then gives up.
//! - **Bounded**: a few waiting wakes per session and a few hundred in all (`CAP`); a wake
//!   carries a key, so asking twice queues once.
//! - **Authority**: the route needs `agent` and a live step-up; the job runs later with no
//!   caller, so it re-checks that the requesting device is still usable with `agent` or `admin`
//!   (a revoked device's queued wake is dropped, audited `agent.wake_dropped`). The session's
//!   rules are the route's: a module's session is never woken, one that holds secrets answers
//!   to its creator or an admin (checked at the route).
//! - **No content**: the wake text lives in the job payload until the run ends (then it is
//!   cleared) and in the session's prompt; audit rows and errors carry ids, never the text.

use std::sync::{Arc, OnceLock};

use ainkrad_core::audit::AuditActor;
use axum::Router;
use serde::Deserialize;
use serde_json::json;

use super::store::{self, Woken};
use crate::api::App;
use crate::jobs::{Cap, Done, Job, JobHandler, Run, Schedule};
use crate::module::Module;

/// The platform job that wakes a session.
pub const JOB: &str = "session_wake";

/// The bounds of the queue.
pub const CAP: Cap = Cap {
    total: 256,
    per_session: 4,
    per_requester: 32,
};

/// Attempts a wake gets while the session is still busy, and the wait after the first.
const ATTEMPTS: u32 = 6;
const BACKOFF_SECS: u32 = 30;

/// The longest wake text, in bytes.
pub const MAX_TEXT: usize = 16 * 1024;

#[derive(Deserialize)]
struct Payload {
    session: String,
    by: String,
    text: Option<String>,
}

/// The platform's jobs, as a module the scheduler mounts like any other (`jobs::register`,
/// `jobs::Engine`); it carries no routes. `attach` hands it the app once that is built.
#[derive(Default)]
pub struct WakeJobs {
    app: Arc<OnceLock<App>>,
}

impl Module for WakeJobs {
    fn id(&self) -> &'static str {
        crate::store::migrate::CORE
    }

    fn routes(&self) -> Router<App> {
        Router::new()
    }

    fn jobs(&self) -> Vec<Job> {
        let mut job = Job::new(
            JOB,
            Schedule::Wake,
            Arc::new(Handler(Arc::clone(&self.app))),
        );
        // A wake that finds the session still busy waits 30 s, 60 s, ... (about a quarter of an
        // hour in all); the last attempt audits the drop.
        job.max_attempts = ATTEMPTS;
        job.backoff_secs = BACKOFF_SECS;
        vec![job]
    }

    fn attach(&self, app: &App) {
        let _ = self.app.set(app.clone());
    }
}

struct Handler(Arc<OnceLock<App>>);

impl JobHandler for Handler {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = self.0.get().ok_or("the Core is still starting")?;
            wake(app, run).await
        })
    }
}

async fn wake(app: &App, run: &Run) -> Result<(), String> {
    let p: Payload = serde_json::from_value(run.payload.clone())
        .map_err(|_| "a wake payload does not have its shape".to_owned())?;
    let db = |e: sqlx::Error| e.to_string();
    let Some(s) = store::get(&app.pool, &p.session).await.map_err(db)? else {
        run.idle();
        return Ok(());
    };
    let by = crate::store::gov::get_device(&app.pool, &p.by)
        .await
        .map_err(db)?;
    let has = |d: &crate::store::gov::Device, scope: &str| d.scopes.iter().any(|x| x == scope);
    let Some(by) = by.filter(|d| d.usable() && (has(d, "agent") || has(d, "admin"))) else {
        return dropped(app, &s, &p.by, "requester_not_allowed").await;
    };
    // The route's secrets rule, with the requester's scopes as they are now.
    if !s.secrets.is_empty() && s.created_by != by.id && !has(&by, "admin") {
        return dropped(app, &s, &p.by, "requester_not_owner").await;
    }
    // A session that is over but whose supervisor has not yet let go of it cannot be taken
    // over: reopening it now could leave it with nobody supervising. Nothing is changed; the run
    // is retried, and dropped (audited) on the last attempt.
    let over = matches!(s.state.as_str(), "ended" | "lost");
    if over && super::supervised(app).contains(&s.id) {
        return match run.attempt >= ATTEMPTS {
            true => dropped(app, &s, &p.by, "supervisor_busy").await,
            false => Err("the session's previous supervisor is still finishing".to_owned()),
        };
    }
    let now = app.clock.now();
    match store::wake(&app.pool, &s.id, p.text.as_deref(), &now)
        .await
        .map_err(db)?
    {
        Woken::Reopened => {
            app.agents
                .elevated
                .lock()
                .unwrap()
                .insert(s.id.clone(), app.hub.wake_elevation());
            // Not supervised just now (checked above): this starts its supervisor. If another
            // path started one in between, that one drives the reopened row just the same.
            super::supervise(app, &s.id);
            let details = json!({"key": run.key});
            let by = AuditActor::System;
            store::action(&app.pool, &s, by, "agent.woken", None, details, &p.by)
                .await
                .map_err(db)
        }
        // Not idle yet: retried after the backoff, and dropped (audited) on the last attempt.
        Woken::Busy if run.attempt >= ATTEMPTS => dropped(app, &s, &p.by, "busy_timeout").await,
        Woken::Busy => Err("the session is not idle yet".to_owned()),
        Woken::Gone => dropped(app, &s, &p.by, "not_wakeable").await,
    }
}

/// A wake that will never run, audited with why.
async fn dropped(app: &App, s: &store::Session, by: &str, reason: &str) -> Result<(), String> {
    let details = json!({"reason": reason});
    let (pool, system) = (&app.pool, AuditActor::System);
    let audit = store::action(pool, s, system, "agent.wake_dropped", None, details, by);
    audit.await.map_err(|e| e.to_string())
}
