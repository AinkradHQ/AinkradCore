//! The run engine's scheduler jobs (E2-11): `dispatch` starts runs for due wakes, `reconcile`
//! makes runs follow their sessions, `timers` queues agent heartbeat wakes. The platform's job
//! engine runs them (leases, retries, missed runs) and survives a restart; the handlers keep no
//! state of their own, so a restart or a retried run changes nothing it should not.
//!
//! A job handler is handed no `App`, so the process attaches its one ([`attach`]) when it mounts
//! the module. ponytail: one Core per process; a `Module::attach` hook replaces the static.

use std::sync::{Arc, RwLock};

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};

use crate::store::exec::{self, Platform};

static APP: RwLock<Option<App>> = RwLock::new(None);

/// Gives the jobs the app they work on. Call once, after building the app.
pub fn attach(app: &App) {
    *APP.write().unwrap() = Some(app.clone());
}

fn app() -> Result<App, String> {
    APP.read()
        .unwrap()
        .clone()
        .ok_or_else(|| "the run engine is not attached to an app".to_owned())
}

/// The most wakes one `dispatch` run starts: the rest wait for the next.
const BATCH: usize = 8;

struct Dispatch;
struct Reconcile;
struct Timers;

impl JobHandler for Dispatch {
    fn run<'a>(&'a self, _: &'a Run) -> Done<'a> {
        Box::pin(async {
            let app = app()?;
            for _ in 0..BATCH {
                let now = app.clock.now();
                match exec::dispatch_next(&app, &Platform, &now).await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(e) => return Err(e.to_string()),
                }
            }
            Ok(())
        })
    }
}

impl JobHandler for Reconcile {
    fn run<'a>(&'a self, _: &'a Run) -> Done<'a> {
        Box::pin(async {
            let app = app()?;
            exec::reconcile(&app, &Platform, &app.clock.now())
                .await
                .map(drop)
                .map_err(|e| e.to_string())
        })
    }
}

impl JobHandler for Timers {
    fn run<'a>(&'a self, _: &'a Run) -> Done<'a> {
        Box::pin(async {
            let app = app()?;
            exec::timer::fire_timers(&app.pool, &app.clock.now())
                .await
                .map(drop)
                .map_err(|e| e.to_string())
        })
    }
}

/// `Module::jobs`: a missed pass is skipped (the next is seconds away), a failed one retried.
pub fn jobs() -> Vec<Job> {
    let job = |name, every, handler: Arc<dyn JobHandler>| Job {
        missed: Missed::Skip,
        grace_secs: 5,
        max_attempts: 2,
        backoff_secs: 1,
        ..Job::new(name, Schedule::Every(every), handler)
    };
    vec![
        job("dispatch", 2, Arc::new(Dispatch)),
        job("reconcile", 3, Arc::new(Reconcile)),
        job("timers", 30, Arc::new(Timers)),
    ]
}
