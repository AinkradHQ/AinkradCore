//! The scheduler on a fake clock: schedules, the missed-run policy, restarts, leases, retries
//! and the wake queue, against a real database.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ainkrad_core::audit::AuditFilter;
use axum::Router;
use serde_json::json;
use sqlx::SqlitePool;

use super::*;
use crate::api::App;
use crate::module::Module;
use crate::scheduler::{Clock, iso_of_unix, unix_secs};
use crate::store::connect;

const T0: &str = "2026-10-30T10:00:00.000Z";

/// A clock the test moves by hand.
struct Manual(Mutex<i64>);

impl Manual {
    fn at(iso: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(unix_secs(iso).unwrap())))
    }

    fn advance(&self, secs: i64) {
        *self.0.lock().unwrap() += secs;
    }

    fn iso(&self) -> String {
        self.now()
    }
}

impl Clock for Manual {
    fn now(&self) -> String {
        iso_of_unix(*self.0.lock().unwrap())
    }
}

/// Records every run it is handed and answers from a script (`Ok` once it runs out).
#[derive(Default)]
struct Probe {
    seen: Mutex<Vec<Run>>,
    script: Mutex<VecDeque<Result<(), String>>>,
    idle: std::sync::atomic::AtomicBool,
}

impl Probe {
    fn script(&self, answers: &[Result<(), &str>]) {
        let all = answers.iter().map(|a| a.map_err(str::to_owned));
        *self.script.lock().unwrap() = all.collect();
    }

    fn runs(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl JobHandler for Probe {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        self.seen.lock().unwrap().push(run.clone());
        if self.idle.load(std::sync::atomic::Ordering::SeqCst) {
            run.idle();
        }
        let answer = self.script.lock().unwrap().pop_front().unwrap_or(Ok(()));
        Box::pin(async move { answer })
    }
}

struct Toy(Vec<Job>);

impl Module for Toy {
    fn id(&self) -> &'static str {
        "toy"
    }

    fn routes(&self) -> Router<App> {
        Router::new()
    }

    fn jobs(&self) -> Vec<Job> {
        self.0.clone()
    }
}

struct Fx {
    pool: SqlitePool,
    clock: Arc<Manual>,
    probe: Arc<Probe>,
    dir: std::path::PathBuf,
}

async fn fx(name: &str) -> Fx {
    let dir = std::env::temp_dir().join(format!("core-jobs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Fx {
        pool: connect(&dir.join("core.db")).await.unwrap(),
        clock: Manual::at(T0),
        probe: Arc::default(),
        dir,
    }
}

impl Fx {
    fn job(&self, name: &'static str, schedule: Schedule) -> Job {
        Job::new(name, schedule, self.probe.clone())
    }

    /// Records `jobs` as a start of the Core would, and returns an engine for them: calling it
    /// again is a restart.
    async fn start(&self, jobs: Vec<Job>) -> Arc<Engine> {
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Toy(jobs))];
        register(&self.pool, &self.clock.iso(), &modules)
            .await
            .unwrap();
        Engine::new(
            self.pool.clone(),
            self.clock.clone(),
            &modules,
            Config::default(),
        )
    }

    async fn runs(&self) -> Vec<(String, i64, String)> {
        sqlx::query_as("SELECT status, attempt, idem_key FROM core_job_runs ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn actions(&self) -> Vec<String> {
        let filter = AuditFilter::default();
        let all = crate::store::audit::list(&self.pool, &filter, None, 100).await;
        all.unwrap().into_iter().map(|e| e.action).collect()
    }

    async fn done(self) {
        self.pool.close().await;
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[tokio::test]
async fn an_interval_and_a_cron_job_run_when_due_and_each_run_is_audited_and_an_event() {
    let fx = fx("sched").await;
    let engine = fx
        .start(vec![
            fx.job("tick", Schedule::Every(60)),
            fx.job("five", Schedule::Cron("*/5 * * * *".into())),
        ])
        .await;
    assert_eq!(
        engine.tick().await.unwrap(),
        0,
        "nothing is due at registration"
    );
    fx.clock.advance(60);
    assert_eq!(
        engine.tick().await.unwrap(),
        1,
        "the interval, not yet the cron"
    );
    assert_eq!(
        fx.probe.seen.lock().unwrap()[0].key,
        "sched:2026-10-30T10:01:00.000Z"
    );
    assert_eq!(
        engine.tick().await.unwrap(),
        0,
        "the same occurrence is not run again"
    );
    fx.clock.advance(4 * 60);
    assert_eq!(
        engine.tick().await.unwrap(),
        2,
        "10:05: the cron, and the interval once for the minutes it missed"
    );
    assert_eq!(fx.runs().await.iter().filter(|r| r.0 == "ok").count(), 3);

    assert_eq!(fx.actions().await, ["job.ran"; 3]);
    let events = crate::store::events::list_events(&fx.pool, 0, 100)
        .await
        .unwrap();
    let ran = events
        .iter()
        .filter(|e| e.kind == "audit" && e.payload.0["action"] == "job.ran")
        .count();
    assert_eq!(ran, 3, "each run is an event too");
    fx.done().await;
}

/// A poll that found nothing writes no audit row, so an idle engine does not grow the chain;
/// the run is still recorded as done, and a failure is audited even when it called `idle`.
#[tokio::test]
async fn an_idle_run_writes_no_audit_row_but_a_failed_one_does() {
    let fx = fx("idle").await;
    fx.probe
        .idle
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let engine = fx.start(vec![fx.job("poll", Schedule::Every(60))]).await;
    for _ in 0..3 {
        fx.clock.advance(60);
        assert_eq!(engine.tick().await.unwrap(), 1);
    }
    assert_eq!(fx.runs().await.iter().filter(|r| r.0 == "ok").count(), 3);
    assert!(fx.actions().await.is_empty(), "{:?}", fx.actions().await);
    fx.probe.script(&[Err("boom"), Err("boom")]);
    fx.clock.advance(60);
    engine.tick().await.unwrap();
    assert_eq!(fx.actions().await, ["job.failed"]);
    fx.done().await;
}

#[tokio::test]
async fn a_missed_schedule_follows_its_policy_after_a_restart() {
    let fx = fx("missed").await;
    let mut skip = fx.job("skips", Schedule::Every(60));
    skip.missed = Missed::Skip;
    let jobs = vec![fx.job("once", Schedule::Every(60)), skip];
    let first = fx.start(jobs.clone()).await;
    first.tick().await.unwrap();
    // The Core is down for three hours.
    drop(first);
    fx.clock.advance(3 * 3600);
    let engine = fx.start(jobs).await;
    assert_eq!(engine.tick().await.unwrap(), 1, "one run, not 180");
    let seen = fx.probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(fx.actions().await, ["job.missed", "job.ran"]);
    // And it is back on schedule: nothing more at once, the next minute runs both.
    assert_eq!(engine.tick().await.unwrap(), 0);
    fx.clock.advance(60);
    assert_eq!(engine.tick().await.unwrap(), 2);
    fx.done().await;
}

#[tokio::test]
async fn no_run_happens_twice_after_a_restart_and_a_one_shot_fires_once() {
    let fx = fx("restart").await;
    let at = iso_of_unix(unix_secs(T0).unwrap() + 120);
    let jobs = vec![
        fx.job("every", Schedule::Every(60)),
        fx.job("once", Schedule::Once(at)),
    ];
    let engine = fx.start(jobs.clone()).await;
    fx.clock.advance(120);
    assert_eq!(engine.tick().await.unwrap(), 2);
    // Restart at the same instant, three times: the schedule state is in the database.
    for _ in 0..3 {
        let again = fx.start(jobs.clone()).await;
        assert_eq!(again.tick().await.unwrap(), 0);
    }
    fx.clock.advance(600);
    let again = fx.start(jobs).await;
    assert_eq!(
        again.tick().await.unwrap(),
        1,
        "the interval again; the one-shot never"
    );
    assert_eq!(fx.probe.runs(), 3);
    fx.done().await;
}

#[tokio::test]
async fn a_dead_worker_loses_its_lease_and_the_run_is_retried_with_the_same_key() {
    let fx = fx("lease").await;
    let engine = fx.start(vec![fx.job("w", Schedule::Wake)]).await;
    let payload = json!({"session": "s1"});
    assert!(
        wake(&fx.pool, &fx.clock.iso(), "toy", "w", "k1", &payload, None)
            .await
            .unwrap()
    );
    // A worker claims it and dies without finishing.
    let now = fx.clock.iso();
    let held = store_claim(&fx, &now, "h_dead").await;
    assert_eq!((held.len(), held[0].run.attempt), (1, 1));

    fx.clock.advance(30);
    assert_eq!(engine.tick().await.unwrap(), 0, "its lease is still good");
    // A heartbeat keeps it alive past the first lease.
    let now = fx.clock.iso();
    assert!(
        heartbeat(&fx.pool, &now, "h_dead", held[0].run.id, 60)
            .await
            .unwrap()
    );
    fx.clock.advance(40);
    assert_eq!(
        engine.tick().await.unwrap(),
        0,
        "70 s in, but the heartbeat at 30 s holds it"
    );
    fx.clock.advance(60);
    assert_eq!(
        engine.tick().await.unwrap(),
        1,
        "the lease expired: another worker takes it"
    );
    let seen = fx.probe.seen.lock().unwrap().clone();
    assert_eq!((seen[0].attempt, seen[0].key.as_str()), (2, "wake:k1"));
    assert_eq!(seen[0].payload, payload);
    assert_eq!(
        fx.runs().await,
        [("ok".to_owned(), 2, "wake:k1".to_owned())]
    );
    // The dead worker, back from the grave, does not settle a run it no longer holds.
    let late = finish(&fx.pool, &fx.clock.iso(), "h_dead", &held[0], &Ok(()))
        .await
        .unwrap();
    assert!(!late);
    fx.done().await;
}

async fn store_claim(fx: &Fx, now: &str, holder: &str) -> Vec<Claimed> {
    claim(&fx.pool, now, holder, 60, 8).await.unwrap()
}

#[tokio::test]
async fn a_crash_looping_run_is_dead_after_its_attempts() {
    let fx = fx("crashloop").await;
    let mut job = fx.job("w", Schedule::Wake);
    job.max_attempts = 2;
    let engine = fx.start(vec![job]).await;
    wake(&fx.pool, &fx.clock.iso(), "toy", "w", "k", &json!({}), None)
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(store_claim(&fx, &fx.clock.iso(), "h_crash").await.len(), 1);
        fx.clock.advance(61);
    }
    assert_eq!(engine.tick().await.unwrap(), 0, "no third attempt");
    assert_eq!(fx.probe.runs(), 0);
    assert_eq!(fx.runs().await[0].0, "dead");
    assert_eq!(fx.actions().await, ["job.failed"]);
    fx.done().await;
}

#[tokio::test]
async fn a_failing_handler_is_retried_with_backoff_then_dead() {
    let fx = fx("retry").await;
    let engine = fx.start(vec![fx.job("w", Schedule::Wake)]).await;
    fx.probe.script(&[Err("boom"), Err("boom again"), Ok(())]);
    wake(&fx.pool, &fx.clock.iso(), "toy", "w", "k", &json!({}), None)
        .await
        .unwrap();
    assert_eq!(engine.tick().await.unwrap(), 1);
    assert_eq!(fx.runs().await[0].0, "queued");
    fx.clock.advance(29);
    assert_eq!(
        engine.tick().await.unwrap(),
        0,
        "30 s backoff after the first failure"
    );
    fx.clock.advance(1);
    assert_eq!(engine.tick().await.unwrap(), 1);
    fx.clock.advance(59);
    assert_eq!(engine.tick().await.unwrap(), 0, "60 s after the second");
    fx.clock.advance(1);
    assert_eq!(engine.tick().await.unwrap(), 1);
    assert_eq!(fx.runs().await, [("ok".to_owned(), 3, "wake:k".to_owned())]);
    assert_eq!(fx.actions().await, ["job.failed", "job.failed", "job.ran"]);

    // Always failing: dead after max_attempts (3), and never tried again.
    fx.probe.script(&[Err("x"), Err("x"), Err("x"), Err("x")]);
    wake(
        &fx.pool,
        &fx.clock.iso(),
        "toy",
        "w",
        "k2",
        &json!({}),
        None,
    )
    .await
    .unwrap();
    for _ in 0..6 {
        engine.tick().await.unwrap();
        fx.clock.advance(120);
    }
    assert_eq!(
        fx.runs().await[1],
        ("dead".to_owned(), 3, "wake:k2".to_owned())
    );
    fx.done().await;
}

#[tokio::test]
async fn wakes_are_idempotent_and_need_a_registered_job() {
    let fx = fx("wake").await;
    let engine = fx.start(vec![fx.job("w", Schedule::Wake)]).await;
    let now = fx.clock.iso();
    let p = json!({"session": "s1", "api_key": "hunter2"});
    assert!(
        wake(&fx.pool, &now, "toy", "w", "same", &p, None)
            .await
            .unwrap()
    );
    assert!(
        !wake(&fx.pool, &now, "toy", "w", "same", &p, None)
            .await
            .unwrap()
    );
    assert_eq!(engine.tick().await.unwrap(), 1);
    assert!(
        !wake(&fx.pool, &now, "toy", "w", "same", &p, None)
            .await
            .unwrap(),
        "not even after it ran"
    );
    assert_eq!(
        fx.probe.seen.lock().unwrap()[0].payload["api_key"],
        "[redacted:api_key]"
    );
    // A wake for later waits for its time.
    let later = iso_of_unix(unix_secs(&now).unwrap() + 300);
    wake(
        &fx.pool,
        &now,
        "toy",
        "w",
        "later",
        &json!({}),
        Some(&later),
    )
    .await
    .unwrap();
    assert_eq!(engine.tick().await.unwrap(), 0);
    fx.clock.advance(300);
    assert_eq!(engine.tick().await.unwrap(), 1);

    for (owner, name, key) in [("toy", "nope", "k"), ("other", "w", "k"), ("toy", "w", "")] {
        let r = wake(&fx.pool, &now, owner, name, key, &json!({}), None).await;
        assert!(
            matches!(r, Err(sqlx::Error::InvalidArgument(_))),
            "{owner}.{name} {key:?}"
        );
    }
    // A job a module stops declaring is disabled and cannot be woken.
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Toy(vec![]))];
    register(&fx.pool, &now, &modules).await.unwrap();
    assert!(
        wake(&fx.pool, &now, "toy", "w", "x", &json!({}), None)
            .await
            .is_err()
    );
    fx.done().await;
}

#[tokio::test]
async fn bad_jobs_stop_registration_and_a_changed_schedule_is_rescheduled() {
    let fx = fx("bad").await;
    let tries = |jobs: Vec<Job>| {
        let pool = fx.pool.clone();
        let now = fx.clock.iso();
        async move {
            let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Toy(jobs))];
            register(&pool, &now, &modules).await
        }
    };
    let mut few = fx.job("a", Schedule::Wake);
    few.max_attempts = 0;
    let mut slow = fx.job("a", Schedule::Wake);
    slow.backoff_secs = 7200;
    for bad in [
        vec![fx.job("a", Schedule::Cron("61 * * * *".into()))],
        vec![fx.job("a", Schedule::Every(0))],
        vec![fx.job("a", Schedule::Once("tomorrow".into()))],
        vec![fx.job("", Schedule::Wake)],
        vec![fx.job("a", Schedule::Wake), fx.job("a", Schedule::Wake)],
        vec![few],
        vec![slow],
    ] {
        assert!(matches!(
            tries(bad).await,
            Err(sqlx::Error::InvalidArgument(_))
        ));
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_jobs")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "a refusal records nothing");

    tries(vec![fx.job("a", Schedule::Every(60))]).await.unwrap();
    let next = || sqlx::query_scalar::<_, String>("SELECT next_at FROM core_jobs");
    let first = next().fetch_one(&fx.pool).await.unwrap();
    fx.clock.advance(10);
    tries(vec![fx.job("a", Schedule::Every(60))]).await.unwrap();
    assert_eq!(
        next().fetch_one(&fx.pool).await.unwrap(),
        first,
        "unchanged: where it was"
    );
    tries(vec![fx.job("a", Schedule::Every(30))]).await.unwrap();
    assert_ne!(
        next().fetch_one(&fx.pool).await.unwrap(),
        first,
        "changed: rescheduled"
    );
    fx.done().await;
}

#[tokio::test]
async fn finished_runs_are_pruned_after_thirty_days() {
    let fx = fx("prune").await;
    let engine = fx.start(vec![fx.job("w", Schedule::Wake)]).await;
    wake(&fx.pool, &fx.clock.iso(), "toy", "w", "k", &json!({}), None)
        .await
        .unwrap();
    engine.tick().await.unwrap();
    fx.clock.advance(29 * 86_400);
    assert_eq!(prune(&fx.pool, &fx.clock.iso(), 100).await.unwrap(), 0);
    fx.clock.advance(2 * 86_400);
    assert_eq!(prune(&fx.pool, &fx.clock.iso(), 100).await.unwrap(), 1);
    fx.done().await;
}

/// The platform's wake queue (`wake_platform`) is the platform's alone, is bounded in all and
/// per session, dedupes on its key, and a finished run keeps no payload.
#[tokio::test]
async fn the_platform_queue_is_closed_to_modules_bounded_and_forgets_its_payload() {
    let fx = fx("platform").await;
    let wake_jobs: Vec<Arc<dyn Module>> = vec![Arc::new(crate::agents::wake::WakeJobs::default())];
    register(&fx.pool, T0, &wake_jobs).await.unwrap();
    let now = fx.clock.iso();
    let name = crate::agents::wake::JOB;
    let cap = Cap {
        total: 3,
        per_session: 2,
    };
    // A module's `wake` cannot reach it.
    let r = wake(&fx.pool, &now, "core", name, "k", &json!({}), None).await;
    assert!(matches!(r, Err(sqlx::Error::InvalidArgument(_))), "{r:?}");
    let ask = |session: &'static str, key: &'static str| {
        let (pool, now) = (fx.pool.clone(), now.clone());
        async move {
            let p = json!({"session": session, "text": "private text 77"});
            wake_platform(&pool, &now, name, key, &p, cap)
                .await
                .unwrap()
        }
    };
    assert_eq!(ask("s1", "a").await, Queued::New);
    assert_eq!(ask("s1", "b").await, Queued::New);
    assert_eq!(ask("s1", "c").await, Queued::Full, "two per session");
    assert_eq!(
        ask("s1", "a").await,
        Queued::Duplicate,
        "a used key is no new wake"
    );
    assert_eq!(ask("s2", "d").await, Queued::New);
    assert_eq!(ask("s3", "e").await, Queued::Full, "three in all");
    // Nothing handles the job in this test's engine, so the runs fail: after their attempts
    // they are dead, which frees the queue, and none keeps the wake text.
    let engine = Engine::new(
        fx.pool.clone(),
        fx.clock.clone(),
        &wake_jobs,
        Config::default(),
    );
    engine.tick().await.unwrap();
    let kept: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM core_job_runs WHERE status = 'queued'")
            .fetch_all(&fx.pool)
            .await
            .unwrap();
    assert_eq!(kept.len(), 3, "failed once, waiting out the backoff");
    for _ in 0..8 {
        fx.clock.advance(3600);
        engine.tick().await.unwrap();
    }
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT status, payload FROM core_job_runs")
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert!(
        rows.iter().all(|r| r.0 == "dead" && r.1 == "{}"),
        "{rows:?}"
    );
    assert_eq!(
        ask("s3", "e").await,
        Queued::New,
        "the queue has room again"
    );
    fx.done().await;
}
