//! The scheduler across a real kill (E2-11.1, E2-11.2): a toy module outside the crate registers
//! jobs through the public API, a child process runs them and is killed with SIGKILL while a run
//! is in flight, and the Core that starts after three hours of downtime applies each job's
//! missed-run policy, retries the killed run once under the same key, and runs nothing twice.
//!
//! The child is this test binary run again for `jobs_child` (it does nothing unless
//! `CORE_JOBS_CHILD_DB` is set). Time is a fake clock, so nothing here sleeps for a schedule.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_core_server::jobs::{
    self, Config, Done, Engine, Job, JobHandler, Missed, Run, Schedule,
};
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, iso_of_unix, unix_secs};
use ainkrad_core_server::store::connect;
use axum::Router;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinSet;

const CHILD_DB: &str = "CORE_JOBS_CHILD_DB";
const READY: &str = "jobs-child-ready";
const T0: &str = "2026-10-30T10:00:00.000Z";

struct Manual(Mutex<i64>);

impl Manual {
    fn at(iso: &str) -> Arc<Self> {
        Arc::new(Self(Mutex::new(unix_secs(iso).unwrap())))
    }

    fn advance(&self, secs: i64) {
        *self.0.lock().unwrap() += secs;
    }
}

impl Clock for Manual {
    fn now(&self) -> String {
        iso_of_unix(*self.0.lock().unwrap())
    }
}

/// Counts its runs; the slow one never returns (the child is killed inside it).
#[derive(Default)]
struct Count {
    runs: AtomicUsize,
    hang: bool,
}

impl JobHandler for Count {
    fn run<'a>(&'a self, _: &'a Run) -> Done<'a> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let hang = self.hang;
        Box::pin(async move {
            if hang {
                std::future::pending::<()>().await;
            }
            Ok(())
        })
    }
}

/// The module under test: a job that runs on a miss, one that skips a miss, and a wake job.
struct Toy {
    every: Arc<Count>,
    skips: Arc<Count>,
    slow: Arc<Count>,
}

impl Toy {
    fn new(hang: bool) -> Arc<Self> {
        Arc::new(Self {
            every: Arc::default(),
            skips: Arc::default(),
            slow: Arc::new(Count {
                hang,
                ..Count::default()
            }),
        })
    }
}

impl Module for Toy {
    fn id(&self) -> &'static str {
        "toy"
    }

    fn routes(&self) -> Router<App> {
        Router::new()
    }

    fn jobs(&self) -> Vec<Job> {
        let mut skips = Job::new("skips", Schedule::Every(60), self.skips.clone());
        skips.missed = Missed::Skip;
        skips.grace_secs = 60;
        vec![
            Job::new("every", Schedule::Every(60), self.every.clone()),
            skips,
            Job::new("slow", Schedule::Wake, self.slow.clone()),
        ]
    }
}

async fn count(pool: &sqlx::SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// The child: registers the jobs, lets a minute pass, runs what is due, and hangs inside the
/// wake job until it is killed. Not a test on its own.
#[tokio::test]
async fn jobs_child() {
    let Ok(db) = std::env::var(CHILD_DB) else {
        return;
    };
    let pool = connect(db.as_ref()).await.unwrap();
    let clock = Manual::at(T0);
    let toy = Toy::new(true);
    let modules: Vec<Arc<dyn Module>> = vec![toy];
    jobs::register(&pool, &clock.now(), &modules).await.unwrap();
    let engine = Engine::new(pool.clone(), clock.clone(), &modules, Config::default());
    jobs::wake(
        &pool,
        &clock.now(),
        "toy",
        "slow",
        "slow-1",
        &json!({}),
        None,
    )
    .await
    .unwrap();
    clock.advance(60);
    let mut running = JoinSet::new();
    engine.tick_into(&mut running).await.unwrap();
    // READY once the two quick runs are settled and the slow one holds its lease.
    for _ in 0..1000 {
        let ok = count(
            &pool,
            "SELECT count(*) FROM core_job_runs WHERE status = 'ok'",
        )
        .await;
        let held = count(
            &pool,
            "SELECT count(*) FROM core_job_runs WHERE status = 'running'",
        )
        .await;
        if (ok, held) == (2, 1) {
            println!("{READY}");
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the child's runs never settled");
}

async fn spawn_child(db: &std::path::Path) -> tokio::process::Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "jobs_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_DB, db)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if line.ends_with(READY) {
                return;
            }
        }
        panic!("the child exited before it was ready");
    };
    tokio::time::timeout(Duration::from_secs(60), ready)
        .await
        .expect("the child never got ready");
    child
}

#[tokio::test]
async fn a_core_killed_mid_run_applies_each_jobs_missed_policy_when_it_comes_back() {
    let dir = std::env::temp_dir().join(format!("core-jobs-kill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");

    let mut child = spawn_child(&db).await;
    child.kill().await.unwrap(); // SIGKILL: no shutdown, no drop, a lease left behind
    drop(child);

    // Three hours later the Core starts again on the same database.
    let pool = connect(&db).await.unwrap();
    let clock = Manual::at(T0);
    clock.advance(60 + 3 * 3600);
    let toy = Toy::new(false);
    let modules: Vec<Arc<dyn Module>> = vec![toy.clone()];
    jobs::register(&pool, &clock.now(), &modules).await.unwrap();
    let engine = Engine::new(pool.clone(), clock.clone(), &modules, Config::default());
    assert_eq!(
        engine.tick().await.unwrap(),
        2,
        "the missed interval once (not 180), and the killed run once more"
    );
    let ran = |c: &Arc<Count>| c.runs.load(Ordering::SeqCst);
    assert_eq!(
        (ran(&toy.every), ran(&toy.skips), ran(&toy.slow)),
        (1, 0, 1)
    );

    // The killed run kept its key: one row, retried (attempt 2) and settled.
    let slow: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, attempt FROM core_job_runs WHERE idem_key = 'wake:slow-1'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(slow, [("ok".to_owned(), 2)]);
    // The skip policy is audited, once; every settled run is audited once.
    let missed = "SELECT count(*) FROM audit_events WHERE action = 'job.missed'";
    assert_eq!(count(&pool, missed).await, 1);
    let settled = "SELECT count(*) FROM audit_events WHERE action = 'job.ran'";
    assert_eq!(
        count(&pool, settled).await,
        4,
        "two before the kill, two after"
    );
    let dupes = "SELECT count(*) - count(DISTINCT job_id || idem_key) FROM core_job_runs";
    assert_eq!(count(&pool, dupes).await, 0);

    // And a restart right away runs nothing again, the schedule is back on its minute.
    let engine = Engine::new(pool.clone(), clock.clone(), &modules, Config::default());
    jobs::register(&pool, &clock.now(), &modules).await.unwrap();
    assert_eq!(engine.tick().await.unwrap(), 0);
    clock.advance(60);
    assert_eq!(
        engine.tick().await.unwrap(),
        2,
        "the next minute: both intervals"
    );
    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
