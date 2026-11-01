//! The wake queue end to end (E2-11.3): a wake queued on the scheduler resumes an idle session
//! on a real runner, a wake for a session that is still running waits for it, and a wake whose
//! requester lost its access in the meantime is dropped.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::agents::wake::{CAP, JOB, WakeJobs};
use ainkrad_core_server::jobs::{self, Config, Engine, Queued};
use ainkrad_core_server::module::Module;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use serde_json::json;

use super::agents::{finished, run_runner, script, session, state_of};
use super::runner::{paired, state};
use super::{Core, quick};

const TEXT: &str = "carry on with the second part 41ac";

/// The platform's wake job on `core`, as `serve` mounts it, and an engine for it that ticks fast.
async fn queue(core: &Core) -> Arc<Engine> {
    let wake_jobs = Arc::new(WakeJobs::default());
    wake_jobs.attach(&core.app);
    let modules: Vec<Arc<dyn Module>> = vec![wake_jobs];
    jobs::register(&core.app.pool, &SystemClock.now(), &modules)
        .await
        .unwrap();
    let config = Config {
        every: Duration::from_millis(50),
        ..Config::default()
    };
    Engine::new(
        core.app.pool.clone(),
        Arc::new(SystemClock),
        &modules,
        config,
    )
}

async fn ask(core: &Core, id: &str, by: &str, key: &str, text: Option<&str>) -> Queued {
    let payload = json!({"session": id, "by": by, "text": text});
    let now = SystemClock.now();
    let r = jobs::wake_platform(&core.app.pool, &now, JOB, key, &payload, CAP).await;
    r.unwrap()
}

async fn actions(core: &Core) -> Vec<String> {
    let sql = "SELECT action FROM audit_events WHERE action LIKE 'agent.wake%' \
               OR action = 'agent.woken' ORDER BY seq";
    sqlx::query_scalar(sql)
        .fetch_all(&core.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_wake_resumes_an_idle_session_and_not_one_whose_requester_lost_access() {
    let core = Core::start("wake", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("wake");
    paired(&core, &base, None, &st).await;
    let r = run_runner(&core, &base, &st, script("echo turn")).await;
    let id = session(&core, &r.id, &[]).await;
    let (first, _) = finished(&core, &id).await;
    assert_eq!(first.outcome.as_ref().unwrap()["kind"], "succeeded");
    assert!(
        first.harness_session.is_some(),
        "the turn left a harness session to continue"
    );
    assert_eq!(first.resumes, 0);

    let engine = queue(&core).await;
    assert_eq!(ask(&core, &id, &r.id, "w1", Some(TEXT)).await, Queued::New);
    assert_eq!(engine.tick().await.unwrap(), 1);
    // The idle session is going again, on its own harness session, with the wake as its prompt.
    let (second, transcript) = finished(&core, &id).await;
    assert_eq!(second.resumes, 1);
    assert_eq!(second.prompt.as_deref(), Some(TEXT));
    assert_eq!(second.harness_session, first.harness_session);
    assert!(
        transcript
            .iter()
            .any(|b| b["type"] == "started" && b["resumed"] == true),
        "{transcript:?}"
    );
    assert_eq!(actions(&core).await, ["agent.woken"]);
    // The key is spent: the same wake again queues nothing, so nothing runs twice.
    assert_eq!(
        ask(&core, &id, &r.id, "w1", Some(TEXT)).await,
        Queued::Duplicate
    );
    assert_eq!(engine.tick().await.unwrap(), 0);

    // A wake whose requester has lost `agent` and `admin` by the time it runs is dropped.
    sqlx::query("UPDATE core_devices SET scopes = '[\"runner\"]' WHERE id = ?")
        .bind(&r.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(ask(&core, &id, &r.id, "w2", None).await, Queued::New);
    engine.tick().await.unwrap();
    assert_eq!(actions(&core).await, ["agent.woken", "agent.wake_dropped"]);
    assert_eq!(state_of(&core, &id).await.state, "ended", "it stayed idle");
    assert_eq!(state_of(&core, &id).await.resumes, 1);
    let all: String = sqlx::query_scalar("SELECT group_concat(details) FROM audit_events")
        .fetch_one(&core.app.pool)
        .await
        .unwrap();
    assert!(!all.contains(TEXT), "the wake text is not audited");
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}

#[tokio::test]
async fn a_wake_for_a_running_session_waits_until_it_is_idle() {
    let core = Core::start("wake-busy", quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("wake-busy");
    paired(&core, &base, None, &st).await;
    let gate = st.0.join("go");
    let exec = script(&format!(
        "while [ ! -e '{}' ]; do sleep 0.05; done; echo done",
        gate.display()
    ));
    let r = run_runner(&core, &base, &st, exec).await;
    let id = session(&core, &r.id, &[]).await;
    assert_eq!(state_of(&core, &id).await.state, "running");
    let engine = queue(&core).await;
    assert_eq!(ask(&core, &id, &r.id, "busy", None).await, Queued::New);
    engine.tick().await.unwrap();
    let rows: Vec<(String, i64)> = sqlx::query_as("SELECT status, attempt FROM core_job_runs")
        .fetch_all(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(
        rows,
        [("queued".to_owned(), 1)],
        "not idle: waiting out its backoff"
    );
    assert_eq!(
        state_of(&core, &id).await.resumes,
        0,
        "a running session is not touched"
    );
    std::fs::write(&gate, "").unwrap();
    let (s, _) = finished(&core, &id).await;
    assert_eq!(s.resumes, 0);
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}
