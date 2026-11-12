//! The engine's authorisation is its device's, and the engine's remaining guards.

use super::*;

// --- the engine's authorisation is its device's -------------------------------------------------

#[tokio::test]
async fn a_revoked_device_takes_the_engines_authorisation_with_it() {
    let w = world().await;
    w.wake("assign:1").await;
    ainkrad_core_server::store::gov::revoke_device(
        &w.app().pool,
        &w.fx.dev.id,
        AuditActor::System,
        None,
        &w.now(),
    )
    .await
    .unwrap();
    assert!(
        engine::engine_device(&w.app().pool)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        w.dispatch().await.is_none(),
        "a revoked device's switch starts nothing"
    );
    assert!(w.host.started.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_device_that_lost_admin_takes_the_engines_authorisation_with_it() {
    let w = world().await;
    let weak = enroll(w.app(), "old admin", &["read"], true).await;
    engine::set_engine(&w.app().pool, true, &weak.id, &w.now())
        .await
        .unwrap();
    assert!(
        engine::engine_device(&w.app().pool)
            .await
            .unwrap()
            .is_none()
    );
    w.wake("assign:1").await;
    assert!(w.dispatch().await.is_none());
}

#[tokio::test]
async fn the_platform_scheduler_accepts_the_engines_jobs() {
    use ainkrad_core_server::module::Module;
    let fx = fx().await;
    let modules: Vec<std::sync::Arc<dyn Module>> =
        vec![std::sync::Arc::new(citadel_module::Citadel::default())];
    ainkrad_core_server::jobs::register(&fx.app.pool, &fx.app.clock.now(), &modules)
        .await
        .unwrap();
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM core_jobs WHERE owner = 'citadel' ORDER BY name")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(names, ["dispatch", "reconcile", "repair", "timers"]);
}

/// L1: an admin's cancel that lands while the session starts must not leave it running, with its
/// spend counted nowhere: the session is killed as soon as it is recorded, and its tokens count.
#[tokio::test]
async fn a_cancel_during_session_start_kills_the_session_and_counts_its_spend() {
    let w = world().await;
    w.host.cancel_during_start.store(true, Ordering::SeqCst);
    w.wake("assign:1").await;
    let run = w.dispatch().await.expect("the run");
    assert_eq!(run.state, RunState::Cancelled);
    let sid = run.session_id.clone().expect("the session is on the run");
    let stopped = w
        .host
        .told
        .lock()
        .unwrap()
        .iter()
        .any(|(s, what)| *s == sid && matches!(what, Instruction::Stop { kill: true }));
    assert!(stopped, "the session of a run already over is killed");
    assert!(!w.session(&run).await.live());
    let spent = count(
        &w,
        "SELECT coalesce(sum(input_tokens), 0) FROM core_cost_events",
    )
    .await;
    assert_eq!(spent, 100, "what it spent before the kill is on the ledger");
}

/// R1: an engine with nothing to do writes no `job.ran` audit rows (about 15.8k a day otherwise).
#[tokio::test]
async fn an_idle_engine_writes_no_audit_rows() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicI64;

    use ainkrad_core::audit::AuditFilter;
    use ainkrad_core_server::jobs::{Config, Engine, register};
    use ainkrad_core_server::module::Module;
    use ainkrad_core_server::scheduler::{Clock, iso_of_unix};

    struct Manual(AtomicI64);
    impl Clock for Manual {
        fn now(&self) -> String {
            iso_of_unix(self.0.load(Ordering::SeqCst))
        }
    }
    let fx = fx().await;
    citadel_module::engine::attach(&fx.app);
    let clock = Arc::new(Manual(AtomicI64::new(1_800_000_000)));
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(citadel_module::Citadel::default())];
    register(&fx.app.pool, &clock.now(), &modules)
        .await
        .unwrap();
    let jobs = Engine::new(
        fx.app.pool.clone(),
        clock.clone(),
        &modules,
        Config::default(),
    );
    for _ in 0..5 {
        clock.0.fetch_add(60, Ordering::SeqCst);
        jobs.tick().await.unwrap();
    }
    let done: i64 = sqlx::query_scalar("SELECT count(*) FROM core_job_runs WHERE status = 'ok'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert!(done >= 5, "the jobs ran ({done} runs)");
    let rows =
        ainkrad_core_server::store::audit::list(&fx.app.pool, &AuditFilter::default(), None, 100)
            .await
            .unwrap();
    let ran = rows.iter().filter(|e| e.action == "job.ran").count();
    assert_eq!(ran, 0, "nothing happened, nothing is audited");
}

/// C1: a wake never carries another company's issue into an agent's session.
#[tokio::test]
async fn a_wake_for_another_companys_issue_is_refused() {
    let w = world().await;
    let other = seed(&w.app().pool, "B", "BEE", ProjectMode::Scrum).await;
    let mut cross = w.wake_for("cross:1");
    cross.issue_id = Some(IssueId(other.issue));
    let refused = engine::enqueue_wake(&w.app().pool, &cross).await;
    assert!(refused.is_err(), "{refused:?}");
    let mut missing = w.wake_for("missing:1");
    missing.issue_id = Some(IssueId(9999));
    assert!(engine::enqueue_wake(&w.app().pool, &missing).await.is_err());
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_wake_requests").await,
        0
    );
    w.wake("own:1").await;
    assert_eq!(
        count(&w, "SELECT count(*) FROM citadel_wake_requests").await,
        1
    );
}

/// M2: the platform handle drives only the sessions the module owns; a client's session or
/// another module's is refused whatever the caller names.
#[tokio::test]
async fn the_engine_cannot_drive_a_session_it_does_not_own() {
    use ainkrad_core_server::agents::ModuleAgents;
    use ainkrad_proto::v2::{AgentStop, Command};
    let w = world().await;
    let policy = serde_json::json!({"mode": "ask"});
    let runner = w.host.runners[0].clone();
    let new = new_session(&runner, &policy, &w.fx.dev.id);
    let clients = sessions::create(&w.app().pool, &new, AuditActor::System, &w.now())
        .await
        .unwrap();
    let theirs = sessions::create_owned(
        &w.app().pool,
        &new,
        Some("other"),
        AuditActor::System,
        &w.now(),
    )
    .await
    .unwrap();
    let stop = |id: &str| {
        Command::AgentStop(AgentStop {
            session: id.to_owned(),
            kill: true,
            turn: false,
        })
    };
    for id in [&clients.id, &theirs.id] {
        let refused = ModuleAgents::of(&citadel_module::Citadel::default())
            .instruct(w.app(), id, stop(id))
            .await;
        assert!(refused.is_err(), "{id}: {refused:?}");
    }
}
