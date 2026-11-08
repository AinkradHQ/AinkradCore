//! B-M1b: a session lives on after the client device that created it is revoked unless the Core
//! ends it. The supervisor ends a client session whose creator is revoked (killing the harness);
//! another device's session is left alone. Revoked through the store alone, as the CLI does.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_core_server::store::gov;

use super::agents::{run_runner, script, state_of};
use super::runner::{paired, state};
use super::{Core, quick as hub_quick};

async fn session_by(core: &Core, runner: &str, creator: &str) -> String {
    let policy = serde_json::json!({"mode": "ask"});
    let new = NewSession {
        runner,
        harness: "fake",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: creator,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s)
        .await
        .unwrap_or_else(|e| panic!("{}", service::describe(&e)));
    s.id
}

async fn running(core: &Core, id: &str) {
    for _ in 0..500 {
        if state_of(core, id).await.state == "running" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{id} never ran");
}

#[tokio::test]
async fn a_session_ends_and_its_harness_is_killed_when_its_creator_is_revoked() {
    let core = Core::start("creator-revoked", hub_quick()).await;
    let base = format!("http://{}", core.host);
    let st = state("creator-revoked");
    paired(&core, &base, None, &st).await;
    let r = run_runner(
        &core,
        &base,
        &st,
        script("while :; do echo tick; sleep 0.05; done"),
    )
    .await;
    let gone = core.device("device", &["agent"]).await;
    let kept = core.device("device", &["agent"]).await;
    let mine = session_by(&core, &r.id, &gone.id).await;
    let other = session_by(&core, &r.id, &kept.id).await;
    running(&core, &mine).await;
    running(&core, &other).await;

    // Revoked through the store only: no broadcast, as `device revoke` on the CLI.
    let now = core.app.clock.now();
    assert!(
        gov::revoke_device(&core.app.pool, &gone.id, AuditActor::System, None, &now)
            .await
            .unwrap()
    );
    let started = std::time::Instant::now();
    loop {
        let s = state_of(&core, &mine).await;
        if !s.live() {
            assert_eq!(s.state, "ended");
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a revoked creator's session still {}",
            s.state
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        state_of(&core, &other).await.live(),
        "another device's session was ended"
    );
    // Its harness is dead: the runner has two slots, so a third session runs only if the
    // revoked creator's slot was freed by the kill.
    let third = session_by(&core, &r.id, &kept.id).await;
    running(&core, &third).await;
    r.halt().await;
    let _ = std::fs::remove_dir_all(&st.0);
}
