//! Lost start answers must reuse the original grants instead of exhausting the lease cap.
use super::*;
use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession, SessionSecret};
use ainkrad_proto::v2::*;

#[tokio::test]
async fn retried_starts_reuse_the_same_lease() {
    let mut core = Core::start(
        "sandbox-retry",
        ainkrad_core_server::hub::HubConfig {
            heartbeat: Duration::from_secs(10),
            ..quick()
        },
    )
    .await;
    core.app.agents = service::Agents::new(service::AgentsConfig {
        answer: Duration::from_millis(50),
        retry: Duration::from_millis(25),
        lost_after: Duration::from_secs(2),
        ..service::AgentsConfig::default()
    });
    let runner = core.runner().await;
    let driver = DriverInfo {
        name: AGENT_DRIVER.into(),
        commands: AGENT_OPS.iter().map(|s| (*s).into()).collect(),
        capacity: 2,
        streams: Some(32),
        ..DriverInfo::default()
    };
    let mut fake = Fake::welcomed(&core, &runner, vec![driver]).await;
    agents::throwaway_mode(&core).await;
    agents::make_admin(&core, &runner.id).await;
    agents::secret(&core, "test.retry", std::slice::from_ref(&runner.id), "env").await;
    let secrets = [SessionSecret {
        name: "test.retry".into(),
        var: "TOKEN".into(),
    }];
    let policy = serde_json::json!({"mode": "ask"});
    let session = sessions::create(
        &core.app.pool,
        &NewSession {
            runner: &runner.id,
            harness: "fake",
            model: None,
            prompt: Some("go"),
            workspace: None,
            policy: &policy,
            secrets: &secrets,
            created_by: &runner.id,
        },
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &session.id);
    service::start(&core.app, &session).await.unwrap();
    let mut leases = Vec::new();
    for _ in 0..3 {
        loop {
            if let Some(Body::Command(Command::AgentStart(start))) =
                fake.next().await.body().unwrap()
            {
                leases.push(start.secrets[0].lease.clone());
                break;
            }
        }
    }
    assert!(
        leases.iter().all(|l| l == &leases[0]),
        "retries minted fresh grants"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&core.app.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "retries exhausted lease accounting");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = sessions::get(&core.app.pool, &session.id)
                .await
                .unwrap()
                .unwrap();
            if state.state == "lost" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("unanswered starts retried without a bound");
    core.app.closing.send_replace(true);
}

#[tokio::test]
async fn an_agent_cannot_select_approval_bypasses() {
    use ainkrad_core_server::api::v1::{Caller, create_agent_for_tests as create};
    use axum::{Extension, body::Bytes, extract::State, response::IntoResponse};
    let core = Core::start("sandbox-policy", quick()).await;
    let device = core.device("device", &["agent"]).await;
    let runner = core.runner().await;
    let caller = Caller {
        device: ainkrad_core_server::store::gov::get_device(&core.app.pool, &device.id)
            .await
            .unwrap()
            .unwrap(),
        session: String::new(),
    };
    for allow in [
        serde_json::json!(["Bash"]),
        serde_json::json!(["Bash:curl"]),
        serde_json::json!(["unknown-alias"]),
    ] {
        let body = serde_json::json!({"runner": runner.id, "harness": "fake", "policy": {"mode":"ask", "allow":allow}});
        let result = create(
            State(core.app.clone()),
            Extension(caller.clone()),
            Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert_eq!(
            result.unwrap_err().into_response().status(),
            axum::http::StatusCode::FORBIDDEN
        );
    }
}

/// B-M1: a session whose creator was revoked or de-scoped is leased nothing, on a start or a
/// resume, and ends. The runner stays active throughout, so the broker's own runner check cannot
/// be what refuses it; an active admin creator is the control and is leased.
#[tokio::test]
async fn a_revoked_or_descoped_creator_is_leased_no_secrets() {
    let core = Core::start("sandbox-revoked", quick()).await;
    let runner = core.runner().await;
    let driver = DriverInfo {
        name: AGENT_DRIVER.into(),
        commands: AGENT_OPS.iter().map(|s| (*s).into()).collect(),
        capacity: 4,
        streams: Some(32),
        ..DriverInfo::default()
    };
    let _fake = Fake::welcomed(&core, &runner, vec![driver]).await;
    agents::throwaway_mode(&core).await;
    agents::secret(
        &core,
        "test.revoked",
        std::slice::from_ref(&runner.id),
        "env",
    )
    .await;
    let secrets = [SessionSecret {
        name: "test.revoked".into(),
        var: "TOKEN".into(),
    }];
    let policy = serde_json::json!({"mode": "ask"});
    let session = |creator: String| {
        let (core, runner, secrets, policy) = (&core, &runner, &secrets, &policy);
        async move {
            let s = sessions::create(
                &core.app.pool,
                &NewSession {
                    runner: &runner.id,
                    harness: "fake",
                    model: None,
                    prompt: Some("go"),
                    workspace: None,
                    policy,
                    secrets,
                    created_by: &creator,
                },
                AuditActor::System,
                &core.app.clock.now(),
            )
            .await
            .unwrap();
            service::authorize_for_tests(&core.app, &s.id);
            s
        }
    };
    let leases = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM core_secret_leases")
            .fetch_one(&core.app.pool)
            .await
            .unwrap()
    };
    // De-scoped, then revoked: no further lease, and the session ends.
    let down = core.device("device", &["admin"]).await;
    let revoked = core.device("device", &["admin"]).await;
    sqlx::query("UPDATE core_devices SET scopes = '[\"agent\"]' WHERE id = ?")
        .bind(&down.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE core_devices SET revoked_at = ?, status = 'rejected' WHERE id = ?")
        .bind(core.app.clock.now())
        .bind(&revoked.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    for creator in [down.id, revoked.id] {
        let s = session(creator).await;
        assert!(service::start(&core.app, &s).await.is_err());
        let ended = sessions::get(&core.app.pool, &s.id).await.unwrap().unwrap();
        assert!(!ended.live(), "the session stayed live: {}", ended.state);
        assert_eq!(
            leases().await,
            0,
            "a creator that is not an admin was leased"
        );
    }
    // The control: an active admin creator is leased (the start itself may time out).
    let admin = core.device("device", &["admin"]).await;
    let _ = service::start(&core.app, &session(admin.id.clone()).await).await;
    assert_eq!(leases().await, 1, "an active admin creator was not leased");
    core.app.closing.send_replace(true);
}
