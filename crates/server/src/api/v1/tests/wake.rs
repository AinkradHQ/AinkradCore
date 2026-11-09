//! The wake queue's route (E2-11.3) without a runner: who may queue a wake, what it refuses,
//! that it is idempotent and bounded, and that no wake text reaches the audit log or events.
//! The job that resumes the session is `tests/hub/wake.rs`.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::agents::wake::{CAP, WakeJobs};
use crate::module::Module;
use crate::store::agents::{self as store, NewSession};

const TEXT: &str = "a private wake text 8d21";

async fn call(fx: &Fx, dev: &TestDevice, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::POST, uri, Some(dev), Some(body))).await
}

async fn scheduled(fx: &Fx) {
    let jobs: Vec<Arc<dyn Module>> = vec![Arc::new(WakeJobs::default())];
    crate::jobs::register(&fx.app.pool, NOW, &jobs)
        .await
        .unwrap();
}

/// A session of the admin device without secrets, `starting` (a live session).
async fn session(fx: &Fx, vm: &str, owner: Option<&str>) -> store::Session {
    let policy = json!({});
    let new = NewSession {
        runner: vm,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    store::create_owned(&fx.app.pool, &new, owner, sys, NOW)
        .await
        .unwrap()
}

fn wake_uri(s: &store::Session) -> String {
    format!("/api/v1/agent-sessions/{}/wake", s.id)
}

async fn count(fx: &Fx, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_wake_needs_agent_and_a_step_up_and_leaves_no_text_in_the_audit_log() {
    let fx = fx().await;
    scheduled(&fx).await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = session(&fx, &vm.id, None).await;
    let uri = wake_uri(&s);
    let reader = enroll(&fx.app, &fx.clock, "reader", &["read"]).await;
    let r = call(&fx, &reader, &uri, json!({})).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    let plain = super::stepup::plain(&fx, "plain", &["agent"], false).await;
    let r = call(&fx, &plain, &uri, json!({})).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    assert_eq!(count(&fx, "SELECT count(*) FROM core_job_runs").await, 0);

    let r = call(&fx, &fx.dev, &uri, json!({"key": "k1", "text": TEXT})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        (r.1["queued"].as_bool(), r.1["key"].as_str()),
        (Some(true), Some("k1"))
    );
    // The same key again queues nothing.
    let r = call(&fx, &fx.dev, &uri, json!({"key": "k1", "text": TEXT})).await;
    assert_eq!(
        (r.0, r.1["queued"].as_bool()),
        (StatusCode::OK, Some(false))
    );
    assert_eq!(count(&fx, "SELECT count(*) FROM core_job_runs").await, 1);
    // No key: one is made up, so the second is a wake of its own.
    let r = call(&fx, &fx.dev, &uri, json!({})).await;
    assert!(r.1["key"].as_str().unwrap().starts_with("w_"), "{}", r.1);
    assert_eq!(count(&fx, "SELECT count(*) FROM core_job_runs").await, 2);

    // The audit log and the event stream name the session, never the text.
    let audit: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    let events: Vec<String> = sqlx::query_scalar("SELECT payload FROM events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    let all = [audit.clone(), events].concat().join("\n");
    assert!(!all.contains(TEXT), "{all}");
    assert_eq!(
        audit.iter().filter(|d| d.contains("\"queued\"")).count(),
        3,
        "agent.wake_queued three times (a duplicate is audited too), each naming the session"
    );
}

#[tokio::test]
async fn a_wake_refuses_what_it_cannot_honour_and_never_quotes_the_body() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = session(&fx, &vm.id, None).await;
    let uri = wake_uri(&s);
    // The scheduler does not know the job (nothing registered it): a 503, nothing queued.
    let r = call(&fx, &fx.dev, &uri, json!({"text": TEXT})).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("scheduler_unavailable")
        )
    );
    scheduled(&fx).await;
    for (why, body) in [
        ("key", json!({"key": "a b"})),
        ("empty key", json!({"key": ""})),
        ("empty text", json!({"text": ""})),
        ("long text", json!({"text": "x".repeat(17 * 1024)})),
        ("not a body", json!([1])),
    ] {
        let r = call(&fx, &fx.dev, &uri, body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
        assert!(!r.1.to_string().contains(TEXT));
    }
    let unknown = "/api/v1/agent-sessions/as_nope/wake";
    assert_eq!(
        call(&fx, &fx.dev, unknown, json!({})).await.0,
        StatusCode::NOT_FOUND
    );
    // A module's session is its module's to drive.
    let owned = session(&fx, &vm.id, Some("citadel")).await;
    let r = call(&fx, &fx.dev, &wake_uri(&owned), json!({})).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("module_owned"))
    );
    // Over for good (failed, or finished without a harness session to continue): not wakeable.
    let failed = json!({"kind": "failed", "reason": "x"});
    store::end(&fx.app.pool, &s.id, "ended", &failed, NOW)
        .await
        .unwrap();
    let r = call(&fx, &fx.dev, &uri, json!({})).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_wakeable"))
    );
    let done = session(&fx, &vm.id, None).await;
    let ok = json!({"kind": "succeeded"});
    store::end(&fx.app.pool, &done.id, "ended", &ok, NOW)
        .await
        .unwrap();
    let r = call(&fx, &fx.dev, &wake_uri(&done), json!({})).await;
    assert_eq!(
        r.1["code"].as_str(),
        Some("not_wakeable"),
        "no harness session to continue"
    );
    sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h-1' WHERE id = ?")
        .bind(&done.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let r = call(&fx, &fx.dev, &wake_uri(&done), json!({})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(count(&fx, "SELECT count(*) FROM core_job_runs").await, 1);
}

#[tokio::test]
async fn the_queue_is_bounded_per_session_and_a_used_key_is_still_answered() {
    let fx = fx().await;
    scheduled(&fx).await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = session(&fx, &vm.id, None).await;
    let uri = wake_uri(&s);
    for n in 0..CAP.per_session {
        let r = call(&fx, &fx.dev, &uri, json!({"key": format!("k{n}")})).await;
        assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    }
    let r = call(&fx, &fx.dev, &uri, json!({"key": "one-more"})).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("limit_reached"))
    );
    let r = call(&fx, &fx.dev, &uri, json!({"key": "k0"})).await;
    assert_eq!(
        (r.0, r.1["queued"].as_bool()),
        (StatusCode::OK, Some(false))
    );
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_job_runs").await,
        CAP.per_session
    );
    // Another session has a queue of its own.
    let other = session(&fx, &vm.id, None).await;
    let r = call(&fx, &fx.dev, &wake_uri(&other), json!({"key": "k0"})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    // The key is per session: the same key on another session is a wake of its own.
    assert_eq!(
        r.1["queued"].as_bool(),
        Some(true),
        "a key on A must not suppress B"
    );
}

/// The secrets rule is re-applied when the wake runs, with the requester's scopes as they are
/// then: a device that was an admin when it queued the wake and is only `agent` now has its
/// wake dropped, and the session is not woken.
#[tokio::test]
async fn a_wake_by_a_requester_demoted_since_is_dropped_on_a_session_holding_secrets() {
    use crate::jobs::{Config, Engine, Queued};
    let fx = fx().await;
    scheduled(&fx).await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let policy = json!({});
    let secrets = [store::SessionSecret {
        name: "git.token".into(),
        var: "GIT_TOKEN".into(),
    }];
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &fx.dev.id,
    };
    let s = store::create(&fx.app.pool, &new, super::super::BY, NOW)
        .await
        .unwrap();
    let ok = json!({"kind": "succeeded"});
    store::end(&fx.app.pool, &s.id, "ended", &ok, NOW)
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h-1' WHERE id = ?")
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let other = super::stepup::plain(&fx, "admin2", &["admin", "agent"], true).await;
    let payload = json!({"session": s.id, "by": other.id});
    let queued = crate::jobs::wake_platform(&fx.app.pool, NOW, "session_wake", "k", &payload, CAP)
        .await
        .unwrap();
    assert_eq!(queued, Queued::New);
    // Demoted between queueing and running.
    sqlx::query("UPDATE core_devices SET scopes = '[\"agent\"]' WHERE id = ?")
        .bind(&other.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let wake_jobs = Arc::new(WakeJobs::default());
    wake_jobs.attach(&fx.app);
    let modules: Vec<Arc<dyn Module>> = vec![wake_jobs];
    let engine = Engine::new(
        fx.app.pool.clone(),
        fx.app.clock.clone(),
        &modules,
        Config::default(),
    );
    assert_eq!(engine.tick().await.unwrap(), 1);
    let why: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'agent.wake_dropped'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(why.contains("requester_not_owner"), "{why}");
    let after = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    assert_eq!(
        (after.state.as_str(), after.resumes),
        ("ended", 0),
        "not woken"
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'agent.woken'"
        )
        .await,
        0
    );
}

/// KAN-417: a wake queued by a device that is revoked before the job runs is dropped, audited
/// with its reason, and the session is not woken; the device keeps every scope it had, so only
/// the revocation can be the cause.
#[tokio::test]
async fn a_wake_by_a_requester_revoked_since_is_dropped() {
    use crate::jobs::{Config, Engine, Queued};
    let fx = fx().await;
    scheduled(&fx).await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = session(&fx, &vm.id, None).await;
    let ok = json!({"kind": "succeeded"});
    store::end(&fx.app.pool, &s.id, "ended", &ok, NOW)
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET harness_session = 'h-1' WHERE id = ?")
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let other = super::stepup::plain(&fx, "admin2", &["admin", "agent"], true).await;
    let payload = json!({"session": s.id, "by": other.id});
    let queued = crate::jobs::wake_platform(&fx.app.pool, NOW, "session_wake", "k", &payload, CAP)
        .await
        .unwrap();
    assert_eq!(queued, Queued::New);
    let revoked =
        crate::store::gov::revoke_device(&fx.app.pool, &other.id, super::super::BY, None, NOW);
    assert!(revoked.await.unwrap());
    let wake_jobs = Arc::new(WakeJobs::default());
    wake_jobs.attach(&fx.app);
    let modules: Vec<Arc<dyn Module>> = vec![wake_jobs];
    let engine = Engine::new(
        fx.app.pool.clone(),
        fx.app.clock.clone(),
        &modules,
        Config::default(),
    );
    assert_eq!(engine.tick().await.unwrap(), 1);
    let why: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'agent.wake_dropped'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(why.contains("requester_not_allowed"), "{why}");
    let after = store::get(&fx.app.pool, &s.id).await.unwrap().unwrap();
    assert_eq!((after.state.as_str(), after.resumes), ("ended", 0));
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'agent.woken'"
        )
        .await,
        0
    );
}
