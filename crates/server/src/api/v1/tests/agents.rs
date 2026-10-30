//! Agent sessions' routes (E2-08) without a runner: what is refused before anything reaches
//! one (a bad body, an offline runner, no step-up, the wrong scope, an unknown session), that a
//! refusal never quotes the prompt and grows no audit row, and the transcript and list reads.
//! The runner end to end is `tests/hub/agents.rs`.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::*;
use crate::store::agents::{self as store, NewSession, SessionSecret};

const PROMPT: &str = "a private prompt 3c9f";

#[tokio::test]
async fn naming_a_secret_requires_admin_even_with_agent_step_up() {
    let fx = fx().await;
    let agent = super::stepup::plain(&fx, "agent-only", &["agent", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &agent).await.0, StatusCode::OK);
    let r = call(
        &fx,
        &agent,
        Method::POST,
        "/api/v1/agent-sessions",
        json!({
            "runner": "d_00000000000000000000000000",
            "harness": "claude",
            "secrets": [{"name": "git.token", "var": "GIT_TOKEN"}]
        }),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
}

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

async fn stored(fx: &Fx, runner: &str) -> store::Session {
    let policy = json!({});
    let secrets = [SessionSecret {
        name: "git.token".into(),
        var: "GIT_TOKEN".into(),
    }];
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: Some(PROMPT),
        workspace: None,
        policy: &policy,
        secrets: &secrets,
        created_by: &fx.dev.id,
    };
    store::create(&fx.app.pool, &new, super::super::BY, NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_create_is_checked_before_any_runner_is_asked() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let ok = json!({"runner": vm.id, "harness": "claude", "prompt": PROMPT});
    for (why, body) in [
        ("runner id", json!({"runner": "vm", "harness": "claude"})),
        (
            "harness",
            json!({"runner": vm.id, "harness": "Claude Code"}),
        ),
        (
            "var",
            json!({"runner": vm.id, "harness": "claude",
                       "secrets": [{"name": "git.token", "var": "LD_PRELOAD"}]}),
        ),
        (
            "name",
            json!({"runner": vm.id, "harness": "claude",
                        "secrets": [{"name": "Git", "var": "T"}]}),
        ),
        (
            "policy",
            json!({"runner": vm.id, "harness": "claude", "policy": {"mode": "yolo"}}),
        ),
        (
            "prompt",
            json!({"runner": vm.id, "harness": "claude", "prompt": "x".repeat(70_000)}),
        ),
    ] {
        let r = call(&fx, &fx.dev, Method::POST, "/api/v1/agent-sessions", body).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // A runner that is not connected: refused, and no session (nor lease) made.
    let r = call(
        &fx,
        &fx.dev,
        Method::POST,
        "/api/v1/agent-sessions",
        ok.clone(),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("runner_offline"))
    );
    assert!(!r.1.to_string().contains(PROMPT));
    assert!(
        fx.ok("/api/v1/agent-sessions")
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    // A device with `read` only, and one without a step-up.
    let reader = enroll(&fx.app, &fx.clock, "reader", &["read"]).await;
    let r = call(
        &fx,
        &reader,
        Method::POST,
        "/api/v1/agent-sessions",
        ok.clone(),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    let unelevated = super::stepup::plain(&fx, "plain", &["agent"], false).await;
    let r = call(&fx, &unelevated, Method::POST, "/api/v1/agent-sessions", ok).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    // A runner device reaches none of it.
    let r = call(&fx, &vm, Method::GET, "/api/v1/agent-sessions", Value::Null).await;
    assert_eq!(r.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sessions_list_read_and_replay_their_transcript_by_seq() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = stored(&fx, &vm.id).await;
    let ev = ainkrad_proto::v2::AgentEvents {
        session: s.id.clone(),
        state: ainkrad_proto::v2::AgentState::Running,
        last_seq: 4,
        // 3 comes before 2 is held: only the run continuing the stored one is taken.
        entries: [1, 3]
            .map(|seq| ainkrad_proto::v2::TranscriptEntry {
                seq,
                at: 1,
                body: json!({"type": "line", "n": seq}),
            })
            .into(),
        harness_session: Some("h-1".into()),
        usage: None,
        outcome: None,
    };
    assert_eq!(
        store::apply(&fx.app.pool, &s.id, &ev, NOW).await.unwrap(),
        1
    );
    let full = ainkrad_proto::v2::AgentEvents {
        entries: (1..=4)
            .map(|seq| ainkrad_proto::v2::TranscriptEntry {
                seq,
                at: 1,
                body: json!({"type": if seq == 4 { "approval_request" } else { "line" },
                             "id": "t1", "tool": "Bash", "n": seq}),
            })
            .collect(),
        ..ev
    };
    // A resend of 1 and the rest: each stored once.
    assert_eq!(
        store::apply(&fx.app.pool, &s.id, &full, NOW).await.unwrap(),
        4
    );
    assert_eq!(
        store::apply(&fx.app.pool, &s.id, &full, NOW).await.unwrap(),
        4
    );
    let uri = format!("/api/v1/agent-sessions/{}/transcript?after=2", s.id);
    let t = fx.ok(&uri).await;
    let seqs: Vec<u64> = t["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [3, 4]);
    let got = fx.ok(&format!("/api/v1/agent-sessions/{}", s.id)).await;
    assert_eq!(
        (got["state"].as_str(), got["last_seq"].as_i64()),
        (Some("starting"), Some(4))
    );
    assert_eq!(got["secrets"], json!(["git.token"]), "names only");
    assert!(!got.to_string().contains(PROMPT));
    assert_eq!(
        fx.ok("/api/v1/agent-sessions")
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // The events: one transcript range per new run, the approval for `approve`.
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT kind FROM events WHERE kind LIKE 'agent.%' ORDER BY seq")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(
        kinds,
        [
            "agent.created",
            "agent.transcript",
            "agent.approval_requested",
            "agent.transcript"
        ]
    );
    assert_eq!(
        crate::store::kinds::platform_scope("agent.approval_requested"),
        "approve"
    );
    assert_eq!(
        crate::store::kinds::platform_scope("agent.transcript"),
        "agent"
    );
    let audit: String =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'agent.created'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        !audit.contains(PROMPT) && audit.contains("git.token"),
        "{audit}"
    );
    // Unknown sessions, and actions on one whose runner is away.
    for uri in [
        "/api/v1/agent-sessions/as_nope",
        "/api/v1/agent-sessions/d_x/transcript",
    ] {
        assert_eq!(
            call(&fx, &fx.dev, Method::GET, uri, Value::Null).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let kill = format!("/api/v1/agent-sessions/{}/kill", s.id);
    let r = call(&fx, &fx.dev, Method::POST, &kill, Value::Null).await;
    assert_eq!(r.1["code"], "runner_offline");
    let resume = format!("/api/v1/agent-sessions/{}/resume", s.id);
    let r = call(&fx, &fx.dev, Method::POST, &resume, Value::Null).await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (StatusCode::CONFLICT, Some("not_resumable"))
    );
}

/// Review M1's lesson for the new writes: refusals a caller can repeat at will are counted,
/// not written to the permanent audit log.
#[tokio::test]
async fn refused_agent_writes_grow_no_audit_rows() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = stored(&fx, &vm.id).await;
    let rows = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events WHERE action = 'api.refused'",
        )
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
    };
    let before = rows().await;
    let create = json!({"runner": vm.id, "harness": "claude"});
    for _ in 0..20 {
        call(
            &fx,
            &fx.dev,
            Method::POST,
            "/api/v1/agent-sessions",
            create.clone(),
        )
        .await;
        let uri = format!("/api/v1/agent-sessions/{}/approvals/t1", s.id);
        call(&fx, &fx.dev, Method::POST, &uri, json!({"approved": true})).await;
        let uri = format!("/api/v1/agent-sessions/{}/messages", s.id);
        call(&fx, &fx.dev, Method::POST, &uri, json!({"text": "hi"})).await;
    }
    assert_eq!(rows().await, before);
}
