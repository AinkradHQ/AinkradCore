//! Code Mode's dispatcher (E2): the security cases. A session acts as its creator device, now,
//! never as admin, only for allow-listed read operations, within its budgets, and every call
//! leaves an audit row with the `ai_session` origin and the person at its root.

use ainkrad_core::audit::{AuditOrigin, OriginKind};
use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::ToolCall;
use serde_json::{Value, json};

use super::*;
use crate::ops_catalog::{call_call, session_scopes};
use crate::store::agents::{self as store, NewSession};

struct S {
    id: String,
    runner: String,
    creator: String,
}

/// A session created by a new device holding `scopes`, started by that device's person.
async fn session(fx: &Fx, scopes: &[&str]) -> S {
    let creator = fx.enroll("creator", scopes).await;
    let runner = super::secrets::runner(fx, "vm").await;
    let policy = json!({});
    let new = NewSession {
        runner: &runner.id,
        harness: "claude",
        model: None,
        prompt: Some("p"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &creator.id,
    };
    let person = AuditOrigin::new(OriginKind::Person, Some(creator.id.clone()));
    let s = crate::store::audit::origin::scope(
        person,
        store::create(&fx.app.pool, &new, super::super::BY, NOW),
    )
    .await
    .unwrap();
    S {
        id: s.id,
        runner: runner.id.clone(),
        creator: creator.id.clone(),
    }
}

async fn go(fx: &Fx, s: &S, args: Value) -> (bool, String) {
    let call = ToolCall {
        tc_seq: 1,
        id: "c1".to_owned(),
        tool: "ainkrad.call".to_owned(),
        args,
    };
    let r = call_call(&fx.app, &s.runner, &s.id, &call).await;
    (r.ok, r.code.unwrap_or_default())
}

async fn ok_result(fx: &Fx, s: &S, args: Value) -> Value {
    let call = ToolCall {
        tc_seq: 1,
        id: "c1".to_owned(),
        tool: "ainkrad.call".to_owned(),
        args,
    };
    let r = call_call(&fx.app, &s.runner, &s.id, &call).await;
    assert!(r.ok, "{:?} {:?}", r.code, r.message);
    r.result.unwrap()
}

async fn sql(fx: &Fx, q: &'static str, bind: &str) {
    sqlx::query(q)
        .bind(bind)
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

async fn rows(
    fx: &Fx,
) -> Vec<(
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
)> {
    sqlx::query_as(
        "SELECT origin, origin_ref, origin_root, origin_root_ref, details FROM audit_events \
         WHERE action = 'code_mode.call' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap()
}

async fn set(fx: &Fx, key: Key, v: &str) {
    crate::store::settings::set(
        &fx.app.pool,
        key,
        Scope::Server,
        v,
        ainkrad_core::audit::AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_allowed_read_runs_as_the_creator_and_its_row_names_the_session_and_the_person() {
    let fx = fx().await;
    let s = session(&fx, &["read", "agent"]).await;
    let list = ok_result(&fx, &s, json!({"op": "listAgentSessions"})).await;
    assert!(list.is_object() || list.is_array());
    let one = ok_result(
        &fx,
        &s,
        json!({"op": "getAgentSession", "args": {"id": s.id}}),
    )
    .await;
    assert_eq!(one["id"], s.id.as_str());
    let health = ok_result(&fx, &s, json!({"op": "getCoreHealth"})).await;
    assert!(health.is_object());

    let r = rows(&fx).await;
    assert_eq!(r.len(), 3, "one row per call");
    for (origin, oref, root, root_ref, details) in &r {
        assert_eq!(origin, "ai_session");
        assert_eq!(oref.as_deref(), Some(s.id.as_str()));
        assert_eq!(root.as_deref(), Some("person"));
        assert_eq!(root_ref.as_deref(), Some(s.creator.as_str()));
        let d: Value = serde_json::from_str(details).unwrap();
        assert_eq!(d["outcome"], "ok");
        assert_eq!(d["risk"], "read");
        assert_eq!(d["args_sha256"].as_str().unwrap().len(), 64);
        // A summary, never a body: no argument value and no result text.
        assert!(
            !details.contains("creator") && d.get("args").is_none() && d.get("result").is_none()
        );
    }
}

#[tokio::test]
async fn admin_is_never_granted_even_to_a_creator_that_holds_it() {
    let fx = fx().await;
    let s = session(&fx, &ALL).await;
    let scopes = session_scopes(&fx.app.pool, &s.id).await.unwrap();
    assert!(
        !scopes.is_empty() && !scopes.iter().any(|x| x == "admin"),
        "{scopes:?}"
    );
    // listAudit is an admin route: refused, though the creator device could call it itself.
    assert_eq!(
        go(&fx, &s, json!({"op": "listAudit"})).await.1,
        "forbidden_scope"
    );
    assert!(fx.get("/api/v1/audit").await.0.is_success());
    // And search never offers it.
    let found = crate::ops_catalog::search(fx.app.catalogue(), &scopes, "audit", None);
    assert!(!found.to_string().contains("listAudit"), "{found}");
}

#[tokio::test]
async fn an_op_outside_the_creators_scopes_is_refused_and_the_handler_never_runs() {
    let fx = fx().await;
    let s = session(&fx, &["read"]).await;
    assert_eq!(
        go(&fx, &s, json!({"op": "listAgentSessions"})).await.1,
        "forbidden_scope"
    );
    assert!(go(&fx, &s, json!({"op": "getCoreHealth"})).await.0);
}

#[tokio::test]
async fn an_op_outside_the_allow_list_or_a_write_is_refused() {
    let fx = fx().await;
    let s = session(&fx, &ALL).await;
    for op in [
        "listDevices",
        "createAgentSession",
        "killAgentSession",
        "revokeDevice",
        "setDeviceScopes",
        "no_such_op",
        "../../etc",
    ] {
        let (ok, code) = go(&fx, &s, json!({"op": op})).await;
        assert!(!ok, "{op}");
        assert_eq!(code, "unknown_op", "{op}");
    }
    // Nothing in the allow-list is a write in this epic; a write op would be `not_available`.
    for o in fx.app.catalogue().ops.values() {
        assert_eq!(
            (o.risk, o.method.as_str()),
            (crate::ops_catalog::Risk::Read, "GET")
        );
    }
}

#[tokio::test]
async fn a_revoked_creator_a_removed_scope_and_an_ended_session_end_the_next_call() {
    let fx = fx().await;
    let s = session(&fx, &["read", "agent"]).await;
    assert!(go(&fx, &s, json!({"op": "listAgentSessions"})).await.0);

    // A scope taken away takes effect on the next call.
    sql(
        &fx,
        "UPDATE core_devices SET scopes = '[\"read\"]' WHERE id = ?",
        &s.creator,
    )
    .await;
    assert_eq!(
        go(&fx, &s, json!({"op": "listAgentSessions"})).await.1,
        "forbidden_scope"
    );
    assert!(go(&fx, &s, json!({"op": "getCoreHealth"})).await.0);

    // The creator device revoked: nothing at all.
    sql(
        &fx,
        "UPDATE core_devices SET revoked_at = '2026-10-22T10:00:00.000Z' WHERE id = ?",
        &s.creator,
    )
    .await;
    for op in ["getCoreHealth", "listAgentSessions"] {
        assert_eq!(go(&fx, &s, json!({"op": op})).await.1, "creator_revoked");
    }
    sql(
        &fx,
        "UPDATE core_devices SET revoked_at = NULL, status = 'rejected' WHERE id = ?",
        &s.creator,
    )
    .await;
    assert_eq!(
        go(&fx, &s, json!({"op": "getCoreHealth"})).await.1,
        "creator_revoked"
    );

    // Restored, then the session ends.
    sql(
        &fx,
        "UPDATE core_devices SET status = 'active' WHERE id = ?",
        &s.creator,
    )
    .await;
    assert!(go(&fx, &s, json!({"op": "getCoreHealth"})).await.0);
    sql(
        &fx,
        "UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?",
        &s.id,
    )
    .await;
    assert_eq!(
        go(&fx, &s, json!({"op": "getCoreHealth"})).await.1,
        "unknown_session"
    );
}

#[tokio::test]
async fn another_runner_or_an_unknown_session_cannot_call() {
    let fx = fx().await;
    let s = session(&fx, &["read"]).await;
    let other = S {
        runner: "d_bbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        id: s.id.clone(),
        creator: s.creator.clone(),
    };
    assert_eq!(
        go(&fx, &other, json!({"op": "getCoreHealth"})).await.1,
        "unknown_session"
    );
    let ghost = S {
        id: "as_nope".to_owned(),
        runner: s.runner.clone(),
        creator: s.creator.clone(),
    };
    assert_eq!(
        go(&fx, &ghost, json!({"op": "getCoreHealth"})).await.1,
        "unknown_session"
    );
    assert!(rows(&fx).await.is_empty(), "no principal, no row");
}

#[tokio::test]
async fn invalid_arguments_never_reach_a_handler() {
    let fx = fx().await;
    let s = session(&fx, &["read", "agent"]).await;
    for args in [
        json!({"op": "getAgentSession"}),
        json!({"op": "getAgentSession", "args": {"id": "../audit"}}),
        json!({"op": "getAgentSession", "args": {"id": "a/b"}}),
        json!({"op": "getAgentSession", "args": {"id": ".."}}),
        json!({"op": "getAgentSession", "args": {"id": "."}}),
        json!({"op": "getAgentSession", "args": {"id": "x?y=1"}}),
        json!({"op": "getAgentSession", "args": {"id": 5}}),
        json!({"op": "getAgentSession", "args": {"id": "as_x", "extra": 1}}),
        json!({"op": "getAgentSession", "args": "as_x"}),
        json!({"op": "listAgentSessions", "args": {"limit": "ten"}}),
        json!({"op": "listAgentSessions", "args": {"limit": -1}}),
        json!({"op": 5}),
        json!({"op": "getCoreHealth", "surprise": true}),
        json!({"op": "getCoreHealth", "run": "a b"}),
        json!({}),
    ] {
        let (ok, code) = go(&fx, &s, args.clone()).await;
        assert!(!ok && code == "bad_args", "{args}: {code}");
    }
}

#[tokio::test]
async fn oversized_arguments_rate_runs_and_concurrency_are_bounded() {
    let fx = fx().await;
    let s = session(&fx, &["read", "agent"]).await;

    let huge = json!({"op": "getCoreHealth", "args": {"pad": "x".repeat(70_000)}});
    assert_eq!(go(&fx, &s, huge).await.1, "args_too_large");

    // A script's call cap: the third call of run "r1" is `too_many_calls`; another run is fine.
    set(&fx, Key::CodeModeMaxRunCalls, "2").await;
    for _ in 0..2 {
        assert!(
            go(&fx, &s, json!({"op": "getCoreHealth", "run": "r1"}))
                .await
                .0
        );
    }
    assert_eq!(
        go(&fx, &s, json!({"op": "getCoreHealth", "run": "r1"}))
            .await
            .1,
        "too_many_calls"
    );
    assert!(
        go(&fx, &s, json!({"op": "getCoreHealth", "run": "r2"}))
            .await
            .0
    );
    let last = rows(&fx).await.pop().unwrap().4;
    assert!(last.contains("\"ok\""));
    assert!(
        rows(&fx)
            .await
            .iter()
            .any(|r| r.4.contains("too_many_calls"))
    );

    // The wall time of a run, counted from its first call.
    set(&fx, Key::CodeModeRunSecs, "1").await;
    fx.app
        .code_mode
        .runs
        .lock()
        .unwrap()
        .values_mut()
        .for_each(|v| {
            v.0 -= std::time::Duration::from_secs(5);
        });
    assert_eq!(
        go(&fx, &s, json!({"op": "getCoreHealth", "run": "r2"}))
            .await
            .1,
        "run_timeout"
    );

    // Concurrency: calls past the cap are `busy`, and a finished call frees its place.
    set(&fx, Key::CodeModeConcurrent, "1").await;
    fx.app
        .code_mode
        .inflight
        .lock()
        .unwrap()
        .insert(s.id.clone(), 1);
    assert_eq!(go(&fx, &s, json!({"op": "getCoreHealth"})).await.1, "busy");
    fx.app.code_mode.inflight.lock().unwrap().clear();
    assert!(go(&fx, &s, json!({"op": "getCoreHealth"})).await.0);
    assert!(fx.app.code_mode.inflight.lock().unwrap().is_empty());

    // The session's rate: refused past the minute's budget, and only a window's first refusal
    // is audited.
    set(&fx, Key::CodeModeCallsPerMin, "1").await;
    fx.app.code_mode.rate.lock().unwrap().clear();
    assert!(go(&fx, &s, json!({"op": "getCoreHealth"})).await.0);
    let before = rows(&fx).await.len();
    for _ in 0..5 {
        assert_eq!(
            go(&fx, &s, json!({"op": "getCoreHealth"})).await.1,
            "rate_limited"
        );
    }
    assert_eq!(
        rows(&fx).await.len(),
        before + 1,
        "a flood is one row per window"
    );
}

#[tokio::test]
async fn a_result_over_the_cap_comes_back_cut_with_its_size() {
    let fx = fx().await;
    let s = session(&fx, &["read", "agent"]).await;
    set(&fx, Key::CodeModeMaxResultBytes, "1024").await;
    let r = ok_result(&fx, &s, json!({"op": "getCoreHealth"})).await;
    let full = fx.ok("/api/v1/core/health").await.to_string().len();
    if full > 1024 {
        assert_eq!(r["truncated"], true);
        assert!(r["size"].as_u64().unwrap() > 1024);
    } else {
        assert!(r.get("truncated").is_none());
    }
}

#[tokio::test]
async fn denied_calls_are_audited_once_per_window_with_origin() {
    let fx = fx().await;
    let s = session(&fx, &["read"]).await;
    for _ in 0..4 {
        assert_eq!(
            go(&fx, &s, json!({"op": "listAgentSessions"})).await.1,
            "forbidden_scope"
        );
    }
    let r = rows(&fx).await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].0, "ai_session");
    assert!(r[0].4.contains("forbidden_scope") && r[0].4.contains("\"denied\""));
    // A different code is its own row.
    assert_eq!(go(&fx, &s, json!({"op": "nope"})).await.1, "unknown_op");
    assert_eq!(rows(&fx).await.len(), 2);
}
