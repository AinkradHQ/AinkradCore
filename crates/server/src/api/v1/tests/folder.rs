//! AI session folders (E2): the session info carries the folder its harness works in on its
//! runner, once the runner has reported it, and keeps it across later answers that do not repeat
//! it. The runner end is `runner::v2::agent::tests`.

use ainkrad_proto::v2::{AgentEvents, AgentState};
use serde_json::json;

use super::*;
use crate::store::agents::{self as store, NewSession};

/// A session on a runner of its own, as the store holds it.
pub(super) async fn session(fx: &Fx, runner: &str) -> store::Session {
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &json!({}),
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    store::create(&fx.app.pool, &new, sys, NOW).await.unwrap()
}

/// The runner's answer about `s`, naming `folder`.
pub(super) fn answer(s: &store::Session, folder: Option<&str>) -> AgentEvents {
    AgentEvents {
        session: s.id.clone(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: vec![],
        plan_limit: None,
        folder: folder.map(str::to_owned),
    }
}

#[tokio::test]
async fn a_started_sessions_info_carries_its_folder_once_the_runner_reports_it() {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let s = session(&fx, &vm.id).await;
    let uri = format!("/api/v1/agent-sessions/{}", s.id);
    assert!(
        fx.ok(&uri).await["folder"].is_null(),
        "absent until reported"
    );

    let dir = "/srv/ainkrad/work/session-x";
    store::apply(&fx.app.pool, &s.id, &answer(&s, Some(dir)), NOW)
        .await
        .unwrap();
    assert_eq!(fx.ok(&uri).await["folder"], json!(dir));
    let listed = fx.ok("/api/v1/agent-sessions").await;
    let row = (listed.as_array().unwrap().iter())
        .find(|r| r["id"] == s.id.as_str())
        .unwrap();
    assert_eq!(row["folder"], json!(dir));

    // A later answer without it keeps it; a new start's folder replaces it.
    store::apply(&fx.app.pool, &s.id, &answer(&s, None), NOW)
        .await
        .unwrap();
    assert_eq!(fx.ok(&uri).await["folder"], json!(dir));
    let next = "/srv/ainkrad/work/worktrees/sessions/x/1";
    store::apply(&fx.app.pool, &s.id, &answer(&s, Some(next)), NOW)
        .await
        .unwrap();
    assert_eq!(fx.ok(&uri).await["folder"], json!(next));
}

/// `createTerminal` with `session` refuses before anything reaches a runner: with `cwd` too,
/// without the `agent` scope, for a session the caller cannot see, on another runner, before the
/// folder is known, and for an ended session whose worktree is gone. The happy path, with a real
/// runner and shell, is `tests/hub/terminals/session.rs`.
#[tokio::test]
async fn a_terminal_for_a_session_is_refused_unless_its_folder_is_known_on_that_runner() {
    use axum::http::{Method, StatusCode};
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let other = super::secrets::runner(&fx, "other").await;
    let dev = super::stepup::plain(&fx, "term-agent", &["terminal", "agent", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &dev).await.0, StatusCode::OK);
    let no_agent = super::stepup::plain(&fx, "term-only", &["terminal", "read"], true).await;
    assert_eq!(
        super::stepup::step_up(&fx, &no_agent).await.0,
        StatusCode::OK
    );
    let s = session(&fx, &vm.id).await;
    let body = |runner: &str, extra: serde_json::Value| {
        let mut b = json!({"runner": runner, "session": s.id, "size": {"rows": 24, "cols": 80}});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        b
    };
    let call = async |d: &TestDevice, b: serde_json::Value| {
        let r = send(
            &fx.app,
            req(Method::POST, "/api/v1/terminals", Some(d), Some(b)),
        )
        .await;
        (r.0, r.1["code"].as_str().unwrap_or_default().to_owned())
    };
    let conflict = |c: &str| (StatusCode::CONFLICT, c.to_owned());

    let both = body(&vm.id, json!({"cwd": "/"}));
    assert_eq!(
        call(&dev, both).await,
        (StatusCode::BAD_REQUEST, "bad_request".into())
    );
    let r = call(&no_agent, body(&vm.id, json!({}))).await;
    assert_eq!(r, (StatusCode::FORBIDDEN, "forbidden_scope".into()));
    let mut unknown = body(&vm.id, json!({}));
    unknown["session"] = json!("as_00000000000000000000000000");
    assert_eq!(call(&dev, unknown).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&dev, body(&vm.id, json!({}))).await,
        conflict("session_folder_unknown")
    );

    store::apply(&fx.app.pool, &s.id, &answer(&s, Some("/w/session-x")), NOW)
        .await
        .unwrap();
    assert_eq!(
        call(&dev, body(&other.id, json!({}))).await,
        conflict("session_runner_mismatch")
    );

    // An ended session with a worktree: its folder was moved away.
    let ws = json!({"repo": "https://example.invalid/r.git", "base": "main", "branch": "b"});
    let new = NewSession {
        runner: &vm.id,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: Some(&ws),
        policy: &json!({}),
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let sys = ainkrad_core::audit::AuditActor::System;
    let w = store::create(&fx.app.pool, &new, sys, NOW).await.unwrap();
    store::apply(&fx.app.pool, &w.id, &answer(&w, Some("/w/wt/1")), NOW)
        .await
        .unwrap();
    store::set_state(&fx.app.pool, &w.id, "ended", "test", false, NOW)
        .await
        .unwrap();
    let mut gone = body(&vm.id, json!({}));
    gone["session"] = json!(w.id);
    assert_eq!(call(&dev, gone).await, conflict("session_folder_gone"));
}
