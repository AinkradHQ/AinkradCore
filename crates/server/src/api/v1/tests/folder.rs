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
