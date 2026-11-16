//! A terminal in an AI session's folder (E1, KAN-456) through the real Core API, runner daemon and
//! `ainkrad-ptyhost`: the client names the session, never the path, and the shell starts in the
//! folder the session's runner reported. The refusals are `api::v1::tests::folder`.

use super::*;
use ainkrad_core_server::store::agents::{self as store, NewSession};
use ainkrad_proto::v2::{AgentEvents, AgentState};

#[tokio::test]
async fn a_terminal_for_a_session_starts_in_the_sessions_folder() {
    let fx = Fx::new("t-sess").await;
    let dev = fx
        .core
        .device("device", &["read", "terminal", "agent"])
        .await;
    elevate(&fx.core, &dev);
    // The folder as the runner would report it: absolute, with no symlink in it (`/tmp` is one on
    // macOS), so `pwd` prints it as it is.
    let folder = fx.dir.with_extension("session");
    std::fs::create_dir_all(&folder).unwrap();
    let folder = folder.canonicalize().unwrap();
    let new = NewSession {
        runner: &fx.runner,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &json!({}),
        secrets: &[],
        created_by: &dev.id,
    };
    let s = store::create(
        &fx.core.app.pool,
        &new,
        AuditActor::System,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    let ev = AgentEvents {
        session: s.id.clone(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
        gateway: vec![],
        plan_limit: None,
        folder: Some(folder.to_str().unwrap().to_owned()),
    };
    store::apply(&fx.core.app.pool, &s.id, &ev, "2026-01-01T00:00:00Z")
        .await
        .unwrap();

    let body = json!({"runner": fx.runner, "session": s.id, "program": "/bin/sh",
        "args": ["-c", "echo \"at:$(pwd)\"; while read -r l; do :; done"],
        "size": {"rows": 24, "cols": 80}});
    let (status, t) = fx.call(&dev, "POST", "/api/v1/terminals", Some(body)).await;
    assert_eq!(status, 201, "{t}");
    let mut c = fx.ws(&dev, t["id"].as_str().unwrap()).await;
    c.read_until(&format!("at:{}", folder.display())).await;
    let _ = std::fs::remove_dir_all(&folder);
}
