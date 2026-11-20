//! A terminal in an AI session's folder (E1, KAN-456) through the real Core API, runner daemon and
//! `ainkrad-ptyhost`: the client names the session, never the path, and the shell starts in the
//! folder the session's runner reported. The folder lies in the runner's state, which the terminal
//! sandbox hides (as on a real runner): only the session's own folder comes back, and only for a
//! terminal opened for that session. The refusals are `api::v1::tests::folder`.

use super::*;
use ainkrad_core_server::store::agents::{self as store, NewSession};
use ainkrad_proto::v2::{AgentEvents, AgentState};

#[tokio::test]
async fn a_terminal_for_a_session_starts_in_the_sessions_folder() {
    let state = PathBuf::from(format!("/tmp/ath-sess-state-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(state.join("work")).unwrap();
    // Absolute, with no symlink in it (`/tmp` is one on macOS), as the runner reports it.
    let state = state.canonicalize().unwrap();
    std::fs::write(state.join("key-canary"), "KEYCANARY-6620").unwrap();
    let (hide, sessions) = (vec![state.clone()], state.join("agents"));
    let fx = Fx::new_with("t-sess", |c| {
        c.hide = Some(hide);
        c.sessions = Some(sessions);
    })
    .await;
    let dev = fx
        .core
        .device("device", &["read", "terminal", "agent"])
        .await;
    unlock(&fx.core, &dev);
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
    // The session's scratch folder, and the record the runner keeps of it.
    let folder = state.join("work").join(format!("session-{}", s.id));
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("work.txt"), "WORKCANARY-1187").unwrap();
    std::fs::create_dir_all(state.join("agents").join(&s.id)).unwrap();
    std::fs::write(
        state.join("agents").join(&s.id).join("meta.json"),
        json!({"folder": folder}).to_string(),
    )
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
        "args": ["-c", "echo \"at:$(pwd)\"; cat work.txt; cat ../../key-canary 2>/dev/null || echo KEY-HIDDEN; while read -r l; do :; done"],
        "size": {"rows": 24, "cols": 80}});
    let (status, t) = fx.call(&dev, "POST", "/api/v1/terminals", Some(body)).await;
    assert_eq!(status, 201, "{t}");
    let mut c = fx.ws(&dev, t["id"].as_str().unwrap()).await;
    c.read_until("KEY-HIDDEN").await;
    let out = &c.seen;
    assert!(out.contains(&format!("at:{}", folder.display())), "{out}");
    assert!(out.contains("WORKCANARY-1187"), "{out}");
    assert!(!out.contains("KEYCANARY-6620"), "{out}");

    // The same folder named as a plain `cwd` is refused: a sandboxed terminal takes no cwd, only
    // the Core's session path reveals a folder.
    let body = json!({"runner": fx.runner, "cwd": folder, "program": "/bin/sh",
        "size": {"rows": 24, "cols": 80}});
    let (status, t) = fx.call(&dev, "POST", "/api/v1/terminals", Some(body)).await;
    assert_eq!(status, 400, "{t}");
    let _ = std::fs::remove_dir_all(&state);
}
