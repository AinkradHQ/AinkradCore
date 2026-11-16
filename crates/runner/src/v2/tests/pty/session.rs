//! A terminal for an AI session under the terminal sandbox: the session's folder lies in the
//! runner's hidden state, and only a terminal opened for that session, in the folder the runner
//! recorded for it, gets in; nothing else of the state comes with it.

use super::*;

struct Setup {
    base: std::path::PathBuf,
    state: std::path::PathBuf,
    work: std::path::PathBuf,
    folder: std::path::PathBuf,
    driver: Arc<PtyDriver>,
}

/// A runner state with session `as_mine` recorded in `<work>/session-as_mine`, another session's
/// folder next to it, and a key canary in the state; shells sandboxed with `user`, if any.
fn setup() -> Setup {
    let base = tmp();
    let state = base.join("state");
    let terminals = state.join("terminals");
    let [_, work] = super::super::super::cli::runtime_paths(&state);
    let folder = work.join("session-as_mine");
    std::fs::create_dir_all(&terminals).unwrap();
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::create_dir_all(work.join("session-as_other")).unwrap();
    std::fs::create_dir_all(state.join("agents/as_mine")).unwrap();
    std::fs::write(folder.join("work.txt"), "WORKCANARY-2210").unwrap();
    std::fs::write(work.join("session-as_other/o.txt"), "OTHERCANARY-5803").unwrap();
    std::fs::write(state.join("key-canary"), "KEYCANARY-9114").unwrap();
    let meta = serde_json::json!({"folder": folder});
    std::fs::write(state.join("agents/as_mine/meta.json"), meta.to_string()).unwrap();
    let host = ainkrad_ptyhost::client::find_host_binary()
        .expect("ainkrad-ptyhost is built next to the tests (cargo test --workspace)");
    let driver = Arc::new(PtyDriver::new(PtyConfig {
        enabled: true,
        capacity: 4,
        host,
        grace: Duration::from_millis(200),
        hide: Some(super::super::super::termbox::hidden_paths(&state, &[])),
        sessions: Some(state.join("agents")),
        ..PtyConfig::new(terminals)
    }));
    Setup {
        base,
        state,
        work,
        folder,
        driver,
    }
}

fn session_open(script: &str, cwd: &std::path::Path, session: Option<&str>) -> Body {
    let mut o = open_req(script);
    o.cwd = Some(cwd.to_string_lossy().into_owned());
    o.session = session.map(str::to_owned);
    Body::Command(Command::PtyOpen(o))
}

async fn run(core: &mut Core, stream: u64, open: Body) -> String {
    core.send(stream, open).await;
    let mut out = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(8),
        until(core, stream, &mut out, |o, b| {
            o.contains("PROBE-DONE") || matches!(b, Body::Result(_) | Body::Error(_))
        }),
    )
    .await;
    out
}

#[tokio::test]
async fn a_session_terminal_reaches_its_folder_and_nothing_else_of_the_hidden_state() {
    let s = setup();
    let (mut core, _) = Core::start_pty(Arc::clone(&s.driver)).await;
    let script = format!(
        "echo \"at:$(pwd)\"; ls; cat work.txt; echo made > made.txt && echo WROTE; \
         if command -v git >/dev/null; then git init -q && git add made.txt && echo GIT-OK; \
         else echo GIT-OK; fi; \
         cat {st}/key-canary 2>&1; cat {w}/session-as_other/o.txt 2>&1; ls {st} 2>&1; \
         echo PROBE-DONE",
        st = s.state.display(),
        w = s.work.display(),
    );
    let out = run(
        &mut core,
        1,
        session_open(&script, &s.folder, Some("as_mine")),
    )
    .await;
    assert!(out.contains("PROBE-DONE"), "{out:?}");
    assert!(
        out.contains("at:/") && out.contains("session-as_mine") && !out.contains("getcwd"),
        "the shell knows where it is: {out:?}"
    );
    for seen in ["work.txt", "WORKCANARY-2210", "WROTE", "GIT-OK"] {
        assert!(out.contains(seen), "{seen}: {out:?}");
    }
    for leak in ["KEYCANARY-9114", "OTHERCANARY-5803", "agents"] {
        assert!(!out.contains(leak), "{leak}: {out:?}");
    }
    assert!(s.folder.join("made.txt").is_file());

    // The same folder as a plain cwd stays hidden: only the session marker reveals it.
    let plain = run(
        &mut core,
        3,
        session_open("cat work.txt 2>&1; echo PROBE-DONE", &s.folder, None),
    )
    .await;
    assert!(!plain.contains("WORKCANARY-2210"), "{plain:?}");

    // A marker the runner cannot back is refused: another folder, or a session it never had.
    let other = s.work.join("session-as_other");
    core.send(5, session_open("true", &other, Some("as_mine")))
        .await;
    assert_eq!(error(core.answer(5).await), ErrorCode::InvalidArgs);
    core.send(7, session_open("true", &other, Some("as_other")))
        .await;
    assert_eq!(error(core.answer(7).await), ErrorCode::InvalidArgs);
    core.send(9, session_open("true", &s.folder, Some("../agents")))
        .await;
    assert_eq!(error(core.answer(9).await), ErrorCode::InvalidArgs);
    let _ = std::fs::remove_dir_all(&s.base);
    let _ = std::fs::remove_dir_all(&s.work);
}
