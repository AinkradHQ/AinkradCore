//! C4b on the driver: `agent.tools` is served only by a runner that lists the capability and only
//! for a running session, and the session's tools socket lives exactly as long as the session.

use ainkrad_proto::v2::{CAP_TOOLS, ToolsPoll};

use super::*;

/// A sandbox that lists the connection tools capability, as a proven Linux runner does.
struct ToolsCapable;

impl Sandbox for ToolsCapable {
    fn name(&self) -> &'static str {
        "tools-capable"
    }
    fn prepare(&self, _: &AgentStart, _: &mut Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
    fn capabilities(&self) -> &'static [&'static str] {
        &[CAP_TOOLS]
    }
}

fn poll(session: &str) -> ToolsPoll {
    ToolsPoll {
        session: session.to_owned(),
        after: 0,
        wait_ms: Some(0),
        results: vec![],
        tools: None,
    }
}

#[tokio::test]
async fn the_capability_is_listed_only_when_the_sandbox_gives_it_and_the_op_follows() {
    let (root, config) = dirs("tools-cap");
    let plain = AgentDriver::new(config, script("true")).unwrap();
    assert!(!plain.info().commands.iter().any(|c| c == CAP_TOOLS));
    let why = plain.tools(&poll("as_a")).await.unwrap_err();
    assert_eq!(why.code, ErrorCode::UnsupportedCommand);
    let (root2, config) = dirs("tools-cap2");
    let capable = AgentDriver::new(config, script("true"))
        .unwrap()
        .with_sandbox(Arc::new(ToolsCapable));
    assert!(capable.info().commands.iter().any(|c| c == CAP_TOOLS));
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(root2);
}

#[tokio::test]
async fn a_poll_serves_a_running_session_only_and_the_socket_goes_with_the_session() {
    let (root, config) = dirs("tools-life");
    let dir = config.dir.clone();
    let gate = root.join("go");
    let s = script(&format!(
        "echo up; while [ ! -e '{}' ]; do sleep 0.05; done; echo done",
        gate.display()
    ));
    let d = Arc::new(
        AgentDriver::new(config, s)
            .unwrap()
            .with_sandbox(Arc::new(ToolsCapable)),
    );
    // Not started: unknown, and no state is made for it.
    assert!(d.tools(&poll("as_a")).await.is_err());
    assert!(!d.tools_port().holds("as_a"));
    d.start(start("as_a", "fake")).unwrap();
    let sock = tools::sock::socket_in(&dir.join("as_a"));
    until("the tools socket", || sock.exists()).await;
    assert!(d.tools(&poll("as_a")).await.is_ok());
    assert!(d.tools_port().holds("as_a"));
    // The socket is the session's alone, 0600, in its 0700 directory.
    assert_eq!(mode(&sock), 0o600);
    std::fs::write(&gate, "").unwrap();
    drain(&d, "as_a").await;
    // Over: no socket file, no state, and a late poll does not bring the state back.
    assert!(!sock.exists(), "the socket outlived the session");
    assert!(d.tools(&poll("as_a")).await.is_err());
    assert!(!d.tools_port().holds("as_a"));
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_new_driver_removes_a_socket_a_crashed_runner_left() {
    let (root, config) = dirs("tools-stale");
    let dir = config.dir.clone();
    let d = Arc::new(AgentDriver::new(config.clone(), script("true")).unwrap());
    d.start(start("as_a", "fake")).unwrap();
    drain(&d, "as_a").await;
    let sock = tools::sock::socket_in(&dir.join("as_a"));
    std::fs::write(&sock, b"stale").unwrap();
    drop(d);
    let _again = AgentDriver::new(config, script("true")).unwrap();
    assert!(!sock.exists(), "a stale socket survived the restart");
    let _ = std::fs::remove_dir_all(root);
}
