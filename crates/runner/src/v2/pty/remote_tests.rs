//! A remote runner opens no terminal but the guided sign-in (E15-4, spec §6); the Core host's built-in
//! runner and This Mac keep every terminal.

use std::collections::BTreeMap;

use ainkrad_proto::v2::{ErrorCode, PTY_PURPOSE_LOGIN, PtyOpen, Size};

use super::{PtyConfig, PtyDriver};

fn open(purpose: Option<&str>) -> PtyOpen {
    PtyOpen {
        program: None,
        args: vec![],
        cwd: None,
        session: None,
        env: BTreeMap::new(),
        env_pass: vec![],
        size: Size { rows: 24, cols: 80 },
        watch: false,
        scrollback_bytes: None,
        scrollback_budget: None,
        ssh: None,
        sandbox: None,
        sandbox_user: None,
        purpose: purpose.map(str::to_owned),
    }
}

fn driver() -> PtyDriver {
    let dir = std::env::temp_dir().join(format!("pty-remote-{}", std::process::id()));
    PtyDriver::new(PtyConfig {
        enabled: true,
        ..PtyConfig::new(dir)
    })
}

#[tokio::test]
async fn a_remote_runner_refuses_a_plain_terminal_before_anything_starts() {
    let d = driver().remote();
    for purpose in [None, Some("shell"), Some("")] {
        let e = d.open(&open(purpose)).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::TerminalTargetRemoved, "{purpose:?}");
    }
}

#[tokio::test]
async fn the_sign_in_purpose_gets_past_the_remote_refusal() {
    let d = driver().remote();
    // It goes on to the ordinary checks (here the runner has no host binary or sandbox set up), so
    // whatever the answer is, it is not the refusal.
    let got = d.open(&open(Some(PTY_PURPOSE_LOGIN))).await;
    assert!(got.is_ok() || got.unwrap_err().code != ErrorCode::TerminalTargetRemoved);
}

#[tokio::test]
async fn a_local_runner_is_never_refused_by_target() {
    let d = driver();
    let got = d.open(&open(None)).await;
    assert!(got.is_ok() || got.unwrap_err().code != ErrorCode::TerminalTargetRemoved);
}
