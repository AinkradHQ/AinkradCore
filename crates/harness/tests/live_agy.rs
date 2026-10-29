//! A real agy run, opt-in: `CITADEL_LIVE_AGY=1 cargo test -p ainkrad-harness --test live_agy
//! -- --nocapture`. Runs on the account's Google quota (agy reports no cost). The work dir is a
//! throwaway temp dir, so the spec calls it sandboxed.
//!
//! Auth comes from a logged-in runner home in `CITADEL_LIVE_AGY_HOME` (`HOME=<dir> agy`, which
//! is interactive); a fresh home has no login. `CITADEL_AGY_BIN` swaps the executable, e.g. for
//! a recording wrapper.

use std::path::PathBuf;
use std::time::Duration;

use ainkrad_harness::agy::Agy;
use ainkrad_harness::{Decision, Harness, HarnessEvent, Spec, TurnOutcome};

const CREATE: &str = "Create a file named hello.txt in the current directory containing exactly \
                      the word hi. Use your file-writing tool, then reply with one word: done.";
const COUNT: &str = "Count from 1 to 500, one number per line, no other text.";
const RECALL: &str = "What is the name of the file you created earlier in this conversation? \
                      Reply with only the filename.";

async fn next(h: &mut Agy) -> HarnessEvent {
    let event = tokio::time::timeout(Duration::from_secs(120), h.next())
        .await
        .expect("an event within 2 minutes")
        .expect("the harness is still running");
    eprintln!("  {event:?}");
    event
}

/// Works one turn to its end, allowing every approval; returns the outcome and its text.
async fn turn(h: &mut Agy) -> (TurnOutcome, String, u32) {
    let (mut text, mut approvals) = (String::new(), 0);
    loop {
        match next(h).await {
            HarnessEvent::ApprovalRequested { id, .. } => {
                approvals += 1;
                h.approve(&id, Decision::Allow).await.unwrap();
            }
            HarnessEvent::AssistantText { text: t } => text.push_str(&t),
            HarnessEvent::TurnEnded { outcome } => return (outcome, text, approvals),
            HarnessEvent::Exited { code } => panic!("agy exited mid-turn ({code:?})"),
            _ => {}
        }
    }
}

#[tokio::test]
async fn a_real_sandboxed_turn_an_interrupt_and_a_resume() {
    if std::env::var("CITADEL_LIVE_AGY").as_deref() != Ok("1") {
        eprintln!("skipped: set CITADEL_LIVE_AGY=1 to run against the real agy");
        return;
    }
    let root = std::env::temp_dir().join(format!("citadel-live-agy-{}", std::process::id()));
    let cwd = root.join("work");
    std::fs::create_dir_all(&cwd).unwrap();
    let config_dir = std::env::var_os("CITADEL_LIVE_AGY_HOME")
        .map_or_else(|| root.join("agy-home"), PathBuf::from);
    std::fs::create_dir_all(&config_dir).unwrap();
    let env_allow: Vec<String> = ["PATH", "HOME", "USER", "TMPDIR"].map(str::to_owned).into();
    let spec = Spec {
        program: std::env::var_os("CITADEL_AGY_BIN").map(PathBuf::from),
        cwd: cwd.clone(),
        model: "gemini-3.8-flash-low".to_owned(),
        config_dir,
        env_allow,
        sandboxed: true,
        ..Spec::default()
    };

    let mut h = Agy::start(&spec).await.unwrap();
    h.send(CREATE).await.unwrap();
    let session = match next(&mut h).await {
        HarnessEvent::SessionStarted { id } => id,
        other => panic!("expected the session first, got {other:?}"),
    };
    let (outcome, _, approvals) = turn(&mut h).await;
    assert_eq!(outcome, TurnOutcome::Success);
    assert_eq!(approvals, 0, "agy has no approval channel");
    let file = std::fs::read_to_string(cwd.join("hello.txt")).unwrap();
    assert_eq!(file.trim(), "hi");

    h.send(COUNT).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    h.interrupt().await.unwrap();
    assert_eq!(turn(&mut h).await.0, TurnOutcome::Interrupted);
    let first = h.usage();
    // An interrupt ends agy's process too.
    assert!(matches!(next(&mut h).await, HarnessEvent::Exited { .. }));
    h.stop().await;

    let mut h = Agy::resume(&spec, &session).await.unwrap();
    h.send(RECALL).await.unwrap();
    assert_eq!(
        next(&mut h).await,
        HarnessEvent::SessionStarted { id: session }
    );
    let (outcome, text, _) = turn(&mut h).await;
    assert_eq!(outcome, TurnOutcome::Success);
    assert!(text.contains("hello.txt"), "{text}");
    let total = h.usage();
    h.stop().await;
    eprintln!("usage before resume {first:?}; after {total:?}");
    let _ = std::fs::remove_dir_all(&root);
}
