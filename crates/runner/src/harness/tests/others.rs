//! Codex, OpenCode and agy runs through the executor, each against a fake binary.

use super::*;

const CODEX_FIXTURE: &str =
    include_str!("../../../../harness/tests/fixtures/codex/approve-interrupt.ndjson");

/// A fake `codex` playing a recorded run up to its first `turn/completed`: the executor
/// spawns it with its own `CODEX_HOME`, forwards the session and events, answers the write's
/// approval (outside the run dir, so denied), and maps the turn's end.
#[tokio::test]
async fn works_a_run_through_codex() {
    let dir = scratch("codex");
    std::fs::write(dir.join("fixture.ndjson"), CODEX_FIXTURE).unwrap();
    let bin = dir.join("codex");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh
env > {d}/env
sed '/\"method\":\"turn.completed/q' {d}/fixture.ndjson
             head -n 4 > /dev/null
"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("codex".to_owned(), bin);
    ex.approval_timeout = Duration::from_millis(50);

    let job = Job {
        model: String::new(),
        ..job("codex")
    };
    assert_eq!(ex.start(&job).await, Ok(None));
    let (tx, mut rx) = mpsc::channel(256);
    let outcome = ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    assert_eq!(outcome, Outcome::Succeeded);
    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let home = format!("CODEX_HOME={}", dir.join("config/codex").display());
    assert!(env.lines().any(|l| l == home), "{env}");

    let mut events = vec![];
    for event in chunks(&mut rx) {
        events.push(event);
    }
    assert_eq!(events[0]["type"], "session_started");
    let denied = events
        .iter()
        .find(|e| e["type"] == "approval_decided")
        .expect("the recorded write asks under the default policy");
    assert_eq!(denied["tool"], "fileChange");
    assert_eq!(denied["approved"], false);
    for kind in ["tool_use", "approval_requested", "usage", "turn_ended"] {
        assert!(events.iter().any(|e| e["type"] == kind), "{kind} missing");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// OpenCode is dispatched to its adapter: a server that never listens fails the start.
#[tokio::test]
async fn an_opencode_server_that_never_listens_fails_the_run() {
    let dir = scratch("opencode");
    let bin = dir.join("opencode");
    std::fs::write(&bin, "#!/bin/sh\necho 'no port today'\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("opencode".to_owned(), bin);
    let job = Job {
        model: String::new(),
        ..job("opencode")
    };
    assert_eq!(ex.start(&job).await, Ok(None));
    let (tx, _rx) = mpsc::channel(8);
    let Outcome::Failed {
        reason,
        fingerprint,
    } = ex.run(&job, RunToken::new("t".to_owned()), tx).await
    else {
        panic!("expected a failure");
    };
    assert!(reason.contains("exited before listening"), "{reason}");
    assert_eq!(fingerprint.as_deref(), Some("harness_start"));
    let _ = std::fs::remove_dir_all(&dir);
}

const AGY_FIXTURE: &str =
    include_str!("../../../../harness/tests/fixtures/agy/sandboxed-interrupt.ndjson");

/// agy only for a sandboxed project on a sandboxed runner: refused otherwise; worked through a fake `agy` playing
/// its recorded first turn when the runner says its workspaces are sandboxes.
#[tokio::test]
async fn works_a_run_through_agy_only_when_sandboxed() {
    let dir = scratch("agy");
    std::fs::write(dir.join("fixture.ndjson"), AGY_FIXTURE).unwrap();
    let bin = dir.join("agy");
    let d = dir.display();
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nenv > {d}/env\nhead -n 1 > /dev/null\n\
             sed '/SUCCESS/q' {d}/fixture.ndjson\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("agy".to_owned(), bin);
    let job = job("agy");
    let token = || RunToken::new("t".to_owned());

    assert_eq!(ex.start(&job).await, Ok(None));
    let (tx, _rx) = mpsc::channel(64);
    let Outcome::Failed { reason, .. } = ex.run(&job, token(), tx).await else {
        panic!("agy ran unsandboxed");
    };
    assert!(reason.contains("sandboxed"), "{reason}");
    assert!(!dir.join("env").exists(), "never spawned");

    // A sandboxed runner is not enough: the project must let the harness act unasked.
    ex.sandboxed = true;
    let (tx, _rx) = mpsc::channel(64);
    assert!(matches!(
        ex.run(&job, token(), tx).await,
        Outcome::Failed { .. }
    ));
    assert!(!dir.join("env").exists(), "never spawned");
    let job = Job {
        policy: Policy {
            mode: PermissionMode::Sandboxed,
            allow: vec![],
            sandboxed: true,
        },
        ..job
    };
    let (tx, mut rx) = mpsc::channel(64);
    assert_eq!(ex.run(&job, token(), tx).await, Outcome::Succeeded);
    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    let home = format!("HOME={}", dir.join("config/agy").display());
    assert!(env.lines().any(|l| l == home), "{env}");
    // agy's own HOME does not move git's config: it stays the runner's.
    let git = format!(
        "GIT_CONFIG_GLOBAL={}",
        dir.join("config/git/config").display()
    );
    assert!(env.lines().any(|l| l == git), "{env}");
    let mut types = vec![];
    for event in chunks(&mut rx) {
        types.push(event["type"].as_str().unwrap().to_owned());
    }
    assert_eq!(types.first().map(String::as_str), Some("session_started"));
    for kind in ["tool_use", "assistant_text", "usage", "turn_ended"] {
        assert!(
            types.iter().any(|t| t == kind),
            "{kind} missing from {types:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
