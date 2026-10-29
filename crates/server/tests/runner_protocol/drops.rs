//! Provider drops end to end (E15.4): a turn the provider drops mid-work is resumed in the
//! same session inside the same run, which finishes (no new run, no retry); an account that
//! keeps dropping turns unhealthy and the run falls back to the next entry on another account.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::AccountStatus;
use ainkrad_core::org::{AgentId, Harness, ModelRoute};
use ainkrad_core_server::store::exec::list_runs;
use ainkrad_core_server::store::gov::{assign_account, create_account, get_account, new_account};
use ainkrad_core_server::store::org::{get_agent, set_fallbacks, update_agent};
use ainkrad_runner::HarnessExecutor;
use sqlx::SqlitePool;

use super::support::*;
use crate::harness::{agent, assign, company, count, issue, runner};

const FIXTURE: &str = include_str!("../../../harness/tests/fixtures/claude/resume.ndjson");

/// A runner host with a fake `claude` whose first `drops` starts on a `flaky*` model lose
/// the turn: the session begins, a message streams, then the process dies (a reset stream).
fn host(dir: &Path, drops: u32) -> HarnessExecutor {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    std::fs::write(dir.join("left"), drops.to_string()).unwrap();
    let init = serde_json::json!({"type": "system", "subtype": "init", "session_id": "SESSION"});
    let partial = serde_json::json!({"type": "assistant", "message": {"id": "m-drop",
        "content": [{"type": "text", "text": "working"}], "usage": {"input_tokens": 100}}});
    std::fs::write(dir.join("lost.ndjson"), format!("{init}\n{partial}\n")).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\necho \"$*\" >> {d}/starts\nmodel=\n\
         while [ $# -gt 0 ]; do [ \"$1\" = --model ] && model=$2; shift; done\n\
         head -n 2 > /dev/null\nleft=$(cat {d}/left)\n\
         case $model in flaky*) ;; *) left=0 ;; esac\n\
         if [ \"$left\" -gt 0 ]; then echo $((left - 1)) > {d}/left; cat {d}/lost.ndjson; \
         exit 1; fi\ncat {d}/fixture.ndjson\n"
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex
}

/// An agent on `flaky-opus` with a `haiku` fallback, and two Claude accounts of its company.
async fn flaky_agent(pool: &SqlitePool) -> (AgentId, Vec<i64>) {
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let mut a = get_agent(pool, dev).await.unwrap().unwrap();
    a.model = "flaky-opus".to_owned();
    update_agent(pool, &a).await.unwrap();
    let by = AuditActor::System;
    let haiku = ModelRoute {
        harness: Harness::Claude,
        model: "haiku".to_owned(),
    };
    set_fallbacks(pool, dev, &[haiku], by).await.unwrap();
    let mut accounts = vec![];
    for label in ["claude-1", "claude-2"] {
        let new = new_account(pool, Harness::Claude, label, None, None, None, None);
        let made = create_account(pool, &new.await.unwrap(), by).await.unwrap();
        assign_account(pool, made.id, c, true, by).await.unwrap();
        accounts.push(made.id.0);
    }
    assign(pool, issue(pool, p).await, dev).await;
    runner(pool, "box", &[]).await;
    (dev, accounts)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("citadel-drops-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[tokio::test]
async fn a_dropped_turn_resumes_in_the_same_run_and_finishes() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (dev, accounts) = flaky_agent(pool).await;
    setting(pool, "runner.resume_backoff_ms", 10).await;
    let dir = scratch("once");
    stack.runner("box", &[], host(&dir, 1));
    let done = "SELECT count(*) FROM runs WHERE state IN ('succeeded', 'failed')";
    until(pool, "the run to end", done).await;

    let runs = list_runs(pool, dev).await.unwrap();
    assert_eq!(runs.len(), 1, "one run, resumed: not a new run");
    let run = &runs[0];
    assert_eq!(run.terminal_reason.as_deref(), Some("succeeded"));
    assert_eq!(run.model_used.as_deref(), Some("flaky-opus"), "no fallback");
    assert_eq!(run.account_id.map(|a| a.0), Some(accounts[0]));
    let retries = "SELECT count(*) FROM wake_requests WHERE source = 'retry'";
    assert_eq!(count(pool, retries).await, 0, "not a retry wake");
    let starts = std::fs::read_to_string(dir.join("starts")).unwrap();
    let starts: Vec<&str> = starts.lines().collect();
    assert_eq!(starts.len(), 2);
    assert!(starts[1].contains("--resume SESSION"), "{}", starts[1]);
    let drop_sql = format!(
        "SELECT count(*) FROM account_events WHERE kind = 'drop' AND account_id = {}",
        accounts[0]
    );
    until(pool, "the drop to be counted", &drop_sql).await;
    assert_eq!(count(pool, &drop_sql).await, 1);
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'run.provider_dropped'";
    assert_eq!(count(pool, audited).await, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn repeated_drops_mark_the_account_unhealthy_and_the_run_falls_back() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (dev, accounts) = flaky_agent(pool).await;
    setting(pool, "runner.resume_backoff_ms", 10).await;
    let dir = scratch("often");
    stack.runner("box", &[], host(&dir, 99));
    let done = "SELECT count(*) FROM runs WHERE state IN ('succeeded', 'failed')";
    until(pool, "the run to end", done).await;

    let run = list_runs(pool, dev).await.unwrap().remove(0);
    assert_eq!(run.terminal_reason.as_deref(), Some("succeeded"));
    assert_eq!(run.model_used.as_deref(), Some("haiku"));
    assert_eq!(run.account_id.map(|a| a.0), Some(accounts[1]));
    let why = run.fallback_reason.unwrap();
    assert!(
        why.starts_with("claude/flaky-opus: unhealthy: the provider dropped the turn 3 times"),
        "{why}"
    );
    let sick = get_account(pool, ainkrad_core::gov::AccountId(accounts[0]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sick.status, AccountStatus::Unhealthy);
    let starts = std::fs::read_to_string(dir.join("starts")).unwrap();
    assert_eq!(starts.lines().count(), 4, "flaky-opus 3 times, then haiku");
    assert_eq!(list_runs(pool, dev).await.unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
