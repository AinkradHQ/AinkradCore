//! Fallbacks end to end (E15.3): an agent whose model the provider refuses has its run moved
//! to the next (harness, model) of its chain, on that entry's own account; the run completes
//! there and shows the model it used and why.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::org::{Harness, ModelRoute};
use ainkrad_core_server::store::exec::list_runs;
use ainkrad_core_server::store::gov::{assign_account, create_account, new_account};
use ainkrad_core_server::store::org::{get_agent, set_fallbacks, update_agent};
use ainkrad_runner::HarnessExecutor;

use super::support::*;
use crate::harness::{agent, assign, company, count, issue, runner};

const FIXTURE: &str = include_str!("../../../harness/tests/fixtures/claude/resume.ndjson");

/// A runner host with a fake `claude` that refuses `--model bad*` as Claude refuses an
/// unknown model and plays a recorded turn for any other.
fn host(dir: &Path) -> HarnessExecutor {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let refused = serde_json::json!({"type": "result", "subtype": "success", "is_error": true,
        "api_error_status": 404, "usage": {}, "result": "There's an issue with the selected \
        model (MODEL). It may not exist or you may not have access to it."});
    std::fs::write(dir.join("refused.ndjson"), format!("{refused}\n")).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\nmodel=\nwhile [ $# -gt 0 ]; do [ \"$1\" = --model ] && model=$2; shift; done\n\
         echo \"$model $CLAUDE_CONFIG_DIR\" >> {d}/models\nhead -n 2 > /dev/null\n\
         case $model in\nbad*) sed \"s/MODEL/$model/\" {d}/refused.ndjson ;;\n\
         *) cat {d}/fixture.ndjson ;;\nesac\n"
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex
}

#[tokio::test]
async fn a_refused_model_falls_back_and_the_run_shows_why() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let mut a = get_agent(pool, dev).await.unwrap().unwrap();
    a.model = "bad-opus".to_owned();
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

    let dir = std::env::temp_dir().join(format!("citadel-fallbacks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    stack.runner("box", &[], host(&dir));
    let done = "SELECT count(*) FROM runs WHERE state IN ('succeeded', 'failed')";
    until(pool, "the run to end", done).await;

    let run = list_runs(pool, dev).await.unwrap().remove(0);
    assert_eq!(run.terminal_reason.as_deref(), Some("succeeded"));
    assert_eq!(run.model_used.as_deref(), Some("haiku"));
    assert_eq!(
        run.account_id.map(|a| a.0),
        Some(accounts[1]),
        "the fallback's own account"
    );
    let why = run.fallback_reason.unwrap();
    assert!(
        why.starts_with("claude/bad-opus: model_unavailable: There's an issue with the selected model (bad-opus)"),
        "{why}"
    );
    let models = std::fs::read_to_string(dir.join("models")).unwrap();
    let config = |label: &str| dir.join(format!("config/accounts/{label}"));
    assert_eq!(
        models,
        format!(
            "bad-opus {}\nhaiku {}\n",
            config("claude-1").display(),
            config("claude-2").display()
        )
    );
    let audited = "SELECT count(*) FROM audit_events WHERE action = 'run.fallback'";
    assert_eq!(count(pool, audited).await, 1);
    let _ = std::fs::remove_dir_all(&dir);
}
