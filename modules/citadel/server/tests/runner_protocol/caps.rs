//! Token caps end to end (E3.8): the server caps the run from its budgets, a real
//! `HarnessExecutor` drives a fake `claude` playing a recorded turn, stops it at the cap,
//! and the server records the usage and ends the run `failed: token_cap`, with no retry.

use std::os::unix::fs::PermissionsExt;

use citadel_core::exec::{RunState, Usage};
use citadel_core::gov::{BudgetPeriod, BudgetScope, NewBudget};
use citadel_server::store::exec::{list_cost_events, list_runs, list_wake_requests};
use citadel_server::store::gov::create_budget;
use ainkrad_runner::HarnessExecutor;

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

const FIXTURE: &str =
    include_str!("../../../../../crates/harness/tests/fixtures/claude/approve-interrupt.ndjson");

#[tokio::test]
async fn a_capped_run_ends_token_cap_with_its_usage_recorded() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let budget = NewBudget {
        scope: BudgetScope::Agent(dev),
        period: BudgetPeriod::Total,
        token_cap: 100,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    create_budget(pool, &budget).await.unwrap();
    assign(pool, issue(pool, p).await, dev).await;
    runner(pool, "box", &[]).await;

    let dir = std::env::temp_dir().join(format!("citadel-caps-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let script = format!(
        "#!/bin/sh\nhead -n 2 > /dev/null\nsed '/\"type\":\"result\"/q' {}\n",
        dir.join("fixture.ndjson").display()
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut executor = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    executor.bins.insert("claude".to_owned(), bin);
    // The recorded write escalates; nobody reviews it here, and the runner gives up after the
    // server's setting.
    setting(pool, "approval.deadline.permission_escalation", 1).await;
    stack.runner("box", &[], executor);

    let ended = "SELECT count(*) FROM runs WHERE state = 'failed'";
    until(pool, "the capped run to end", ended).await;
    let run = list_runs(pool, dev).await.unwrap().remove(0);
    assert_eq!(run.state, RunState::Failed);
    assert_eq!(run.terminal_reason.as_deref(), Some("token_cap"));
    // The turn's first assistant message: 2 in, 3 out, 13163 + 6096 cache.
    let spent = Usage {
        input_tokens: 2,
        output_tokens: 3,
        cache_tokens: 19259,
        cost_usd_micros: None,
    };
    assert_eq!(run.usage, spent);
    let ledger = list_cost_events(pool, run.id).await.unwrap();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert_eq!(ledger[0].usage, spent);
    let wakes = list_wake_requests(pool, dev).await.unwrap();
    assert_eq!(
        wakes.len(),
        1,
        "a token-capped run is never retried: {wakes:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
