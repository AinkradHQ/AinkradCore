//! Account usage limits (E15.2): counted against rolling windows with exact numbers, a warning
//! once at the threshold, `limited` at the limit and skipped, restored once the window rolls;
//! the harness's own plan-limit report; the report per account and per company.

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunEvent;
use citadel_core::gov::{AccountId, AccountStatus, LimitUnit, NewAccountLimit};
use serde_json::json;

use super::wake::{runner, wake};
use super::*;
use crate::store::gov::{
    account_usage, apply_signal, assign_account, create_account, get_account, new_account,
    run_account, set_account_limit,
};

const BY: AuditActor = AuditActor::User(UserId(1));

/// `2026-10-22T<h>:<m>:<s>.000Z`, from 10:00:00 plus `secs`.
fn at(secs: i64) -> String {
    let t = 10 * 3600 + secs;
    format!(
        "2026-10-22T{:02}:{:02}:{:02}.000Z",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

async fn account(pool: &SqlitePool, label: &str, companies: &[CompanyId]) -> AccountId {
    let new = new_account(pool, Harness::Claude, label, None, None, None, None)
        .await
        .unwrap();
    let a = create_account(pool, &new, BY).await.unwrap();
    for c in companies {
        assign_account(pool, a.id, *c, true, BY).await.unwrap();
    }
    a.id
}

async fn limit(pool: &SqlitePool, a: AccountId, window_secs: i64, unit: LimitUnit, max: i64) {
    let new = NewAccountLimit {
        window_secs,
        unit,
        max,
        warn_percent: Some(80),
    };
    set_account_limit(pool, a, new, BY, &at(0)).await.unwrap();
}

async fn status(pool: &SqlitePool, a: AccountId) -> AccountStatus {
    get_account(pool, a).await.unwrap().unwrap().status
}

async fn audits(pool: &SqlitePool, action: &str) -> Vec<serde_json::Value> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = ? AND entity_kind = 'account' ORDER BY seq",
    )
    .bind(action)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.iter()
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

/// Dispatches a wake of `dev` on a fresh issue of `project` at `secs`; the run, if any.
async fn run_at(
    pool: &SqlitePool,
    dev: AgentId,
    project: i64,
    r: RunnerId,
    secs: i64,
) -> Option<Run> {
    let i = NewIssue {
        project_id: citadel_core::work::ProjectId(project),
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: String::new(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    let i = create_issue(pool, &i).await.unwrap().id;
    enqueue_wake(pool, &wake(dev, Some(i), &format!("w{secs}-{}", dev.0)))
        .await
        .unwrap();
    dispatch_next(pool, r, &[], &Harness::ALL, &at(secs))
        .await
        .unwrap()
}

/// Ends a dispatched run.
async fn finish(pool: &SqlitePool, run: &Run, secs: i64) {
    let by = AuditActor::Runner(run.runner_id.unwrap());
    start_run(pool, run.id, by, None, &at(secs)).await.unwrap();
    transition_run(pool, run.id, by, &RunEvent::Succeed, &at(secs))
        .await
        .unwrap();
}

/// A company with a project and an agent: (company, project id, agent).
async fn shop(pool: &SqlitePool, name: &str) -> (CompanyId, i64, AgentId) {
    let c = create_company(pool, name).await.unwrap().id;
    let dev = agent(pool, c).await;
    let i = issue(pool, c).await;
    let project: i64 = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
        .bind(i.0)
        .fetch_one(pool)
        .await
        .unwrap();
    (c, project, dev)
}

fn tokens(n: i64) -> Usage {
    Usage {
        input_tokens: n,
        output_tokens: 0,
        cache_tokens: 0,
        cost_usd_micros: None,
    }
}

#[tokio::test]
async fn a_token_limit_warns_once_limits_skips_and_rolls_over() {
    let db = db().await;
    let pool = &db.pool;
    let (c, project, dev) = shop(pool, "A").await;
    let first = account(pool, "first", &[c]).await;
    limit(pool, first, 5 * 3600, LimitUnit::Tokens, 1000).await;
    let r = runner(pool, "box").await;

    let run = run_at(pool, dev, project, r, 0).await.unwrap();
    assert_eq!(run_account(pool, run.id).await.unwrap().unwrap().id, first);
    // 799 at +1m, 1 more at +2m (80%: one warning), 200 more at +3m (the limit).
    for (seq, (total, secs)) in [(799, 60), (800, 120), (999, 150), (1000, 180)]
        .into_iter()
        .enumerate()
    {
        record_run_usage(pool, &run, seq as u64 + 1, &tokens(total), &at(secs))
            .await
            .unwrap();
        if total == 799 {
            assert!(audits(pool, "account.warning").await.is_empty(), "79.9%");
        }
    }
    let warned = audits(pool, "account.warning").await;
    assert_eq!(warned.len(), 1, "once per window: {warned:?}");
    assert_eq!(warned[0]["used"], 800);
    assert_eq!(warned[0]["max"], 1000);
    assert_eq!(warned[0]["percent"], 80);
    assert_eq!(status(pool, first).await, AccountStatus::Limited);
    let a = get_account(pool, first).await.unwrap().unwrap();
    assert_eq!(
        a.status_reason.as_deref(),
        Some("5h tokens limit reached: 1000 of 1000")
    );
    finish(pool, &run, 200).await;

    // Skipped: a second account takes the next run; with it off, runs wait.
    let second = account(pool, "second", &[c]).await;
    let next = run_at(pool, dev, project, r, 240).await.unwrap();
    assert_eq!(
        run_account(pool, next.id).await.unwrap().unwrap().id,
        second
    );
    finish(pool, &next, 240).await;
    crate::store::gov::set_account_status(pool, second, AccountStatus::Disabled, None, BY)
        .await
        .unwrap();
    assert!(run_at(pool, dev, project, r, 300).await.is_none());

    // 5 h after +30 s every token is still inside the window; 5 h after +1 m the first 799
    // have left it (201 of 1000) and the account is back, its wake dispatched.
    let still = dispatch_next(pool, r, &[], &Harness::ALL, &at(5 * 3600 + 30)).await;
    assert!(still.unwrap().is_none());
    assert_eq!(status(pool, first).await, AccountStatus::Limited);
    let back = dispatch_next(pool, r, &[], &Harness::ALL, &at(5 * 3600 + 60))
        .await
        .unwrap()
        .expect("the window rolled");
    assert_eq!(run_account(pool, back.id).await.unwrap().unwrap().id, first);
    assert_eq!(audits(pool, "account.restored").await.len(), 1);
}

#[tokio::test]
async fn a_message_limit_counts_prompts_and_the_least_used_account_goes_first() {
    let db = db().await;
    let pool = &db.pool;
    let (c, project, dev) = shop(pool, "A").await;
    let busy = account(pool, "busy", &[c]).await;
    let idle = account(pool, "idle", &[c]).await;
    for a in [busy, idle] {
        limit(pool, a, 7 * 86_400, LimitUnit::Messages, 3).await;
    }
    let r = runner(pool, "box").await;
    // busy, idle, busy, idle: equal use, least recently used first; then both full.
    let mut used = vec![];
    for n in 0..6 {
        match run_at(pool, dev, project, r, n * 60).await {
            Some(run) => {
                used.push(run_account(pool, run.id).await.unwrap().unwrap().id);
                finish(pool, &run, n * 60).await;
            }
            None => used.push(AccountId(0)),
        }
    }
    assert_eq!(used, [busy, idle, busy, idle, busy, idle]);
    assert_eq!(status(pool, busy).await, AccountStatus::Limited);
    assert_eq!(status(pool, idle).await, AccountStatus::Limited);
    assert!(
        run_at(pool, dev, project, r, 400).await.is_none(),
        "3 of 3 each"
    );
    let limited = audits(pool, "account.limited").await;
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0]["unit"], "messages");
    assert_eq!(limited[0]["used"], 3);
}

#[tokio::test]
async fn the_least_used_in_its_window_goes_before_the_least_recent() {
    let db = db().await;
    let pool = &db.pool;
    let (c, project, dev) = shop(pool, "A").await;
    let (heavy, light) = (
        account(pool, "heavy", &[c]).await,
        account(pool, "light", &[c]).await,
    );
    for a in [heavy, light] {
        limit(pool, a, 3600, LimitUnit::Tokens, 10_000).await;
    }
    let r = runner(pool, "box").await;
    let one = run_at(pool, dev, project, r, 0).await.unwrap();
    assert_eq!(run_account(pool, one.id).await.unwrap().unwrap().id, heavy);
    record_run_usage(pool, &one, 1, &tokens(5000), &at(10))
        .await
        .unwrap();
    finish(pool, &one, 10).await;
    let two = run_at(pool, dev, project, r, 20).await.unwrap();
    assert_eq!(run_account(pool, two.id).await.unwrap().unwrap().id, light);
    record_run_usage(pool, &two, 1, &tokens(100), &at(30))
        .await
        .unwrap();
    finish(pool, &two, 30).await;
    // light was used last, but holds 1% against heavy's 50%.
    let three = run_at(pool, dev, project, r, 40).await.unwrap();
    assert_eq!(
        run_account(pool, three.id).await.unwrap().unwrap().id,
        light
    );
}

#[tokio::test]
async fn the_harness_report_warns_and_limits_until_its_reset() {
    let db = db().await;
    let pool = &db.pool;
    let (c, project, dev) = shop(pool, "A").await;
    let a = account(pool, "claude-plan", &[c]).await;
    let r = runner(pool, "box").await;
    let run = run_at(pool, dev, project, r, 0).await.unwrap();
    // 2026-10-22T15:00:00Z, five hours on.
    let reset = 1_792_681_200_i64;
    let report = |status: &str, five: f64| {
        json!({"type": "rate_limit", "status": status, "windows": [
            {"name": "five_hour", "utilization": five, "resets_at": reset},
            {"name": "seven_day", "utilization": 0.5, "resets_at": reset + 86_400}]})
    };
    apply_signal(pool, run.id, &report("allowed", 0.13), &at(1))
        .await
        .unwrap();
    assert!(audits(pool, "account.warning").await.is_empty());
    apply_signal(pool, run.id, &report("allowed_warning", 0.85), &at(2))
        .await
        .unwrap();
    apply_signal(pool, run.id, &report("allowed_warning", 0.9), &at(3))
        .await
        .unwrap();
    let warned = audits(pool, "account.warning").await;
    assert_eq!(warned.len(), 1, "on crossing only: {warned:?}");
    assert_eq!(warned[0]["window"], "five_hour");
    assert_eq!(warned[0]["percent"], 85);
    assert_eq!(status(pool, a).await, AccountStatus::Active);
    apply_signal(pool, run.id, &report("rejected", 1.0), &at(4))
        .await
        .unwrap();
    let limited = get_account(pool, a).await.unwrap().unwrap();
    assert_eq!(limited.status, AccountStatus::Limited);
    assert_eq!(
        limited.status_until.as_deref(),
        Some("2026-10-22T15:00:00.000Z")
    );
    finish(pool, &run, 5).await;
    assert!(
        run_at(pool, dev, project, r, 4 * 3600).await.is_none(),
        "before the reset"
    );
    let after = dispatch_next(pool, r, &[], &Harness::ALL, &at(5 * 3600))
        .await
        .unwrap();
    assert!(after.is_some(), "the reset passed");
    assert_eq!(status(pool, a).await, AccountStatus::Active);
    // Another type of chunk, or a run with no account, changes nothing.
    apply_signal(pool, run.id, &json!({"type": "usage"}), &at(6))
        .await
        .unwrap();
    let usage = account_usage(pool, &at(5 * 3600)).await.unwrap();
    assert_eq!(usage[0].signal.as_ref().unwrap()["status"], "rejected");
}

#[tokio::test]
async fn usage_is_reported_per_account_and_per_company() {
    let db = db().await;
    let pool = &db.pool;
    let (a, pa, dev_a) = shop(pool, "A").await;
    let (b, pb, dev_b) = shop(pool, "B").await;
    let shared = account(pool, "shared", &[a, b]).await;
    limit(pool, shared, 3600, LimitUnit::Tokens, 100_000).await;
    let r = runner(pool, "box").await;
    for (dev, project, n, secs) in [
        (dev_a, pa, 300, 0),
        (dev_a, pa, 200, 60),
        (dev_b, pb, 50, 120),
    ] {
        let run = run_at(pool, dev, project, r, secs).await.unwrap();
        record_run_usage(pool, &run, 1, &tokens(n), &at(secs + 1))
            .await
            .unwrap();
        finish(pool, &run, secs + 2).await;
    }
    let report = account_usage(pool, &at(200)).await.unwrap();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].limits[0].used, 550);
    let per: Vec<(i64, i64, i64, i64)> = report[0]
        .companies
        .iter()
        .map(|c| (c.company_id, c.tokens, c.messages, c.runs))
        .collect();
    assert_eq!(per, [(a.0, 500, 2, 2), (b.0, 50, 1, 1)]);
    // An hour after the first run its 300 tokens have left the window; the totals stay.
    let later = account_usage(pool, &at(3601)).await.unwrap();
    assert_eq!(later[0].limits[0].used, 250);
    assert_eq!(later[0].companies[0].tokens, 500);
}

/// R18: a project's `max_parallel_runs` holds a second issue's wake back while the cap is full.
#[tokio::test]
async fn a_project_at_its_parallel_run_cap_holds_wakes_back() {
    let db = db().await;
    let pool = &db.pool;
    let (_, project, dev) = shop(pool, "A").await;
    let r = runner(pool, "r").await;
    sqlx::query("UPDATE projects SET max_parallel_runs = 1 WHERE id = ?")
        .bind(project)
        .execute(pool)
        .await
        .unwrap();
    let first = run_at(pool, dev, project, r, 0).await.unwrap();
    assert!(
        run_at(pool, dev, project, r, 1).await.is_none(),
        "cap of 1 is full"
    );
    finish(pool, &first, 2).await;
    assert!(
        run_at(pool, dev, project, r, 3).await.is_some(),
        "slot freed"
    );
}

/// R18: a project's `runner_tags` are required of the runner, on top of the agent's own.
#[tokio::test]
async fn a_project_only_dispatches_to_runners_with_its_tags() {
    let db = db().await;
    let pool = &db.pool;
    let (_, project, dev) = shop(pool, "A").await;
    let r = runner(pool, "r").await;
    sqlx::query("UPDATE projects SET runner_tags = '[\"gpu\"]' WHERE id = ?")
        .bind(project)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        run_at(pool, dev, project, r, 0).await.is_none(),
        "untagged runner"
    );
    let tagged = ["gpu".to_owned()];
    let run = dispatch_next(pool, r, &tagged, &Harness::ALL, &at(1)).await;
    assert!(
        run.unwrap().is_some(),
        "runner with the tag takes the waiting wake"
    );
}
