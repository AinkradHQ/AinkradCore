//! Budgets at work (E7.2): a hard stop blocks new runs at admission until an overrun is
//! approved, with one approval per budget and period; a warning goes out once per period; the
//! spend counters always match a recount of the ledger, and the mid-run cap reads them too.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{ApprovalKind, ApprovalStatus, BudgetPeriod, BudgetScope, NewBudget};

use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::gov::{
    approve_budget_raise, decide_approval, list_approvals, recompute_budget_spend, set_budget,
};
use crate::store::org::get_agent;

const NOW: &str = "2026-10-22T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

async fn budget(pool: &SqlitePool, scope: BudgetScope, period: BudgetPeriod, cap: i64) {
    let b = NewBudget {
        scope,
        period,
        token_cap: cap,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: true,
    };
    set_budget(pool, &b, BY).await.unwrap();
}

/// `dev` spends `tokens` (as one usage report of a run with no issue) at `at`.
async fn spend(pool: &SqlitePool, dev: AgentId, issue: Option<IssueId>, tokens: i64, at: &str) {
    let run = create_run(pool, &new_run(dev, issue)).await.unwrap();
    let usage = Usage {
        input_tokens: tokens,
        output_tokens: 0,
        cache_tokens: 0,
        cost_usd_micros: None,
    };
    record_run_usage(pool, &run, 1, &usage, at).await.unwrap();
}

async fn count(pool: &SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn an_exhausted_budget_blocks_new_runs_until_an_overrun_is_approved() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    budget(pool, BudgetScope::Agent(dev), BudgetPeriod::Total, 1_000).await;
    spend(pool, dev, None, 1_000, NOW).await;
    enqueue_wake(pool, &wake(dev, Some(i), "go")).await.unwrap();
    let r = runner(pool, "box").await;

    assert_eq!(dispatch(pool, r, NOW).await, None, "blocked at the cap");
    assert_eq!(dispatch(pool, r, NOW).await, None, "still blocked");
    let asked = list_approvals(pool, company).await.unwrap();
    assert_eq!(asked.len(), 1, "one approval per budget and period");
    let a = &asked[0];
    assert_eq!(
        (a.kind, a.requested_by, a.issue_id),
        (ApprovalKind::BudgetOverrun, dev, Some(i))
    );
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap();
    assert_eq!(
        (payload["period"].as_str(), payload["spent"].as_i64()),
        (Some("total"), Some(1_000))
    );
    let exhausted = "SELECT count(*) FROM audit_events WHERE action = 'budget.exhausted'";
    assert_eq!(count(pool, exhausted).await, 1);
    let pending = "SELECT count(*) FROM wake_requests WHERE status = 'pending'";
    assert_eq!(count(pool, pending).await, 1, "the wake waits");

    approve_budget_raise(pool, a.id, 400, UserId(1), Some("one more go"), NOW)
        .await
        .unwrap();
    let run = dispatch(pool, r, NOW)
        .await
        .expect("admitted after the raise");
    assert_eq!((run.agent_id, run.issue_id), (dev, Some(i)));
    let cap = run_token_cap(pool, &run, 1_000_000, NOW).await.unwrap();
    assert_eq!(
        cap, 400,
        "the mid-run cap reads the same counters, raise included"
    );
}

#[tokio::test]
async fn a_rejected_overrun_blocks_until_the_next_period() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    budget(pool, BudgetScope::Company(company), BudgetPeriod::Day, 500).await;
    spend(pool, dev, None, 600, NOW).await;
    enqueue_wake(pool, &wake(dev, Some(i), "go")).await.unwrap();
    let r = runner(pool, "box").await;
    assert_eq!(dispatch(pool, r, NOW).await, None);
    let a = list_approvals(pool, company).await.unwrap().remove(0);
    let no = decide_approval(pool, a.id, false, UserId(1), Some("wait for tomorrow"), NOW);
    assert_eq!(no.await.unwrap().status, ApprovalStatus::Rejected);
    assert_eq!(dispatch(pool, r, NOW).await, None, "still exhausted today");
    assert_eq!(
        list_approvals(pool, company).await.unwrap().len(),
        1,
        "not asked again today"
    );

    let tomorrow = "2026-10-23T00:00:01.000Z";
    let run = dispatch(pool, r, tomorrow)
        .await
        .expect("a new day, a new budget");
    assert_eq!(run.issue_id, Some(i));
}

#[tokio::test]
async fn a_warning_goes_out_once_per_period() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let po = agent(pool, company).await;
    lead_team(pool, dev, po).await;
    sqlx::query("UPDATE team_memberships SET team_role = 'product_owner' WHERE agent_id = ?")
        .bind(po.0)
        .execute(pool)
        .await
        .unwrap();
    budget(pool, BudgetScope::Agent(dev), BudgetPeriod::Week, 1_000).await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let totals = |n| Usage {
        input_tokens: n,
        output_tokens: 0,
        cache_tokens: 0,
        cost_usd_micros: None,
    };
    let warnings = "SELECT count(*) FROM audit_events WHERE action = 'budget.warning'";
    record_run_usage(pool, &run, 1, &totals(700), NOW)
        .await
        .unwrap();
    assert_eq!(count(pool, warnings).await, 0, "70% is under the line");
    record_run_usage(pool, &run, 2, &totals(850), NOW)
        .await
        .unwrap();
    record_run_usage(pool, &run, 3, &totals(990), NOW)
        .await
        .unwrap();
    assert_eq!(count(pool, warnings).await, 1, "once a period");
    let (agent, reason): (i64, String) =
        sqlx::query_as("SELECT agent_id, reason FROM wake_requests WHERE source = 'escalation'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(agent, po.0, "the product owner hears of it");
    assert!(reason.contains("85%"), "{reason}");

    // Next week the counter starts again, and so does the warning.
    let next = "2026-10-27T10:00:00.000Z";
    record_run_usage(pool, &run, 4, &totals(1_900), next)
        .await
        .unwrap();
    assert_eq!(count(pool, warnings).await, 2);
}

#[tokio::test]
async fn the_counters_match_a_full_recount_of_the_ledger() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    let lead = agent(pool, company).await;
    lead_team(pool, dev, lead).await;
    let project: i64 = count(pool, "SELECT project_id FROM issues LIMIT 1").await;
    let dept: i64 = count(pool, "SELECT id FROM departments LIMIT 1").await;
    use BudgetPeriod::*;
    for period in [Day, Week, Month, Total] {
        budget(pool, BudgetScope::Agent(dev), period, 1_000_000).await;
        budget(pool, BudgetScope::Company(company), period, 1_000_000).await;
        budget(
            pool,
            BudgetScope::Department(ainkrad_core::org::DepartmentId(dept)),
            period,
            1_000_000,
        )
        .await;
        budget(
            pool,
            BudgetScope::Project(ainkrad_core::work::ProjectId(project)),
            period,
            1_000_000,
        )
        .await;
    }
    let days = [
        "2026-09-30T23:00:00.000Z",
        "2026-10-01T01:00:00.000Z",
        "2026-10-05T12:00:00.000Z",
        NOW,
    ];
    for (n, at) in days.iter().enumerate() {
        let n = n as i64 + 1;
        spend(pool, dev, Some(i), 100 * n, at).await;
        spend(pool, lead, None, 7 * n, at).await;
    }
    let snapshot = || async {
        sqlx::query_as::<_, (i64, String, i64)>(
            "SELECT budget_id, period_key, tokens FROM budget_spend ORDER BY 1, 2",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    };
    let live = snapshot().await;
    assert_eq!(
        recompute_budget_spend(pool, BY).await.unwrap() as usize,
        live.len()
    );
    assert_eq!(snapshot().await, live);
    let total: i64 = count(
        pool,
        "SELECT sum(input_tokens + output_tokens + cache_tokens) FROM cost_events",
    )
    .await;
    let company_total = live
        .iter()
        .filter(|(_, key, _)| key == "total")
        .map(|r| r.2)
        .max()
        .unwrap();
    assert_eq!(
        company_total, total,
        "the company's all-time counter holds everything"
    );
    let october: Vec<_> = live.iter().filter(|r| r.1 == "2026-10").collect();
    assert!(!october.is_empty());
}

async fn usd_budget(pool: &SqlitePool, scope: BudgetScope, tokens: i64, usd: i64) {
    let b = NewBudget {
        scope,
        period: BudgetPeriod::Total,
        token_cap: tokens,
        usd_cap_micros: Some(usd),
        warn_at_percent: 80,
        hard_stop: true,
    };
    set_budget(pool, &b, BY).await.unwrap();
}

#[tokio::test]
async fn a_dollar_cap_blocks_like_a_token_cap_and_an_overrun_raises_dollars() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    // Dollars only (token cap 0): a run is not capped in tokens, and an issue-scoped one counts.
    usd_budget(pool, BudgetScope::Issue(i), 0, 1_000_000).await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let usage = Usage {
        input_tokens: 10,
        output_tokens: 0,
        cache_tokens: 0,
        cost_usd_micros: Some(1_000_000),
    };
    record_run_usage(pool, &run, 1, &usage, NOW).await.unwrap();
    sqlx::query("UPDATE runs SET state = 'cancelled', terminal_reason = 'cancelled'")
        .execute(pool)
        .await
        .unwrap();
    enqueue_wake(pool, &wake(dev, Some(i), "go")).await.unwrap();
    let r = runner(pool, "box").await;
    assert_eq!(dispatch(pool, r, NOW).await, None, "the dollars ran out");
    let a = list_approvals(pool, company).await.unwrap().remove(0);
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap();
    assert_eq!(payload["unit"], "usd_micros");
    approve_budget_raise(pool, a.id, 500_000, UserId(1), None, NOW)
        .await
        .unwrap();
    let run = dispatch(pool, r, NOW)
        .await
        .expect("admitted after the raise");
    let cap = run_token_cap(pool, &run, 1_000_000, NOW).await.unwrap();
    assert_eq!(cap, 1_000_000, "a dollars-only budget leaves tokens alone");
    let (usd, raised): (i64, i64) =
        sqlx::query_as("SELECT usd_micros, raised_usd_micros FROM budget_spend")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!((usd, raised), (1_000_000, 500_000));
}

#[tokio::test]
async fn pricing_the_past_fills_in_unpriced_events_runs_and_dollar_counters() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = get_agent(pool, dev).await.unwrap().unwrap().company_id;
    usd_budget(pool, BudgetScope::Company(company), 0, 10_000_000).await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let usage = Usage {
        input_tokens: 1_000_000,
        output_tokens: 500_000,
        cache_tokens: 0,
        cost_usd_micros: None,
    };
    record_run_usage(pool, &run, 1, &usage, NOW).await.unwrap();
    let model: String = sqlx::query_scalar("SELECT model FROM agents WHERE id = ?")
        .bind(dev.0)
        .fetch_one(pool)
        .await
        .unwrap();
    let seen = crate::store::gov::unpriced(pool, company).await.unwrap();
    assert_eq!(
        (seen.len(), seen[0].runs, seen[0].tokens, &seen[0].model),
        (1, 1, 1_500_000, &model)
    );

    // From now on leaves the past alone.
    let rates = [2_000_000, 4_000_000, 0];
    let (_, n) =
        crate::store::gov::set_price_from(pool, Harness::Claude, &model, rates, false, BY, NOW)
            .await
            .unwrap();
    assert_eq!(n, 0);
    assert_eq!(
        crate::store::gov::unpriced(pool, company)
            .await
            .unwrap()
            .len(),
        1
    );

    // The past: 1M in at $2 plus 0.5M out at $4 is $4.
    let (_, n) =
        crate::store::gov::set_price_from(pool, Harness::Claude, &model, rates, true, BY, NOW)
            .await
            .unwrap();
    assert_eq!(n, 1);
    assert!(
        crate::store::gov::unpriced(pool, company)
            .await
            .unwrap()
            .is_empty()
    );
    let (event, priced, run_cost): (i64, bool, i64) = sqlx::query_as(
        "SELECT c.cost_usd_micros, r.priced, r.cost_usd_micros FROM cost_events c \
         JOIN runs r ON r.id = c.run_id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((event, priced, run_cost), (4_000_000, true, 4_000_000));
    let usd: i64 = count(pool, "SELECT usd_micros FROM budget_spend").await;
    assert_eq!(usd, 4_000_000, "the dollar counter was recounted");
    // A priced event is never re-costed.
    let again =
        crate::store::gov::set_price_from(pool, Harness::Claude, &model, [9, 9, 9], true, BY, NOW)
            .await
            .unwrap();
    assert_eq!(again.1, 0);
}
