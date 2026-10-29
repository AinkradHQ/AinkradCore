//! Token caps from budgets, and usage recorded mid-run (E3.8).

use citadel_core::gov::{BudgetPeriod, BudgetScope, NewBudget};
use citadel_core::org::{TeamMembership, TeamRole};
use citadel_core::work::{NewSprint, SprintState};

use super::*;
use crate::store::gov::set_budget;
use crate::store::org::{create_department, create_membership, create_team};
use crate::store::work::{create_sprint, get_issue};

const NOW: &str = "2026-10-21T10:00:00.000Z";
const DEFAULT: u64 = 1_000_000;

async fn budget(pool: &SqlitePool, scope: BudgetScope, period: BudgetPeriod, cap: i64, hard: bool) {
    let b = NewBudget {
        scope,
        period,
        token_cap: cap,
        usd_cap_micros: None,
        warn_at_percent: 80,
        hard_stop: hard,
    };
    let by = citadel_core::audit::AuditActor::User(citadel_core::work::UserId(1));
    set_budget(pool, &b, by).await.unwrap();
}

fn tokens(input: i64, output: i64, cache: i64) -> Usage {
    Usage {
        input_tokens: input,
        output_tokens: output,
        cache_tokens: cache,
        cost_usd_micros: None,
    }
}

/// A finished run of `dev` on `i` that spent `spent` tokens, recorded at `at`.
async fn spent(pool: &SqlitePool, dev: AgentId, i: IssueId, spent: i64, at: &str) {
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    record_run_usage(pool, &run, 1, &tokens(spent, 0, 0), at)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn no_budget_means_the_default_cap_never_unlimited() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    assert_eq!(
        run_token_cap(pool, &run, DEFAULT, NOW).await.unwrap(),
        DEFAULT
    );
    let none = create_run(pool, &new_run(dev, None)).await.unwrap();
    assert_eq!(run_token_cap(pool, &none, 7, NOW).await.unwrap(), 7);
    assert!(run_token_cap(pool, &run, DEFAULT, "soon").await.is_err());
}

/// The cap is the least left in any hard-stop budget that applies: agent, company,
/// department, project, sprint. Warn-only budgets, other agents' budgets and spend outside a
/// budget's period do not count.
#[tokio::test]
async fn the_cap_is_the_least_left_of_the_budgets_that_apply() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let issue = get_issue(pool, i).await.unwrap().unwrap();
    let company: CompanyId = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(dev.0)
        .fetch_one(pool)
        .await
        .map(CompanyId)
        .unwrap();
    let other = agent(pool, company).await;
    let run = create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let cap = || run_token_cap(pool, &run, DEFAULT, NOW);
    use BudgetPeriod::*;

    budget(pool, BudgetScope::Agent(dev), Total, 9_000, true).await;
    budget(pool, BudgetScope::Agent(other), Total, 10, true).await;
    budget(pool, BudgetScope::Company(company), Total, 50, false).await;
    assert_eq!(
        cap().await.unwrap(),
        9_000,
        "warn-only and others' budgets do not apply"
    );

    // 3000 spent by dev this hour, 2000 by the other agent two days ago, same issue.
    spent(pool, dev, i, 3_000, "2026-10-21T09:00:00.000Z").await;
    spent(pool, other, i, 2_000, "2026-10-19T10:00:00.000Z").await;
    assert_eq!(cap().await.unwrap(), 6_000);
    budget(
        pool,
        BudgetScope::Project(issue.project_id),
        Day,
        4_000,
        true,
    )
    .await;
    assert_eq!(
        cap().await.unwrap(),
        1_000,
        "a day counts only today's 3000"
    );
    budget(
        pool,
        BudgetScope::Project(issue.project_id),
        Week,
        5_500,
        true,
    )
    .await;
    assert_eq!(cap().await.unwrap(), 500, "a week counts both");

    let dept = create_department(pool, company, "Eng").await.unwrap();
    let team = create_team(pool, dept.id, "Core").await.unwrap();
    let member = TeamMembership {
        team_id: team.id,
        agent_id: dev,
        team_role: TeamRole::Member,
    };
    create_membership(pool, &member).await.unwrap();
    budget(pool, BudgetScope::Department(dept.id), Total, 3_200, true).await;
    assert_eq!(
        cap().await.unwrap(),
        200,
        "the department counts its members' 3000"
    );

    let s = NewSprint {
        project_id: issue.project_id,
        name: "S1".to_owned(),
        goal: String::new(),
        state: SprintState::Planned,
        starts_on: None,
        ends_on: None,
    };
    let s = create_sprint(pool, &s).await.unwrap();
    sqlx::query("UPDATE issues SET sprint_id = ? WHERE id = ?")
        .bind(s.id.0)
        .bind(i.0)
        .execute(pool)
        .await
        .unwrap();
    budget(pool, BudgetScope::Sprint(s.id), Month, 4_000, true).await;
    assert_eq!(
        cap().await.unwrap(),
        0,
        "the sprint's issue spent 5000: exhausted"
    );
    assert_eq!(run_token_cap(pool, &run, 100, NOW).await.unwrap(), 0);
}

/// Totals come in as reports; the ledger gets the growth, once per report, and the run its
/// totals. Repeats, stale reports and no growth add nothing.
#[tokio::test]
async fn usage_reports_land_in_the_ledger_once() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let run = &create_run(pool, &new_run(dev, Some(i))).await.unwrap();
    let record = |seq, t: Usage| async move { record_run_usage(pool, run, seq, &t, NOW).await };

    let first = record(1, tokens(100, 10, 1_000)).await.unwrap().unwrap();
    assert_eq!(first.usage, tokens(100, 10, 1_000));
    assert_eq!(first.idempotency_key, format!("run:{}:usage:1", run.id.0));
    let second = record(2, tokens(150, 30, 1_000)).await.unwrap().unwrap();
    assert_eq!(second.usage, tokens(50, 20, 0));
    assert_eq!(
        record(2, tokens(150, 30, 1_000)).await.unwrap(),
        None,
        "a repeat"
    );
    assert_eq!(
        record(3, tokens(120, 30, 1_000)).await.unwrap(),
        None,
        "stale"
    );
    assert_eq!(
        record(4, tokens(150, 30, 1_000)).await.unwrap(),
        None,
        "no growth"
    );
    assert_eq!(list_cost_events(pool, run.id).await.unwrap().len(), 2);
    let stored = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(stored.usage, tokens(150, 30, 1_000));
}
