//! What budgets do (E7.2, #15), all from the spend counters:
//!
//! - Admission (`admit_in`, called by dispatch, S7): a run is not started while any hard-stop
//!   budget that applies to it has nothing left; each such budget gets one `budget_overrun`
//!   approval per period, requested by the blocked agent. Approving it raises that period's
//!   budget by the tokens the decider gives (`raise_in`); rejecting it leaves the budget
//!   exhausted until the next period.
//! - Warning (`warn_in`, after each cost event): a budget whose spend reaches `warn_at_percent`
//!   of its cap appends `budget.warning`, once per period. The monolith also woke the product
//!   owner of the spending issue's team; that wake needs the wake queue (S7) and is not here.
//! - The mid-run cap (`exec::run_token_cap`, S7) is the least left of the same standings.

use super::*;
use crate::domain::gov::{Approval, ApprovalKind, NewApproval};
use crate::domain::work::UserId;
use crate::store::gov::{open_approval_in, user_actor};

/// Every budget that applies to a run of `agent` on `issue`, as it stands in the period
/// containing `now`; only hard-stop ones with `hard_only`.
pub async fn standings<'e>(
    ex: impl sqlx::SqliteExecutor<'e>,
    agent: AgentId,
    issue: Option<IssueId>,
    now: &str,
    hard_only: bool,
) -> Result<Vec<Standing>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        budget_columns!(),
        ", ",
        period_key!("?3"),
        " AS period_key, coalesce(s.tokens, 0) AS spent, coalesce(s.raised, 0) AS raised, \
         coalesce(s.usd_micros, 0) AS usd_spent, \
         coalesce(s.raised_usd_micros, 0) AS raised_usd \
         FROM citadel_budgets b LEFT JOIN citadel_budget_spend s ON s.budget_id = b.id \
         AND s.period_key = ",
        period_key!("?3"),
        " WHERE (?4 = 0 OR b.hard_stop = 1) AND ",
        applies!("?1", "?2"),
        " ORDER BY b.id"
    ))
    .bind(agent.0)
    .bind(issue.map(|i| i.0))
    .bind(now)
    .bind(hard_only)
    .fetch_all(ex)
    .await?
    .into_iter()
    .map(standing)
    .collect()
}

/// Whether a run of `agent` (of `company`) on `issue` may start at `now`: no hard-stop budget
/// that applies is exhausted. Each exhausted one gets a `budget_overrun` approval for its
/// period unless it has one already (whatever its status), with `budget.exhausted` appended.
#[allow(dead_code)] // S7: dispatch admits a run through the budget guard
pub(crate) async fn admit_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    company: CompanyId,
    issue: Option<IssueId>,
    now: &str,
) -> Result<bool, Error> {
    let exhausted: Vec<Standing> = standings(&mut *conn, agent, issue, now, true)
        .await?
        .into_iter()
        .filter(|s| s.exhausted())
        .collect();
    for s in &exhausted {
        let asked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_approvals WHERE kind = 'budget_overrun' \
             AND json_extract(payload, '$.budget') = ? AND json_extract(payload, '$.period') = ?)",
        )
        .bind(s.budget.id.0)
        .bind(&s.period_key)
        .fetch_one(&mut *conn)
        .await?;
        if asked {
            continue;
        }
        let (scope, scope_id) = scope_parts(s.budget.scope);
        // Dollars when they are what ran out; the decider's raise is in that unit.
        let usd = s.left() > 0;
        let summary = match usd {
            true => format!(
                "{scope} {scope_id} {} budget exhausted: {} of {} micro-dollars spent",
                s.budget.period.as_str(),
                s.usd_spent,
                s.budget.usd_cap_micros.unwrap_or(0) + s.raised_usd
            ),
            false => format!(
                "{scope} {scope_id} {} budget exhausted: {} of {} tokens spent",
                s.budget.period.as_str(),
                s.spent,
                s.budget.token_cap + s.raised
            ),
        };
        let payload = json!({"budget": s.budget.id.0, "period": s.period_key, "scope": scope,
                             "scope_id": scope_id, "token_cap": s.budget.token_cap,
                             "spent": s.spent, "raised": s.raised,
                             "unit": if usd { "usd_micros" } else { "tokens" },
                             "usd_cap_micros": s.budget.usd_cap_micros,
                             "usd_spent": s.usd_spent, "summary": summary});
        let new = NewApproval {
            company_id: company,
            kind: ApprovalKind::BudgetOverrun,
            issue_id: issue,
            sprint_id: None,
            agent_id: None,
            requested_by: agent,
            payload: payload.to_string(),
        };
        let a = open_approval_in(conn, &new, None, now).await?;
        let details = json!({"approval": a.id.0, "period": s.period_key, "spent": s.spent,
                             "blocked_agent": agent.0});
        append_budget_event(
            conn,
            s.budget.id,
            Some(company),
            AuditActor::System,
            "budget.exhausted",
            details,
        )
        .await?;
    }
    Ok(exhausted.is_empty())
}

/// After a cost event by `agent` on `issue` at `now`: every budget that applies and reached
/// its warning threshold this period without a warning yet gets one (`budget.warning`).
/// Returns the budgets warned.
// S7: the monolith also enqueued an `escalation` wake for the product owner (`product_owner` in
// the details) with key `budget:<id>:<period>:warning`; it needs the wake queue.
#[allow(dead_code)] // S7: the run engine calls the guard after a run
pub(crate) async fn warn_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    issue: Option<IssueId>,
    now: &str,
) -> Result<Vec<BudgetId>, Error> {
    let due: Vec<Standing> = standings(&mut *conn, agent, issue, now, false)
        .await?
        .into_iter()
        .filter(|s| {
            let warn = i64::from(s.budget.warn_at_percent);
            let tokens = !s.dollars_only() && s.spent * 100 >= s.budget.token_cap * warn;
            let usd = s
                .budget
                .usd_cap_micros
                .is_some_and(|c| s.usd_spent * 100 >= c * warn);
            tokens || usd
        })
        .collect();
    let po: Option<i64> = sqlx::query_scalar(
        "SELECT m.agent_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
         JOIN citadel_team_memberships m ON m.team_id = p.team_id \
         AND m.team_role = 'product_owner' WHERE i.id = ?",
    )
    .bind(issue.map(|i| i.0))
    .fetch_optional(&mut *conn)
    .await?;
    let mut warned = vec![];
    for s in due {
        let first = sqlx::query(
            "UPDATE citadel_budget_spend SET warned_at = ? \
             WHERE budget_id = ? AND period_key = ? AND warned_at IS NULL",
        )
        .bind(now)
        .bind(s.budget.id.0)
        .bind(&s.period_key)
        .execute(&mut *conn)
        .await?
        .rows_affected()
            > 0;
        if !first {
            continue;
        }
        let company: Option<i64> =
            sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
                .bind(agent.0)
                .fetch_optional(&mut *conn)
                .await?;
        let details = json!({"period": s.period_key, "spent": s.spent,
                             "token_cap": s.budget.token_cap, "product_owner": po});
        let company = company.map(CompanyId);
        let by = AuditActor::System;
        append_budget_event(conn, s.budget.id, company, by, "budget.warning", details).await?;
        warned.push(s.budget.id);
    }
    Ok(warned)
}

/// What an approved `budget_overrun` does, inside the deciding transaction: its budget's
/// period (from the payload) gets `raise` more tokens, and `budget.raised` is appended by `by`.
pub(crate) async fn raise_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    raise: i64,
    by: UserId,
) -> Result<(), Error> {
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap_or_default();
    let (Some(budget), Some(period)) = (payload["budget"].as_i64(), payload["period"].as_str())
    else {
        return Err(Error::InvalidArgument(format!(
            "approval {} names no budget period",
            a.id.0
        )));
    };
    // A budget that ran out of dollars is raised in dollars (millionths), else in tokens.
    let usd = payload["unit"].as_str() == Some("usd_micros");
    sqlx::query(
        "INSERT INTO citadel_budget_spend (budget_id, period_key, raised, raised_usd_micros) \
         SELECT id, ?1, iif(?4, 0, ?2), iif(?4, ?2, 0) FROM citadel_budgets WHERE id = ?3 \
         ON CONFLICT (budget_id, period_key) DO UPDATE SET raised = raised + excluded.raised, \
         raised_usd_micros = raised_usd_micros + excluded.raised_usd_micros",
    )
    .bind(period)
    .bind(raise)
    .bind(budget)
    .bind(usd)
    .execute(&mut *conn)
    .await?;
    let unit = if usd { "usd_micros" } else { "tokens" };
    let details = json!({"approval": a.id.0, "period": period, "raise": raise, "unit": unit});
    let by = user_actor(by);
    let id = BudgetId(budget);
    append_budget_event(conn, id, Some(a.company_id), by, "budget.raised", details).await
}

/// A new budget's warning threshold when none is given: the `budget.warn_percent` setting
/// (E15.17).
// ponytail: server-wide until the Core settings store has company/project scopes; the monolith
// read the company that owns `scope`.
pub async fn default_warn_percent(pool: &SqlitePool, _scope: &BudgetScope) -> Result<u8, Error> {
    let warn = crate::settings::value(pool, "budget.warn_percent").await?;
    Ok(warn as u8)
}

/// The company owning what `scope` names; `None` when it names nothing.
pub async fn scope_company(
    pool: impl sqlx::SqliteExecutor<'_>,
    scope: &BudgetScope,
) -> Result<Option<i64>, Error> {
    let (sql, id) = match scope {
        BudgetScope::Company(c) => ("SELECT id FROM citadel_companies WHERE id = ?", c.0),
        BudgetScope::Department(d) => (
            "SELECT company_id FROM citadel_departments WHERE id = ?",
            d.0,
        ),
        BudgetScope::Project(p) => ("SELECT company_id FROM citadel_projects WHERE id = ?", p.0),
        BudgetScope::Agent(a) => ("SELECT company_id FROM citadel_agents WHERE id = ?", a.0),
        BudgetScope::Sprint(s) => (
            "SELECT p.company_id FROM citadel_sprints s JOIN citadel_projects p \
             ON p.id = s.project_id WHERE s.id = ?",
            s.0,
        ),
        BudgetScope::Issue(i) => (
            "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p \
             ON p.id = i.project_id WHERE i.id = ?",
            i.0,
        ),
    };
    sqlx::query_scalar(sql).bind(id).fetch_optional(pool).await
}
