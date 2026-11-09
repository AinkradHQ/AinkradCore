//! Budgets (E7.2): token caps per company, department, project, agent or sprint, each over a
//! calendar period (UTC day, week from Monday, month, or all time), warning at
//! `warn_at_percent` and, with `hard_stop`, stopping new runs at the cap.
//!
//! Spend is kept per budget and period in `budget_spend`, updated by a trigger in the same
//! transaction as each cost event (migration `budget_spend`), so admission and the mid-run cap
//! read one counter per budget and never sum the ledger. `recompute_budget_spend` rebuilds the
//! counters from the ledger for repair. A budget is set (created or changed) through
//! `set_budget`, audited, which counts the period's spend so far. What a budget does at
//! dispatch and after each cost event is in `guard`.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::gov::{Budget, BudgetId, BudgetScope, NewBudget};
use citadel_core::org::{AgentId, CompanyId, DepartmentId};
use citadel_core::work::{IssueId, ProjectId, SprintId};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::id_column;
use crate::store::org::text;

/// SQL: the key of budget `b`'s period that contains the time `$t` (an SQL expression).
macro_rules! period_key {
    ($t:literal) => {
        concat!(
            "CASE b.period WHEN 'day' THEN date(",
            $t,
            ") \
             WHEN 'week' THEN date(",
            $t,
            ", '-6 days', 'weekday 1') \
             WHEN 'month' THEN strftime('%Y-%m', ",
            $t,
            ") ELSE 'total' END"
        )
    };
}

/// SQL: whether budget `b` applies to spend by agent `$agent` on issue `$issue` (SQL
/// expressions): its agent's, the agent's company's and departments' (through its teams), its
/// issue's project's and sprint's. The `budget_spend` trigger holds the same rule.
macro_rules! applies {
    ($agent:literal, $issue:literal) => {
        concat!(
            "(b.agent_id = ",
            $agent,
            " OR b.company_id = (SELECT company_id FROM agents WHERE id = ",
            $agent,
            ")",
            " OR b.department_id IN (SELECT t.department_id FROM team_memberships m \
             JOIN teams t ON t.id = m.team_id WHERE m.agent_id = ",
            $agent,
            ")",
            " OR b.project_id = (SELECT project_id FROM issues WHERE id = ",
            $issue,
            ")",
            " OR b.sprint_id = (SELECT sprint_id FROM issues WHERE id = ",
            $issue,
            ")",
            " OR b.issue_id = ",
            $issue,
            ")"
        )
    };
}

/// SQL: the company budget `b` belongs to.
macro_rules! budget_company {
    () => {
        "coalesce(b.company_id, (SELECT company_id FROM departments WHERE id = b.department_id), \
         (SELECT company_id FROM projects WHERE id = b.project_id), \
         (SELECT company_id FROM agents WHERE id = b.agent_id), \
         (SELECT p.company_id FROM sprints sp JOIN projects p ON p.id = sp.project_id \
             WHERE sp.id = b.sprint_id), \
         (SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id \
             WHERE i.id = b.issue_id))"
    };
}

/// SQL: the company budget `?` belongs to (a row of NULL when it has none); no row when there is
/// no such budget.
pub const BUDGET_COMPANY: &str = concat!(
    "SELECT ",
    budget_company!(),
    " FROM budgets b WHERE b.id = ?"
);

macro_rules! budget_columns {
    () => {
        "b.id, b.scope, b.company_id, b.department_id, b.project_id, b.agent_id, b.sprint_id, \
         b.issue_id, b.period, b.token_cap, b.usd_cap_micros, b.warn_at_percent, b.hard_stop"
    };
}

/// The same, unqualified, for `RETURNING`.
macro_rules! returned_columns {
    () => {
        "id, scope, company_id, department_id, project_id, agent_id, sprint_id, issue_id, \
         period, token_cap, usd_cap_micros, warn_at_percent, hard_stop"
    };
}

/// (scope text, its id) — the id goes in the column named after the scope.
fn scope_parts(s: BudgetScope) -> (&'static str, i64) {
    match s {
        BudgetScope::Company(id) => ("company", id.0),
        BudgetScope::Department(id) => ("department", id.0),
        BudgetScope::Project(id) => ("project", id.0),
        BudgetScope::Agent(id) => ("agent", id.0),
        BudgetScope::Sprint(id) => ("sprint", id.0),
        BudgetScope::Issue(id) => ("issue", id.0),
    }
}

fn budget(row: SqliteRow) -> Result<Budget, Error> {
    let scope: String = row.try_get("scope")?;
    let id = |column: &str| -> Result<i64, Error> {
        id_column(&row, column)?.ok_or_else(|| Error::ColumnNotFound(column.to_owned()))
    };
    let scope = match scope.as_str() {
        "company" => BudgetScope::Company(CompanyId(id("company_id")?)),
        "department" => BudgetScope::Department(DepartmentId(id("department_id")?)),
        "project" => BudgetScope::Project(ProjectId(id("project_id")?)),
        "agent" => BudgetScope::Agent(AgentId(id("agent_id")?)),
        "sprint" => BudgetScope::Sprint(SprintId(id("sprint_id")?)),
        "issue" => BudgetScope::Issue(IssueId(id("issue_id")?)),
        _ => return Err(Error::ColumnNotFound("scope".to_owned())),
    };
    Ok(Budget {
        id: BudgetId(row.try_get("id")?),
        scope,
        period: text(&row, "period")?,
        token_cap: row.try_get("token_cap")?,
        usd_cap_micros: row.try_get("usd_cap_micros")?,
        warn_at_percent: row.try_get("warn_at_percent")?,
        hard_stop: row.try_get("hard_stop")?,
    })
}

/// A second budget for the same scope and period is a constraint error. Test-only (and
/// `test-support`), like `update_budget` and `delete_budget`: unaudited; use `set_budget`.
#[cfg(any(test, feature = "test-support"))]
pub async fn create_budget(pool: &SqlitePool, b: &NewBudget) -> Result<Budget, Error> {
    let (scope, scope_id) = scope_parts(b.scope);
    // `scope = 'x'` selects which id column receives the value; the rest stay NULL.
    sqlx::query(concat!(
        "INSERT INTO budgets (scope, company_id, department_id, project_id, agent_id, \
         sprint_id, issue_id, period, token_cap, usd_cap_micros, warn_at_percent, hard_stop) \
         VALUES (?1, iif(?1 = 'company', ?2, NULL), iif(?1 = 'department', ?2, NULL), \
         iif(?1 = 'project', ?2, NULL), iif(?1 = 'agent', ?2, NULL), \
         iif(?1 = 'sprint', ?2, NULL), iif(?1 = 'issue', ?2, NULL), ?3, ?4, ?7, ?5, ?6) RETURNING ",
        returned_columns!()
    ))
    .bind(scope)
    .bind(scope_id)
    .bind(b.period.as_str())
    .bind(b.token_cap)
    .bind(b.warn_at_percent)
    .bind(b.hard_stop)
    .bind(b.usd_cap_micros)
    .fetch_one(pool)
    .await
    .and_then(budget)
}

pub async fn get_budget(pool: &SqlitePool, id: BudgetId) -> Result<Option<Budget>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        budget_columns!(),
        " FROM budgets b WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(budget)
    .transpose()
}

/// Every budget on `scope`, one per period.
pub async fn list_budgets(pool: &SqlitePool, scope: BudgetScope) -> Result<Vec<Budget>, Error> {
    let (scope, scope_id) = scope_parts(scope);
    sqlx::query(concat!(
        "SELECT ",
        budget_columns!(),
        " FROM budgets b WHERE scope = ? AND scope_id = ? ORDER BY id"
    ))
    .bind(scope)
    .bind(scope_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(budget)
    .collect()
}

/// Updates period, cap, warning threshold and hard stop; the scope is fixed.
#[cfg(any(test, feature = "test-support"))]
pub async fn update_budget(pool: &SqlitePool, b: &Budget) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE budgets SET period = ?, token_cap = ?, usd_cap_micros = ?, warn_at_percent = ?, \
         hard_stop = ? WHERE id = ?",
    )
    .bind(b.period.as_str())
    .bind(b.token_cap)
    .bind(b.usd_cap_micros)
    .bind(b.warn_at_percent)
    .bind(b.hard_stop)
    .bind(b.id.0)
    .execute(pool)
    .await
    .map(crate::store::org::affected)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn delete_budget(pool: &SqlitePool, id: BudgetId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM budgets WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(crate::store::org::affected)
}

/// A budget as it stands in the period containing some moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub budget: Budget,
    /// `2026-10-22`, `2026-10-19` (a week's Monday), `2026-10` or `total`.
    pub period_key: String,
    /// Tokens spent in the period.
    pub spent: i64,
    /// Tokens added for the period by approved overruns.
    pub raised: i64,
    /// Priced dollars (millionths) spent in the period, and added by approved overruns.
    pub usd_spent: i64,
    pub raised_usd: i64,
}

impl Standing {
    /// A dollar cap with no token cap (`token_cap` 0): only the dollars count.
    pub fn dollars_only(&self) -> bool {
        self.budget.token_cap == 0 && self.budget.usd_cap_micros.is_some()
    }

    /// Tokens left: the cap plus the raises, less the spend; 0 or less is exhausted. A
    /// dollars-only budget has no token limit (`i64::MAX`).
    pub fn left(&self) -> i64 {
        match self.dollars_only() {
            true => i64::MAX,
            false => self.budget.token_cap + self.raised - self.spent,
        }
    }

    /// Dollars (millionths) left, when the budget has a dollar cap; 0 or less is exhausted.
    pub fn usd_left(&self) -> Option<i64> {
        let cap = self.budget.usd_cap_micros?;
        Some(cap + self.raised_usd - self.usd_spent)
    }

    /// Nothing left in tokens or in dollars.
    pub fn exhausted(&self) -> bool {
        self.left() <= 0 || self.usd_left().is_some_and(|l| l <= 0)
    }
}

fn standing(row: SqliteRow) -> Result<Standing, Error> {
    Ok(Standing {
        period_key: row.try_get("period_key")?,
        spent: row.try_get("spent")?,
        raised: row.try_get("raised")?,
        usd_spent: row.try_get("usd_spent")?,
        raised_usd: row.try_get("raised_usd")?,
        budget: budget(row)?,
    })
}

/// Creates the budget for its scope and period, or changes the cap, warning threshold and
/// hard stop of the one there, and appends `budget.set` by `actor`; then counts its spend from
/// the ledger, so a budget set mid-period sees what was spent already. One `BEGIN IMMEDIATE`
/// transaction.
pub async fn set_budget(
    pool: &SqlitePool,
    b: &NewBudget,
    actor: AuditActor,
) -> Result<Budget, Error> {
    write_budget(pool, b, actor, true)
        .await
        .map(|b| b.expect("an upsert always writes"))
}

/// `set_budget` that only creates: `None` when its scope already has a budget for the period.
pub async fn add_budget(
    pool: &SqlitePool,
    b: &NewBudget,
    actor: AuditActor,
) -> Result<Option<Budget>, Error> {
    write_budget(pool, b, actor, false).await
}

/// Deletes the budget (its spend counters go with it) and appends `budget.deleted` by `actor`;
/// `false` when there is no such budget.
pub async fn remove_budget(
    pool: &SqlitePool,
    id: BudgetId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let company: Option<Option<i64>> = sqlx::query_scalar(BUDGET_COMPANY)
        .bind(id.0)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let b = sqlx::query(concat!(
        "DELETE FROM budgets WHERE id = ? RETURNING ",
        returned_columns!()
    ))
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await
    .and_then(budget)?;
    let (scope, scope_id) = scope_parts(b.scope);
    let details = json!({"scope": scope, "scope_id": scope_id, "period": b.period.as_str(),
                         "token_cap": b.token_cap});
    append_budget_event(
        &mut tx,
        id,
        company.map(CompanyId),
        actor,
        "budget.deleted",
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

async fn write_budget(
    pool: &SqlitePool,
    b: &NewBudget,
    actor: AuditActor,
    replace: bool,
) -> Result<Option<Budget>, Error> {
    if b.token_cap < 0
        || b.usd_cap_micros.is_some_and(|c| c < 0)
        || !(1..=100).contains(&b.warn_at_percent)
    {
        let why = "a budget needs a cap of 0 or more tokens (and dollars) and a warning at 1-100%";
        return Err(Error::InvalidArgument(why.to_owned()));
    }
    let (scope, scope_id) = scope_parts(b.scope);
    let mut tx = crate::store::begin_write(pool).await?;
    if !replace {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM budgets WHERE scope = ? AND scope_id = ? AND period = ?)",
        )
        .bind(scope)
        .bind(scope_id)
        .bind(b.period.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if taken {
            return Ok(None);
        }
    }
    let set = sqlx::query(concat!(
        "INSERT INTO budgets (scope, company_id, department_id, project_id, agent_id, \
         sprint_id, issue_id, period, token_cap, usd_cap_micros, warn_at_percent, hard_stop) \
         VALUES (?1, iif(?1 = 'company', ?2, NULL), iif(?1 = 'department', ?2, NULL), \
         iif(?1 = 'project', ?2, NULL), iif(?1 = 'agent', ?2, NULL), \
         iif(?1 = 'sprint', ?2, NULL), iif(?1 = 'issue', ?2, NULL), ?3, ?4, ?7, ?5, ?6) \
         ON CONFLICT (scope, scope_id, period) DO UPDATE SET token_cap = excluded.token_cap, \
         usd_cap_micros = excluded.usd_cap_micros, warn_at_percent = excluded.warn_at_percent, hard_stop = excluded.hard_stop RETURNING ",
        returned_columns!()
    ))
    .bind(scope)
    .bind(scope_id)
    .bind(b.period.as_str())
    .bind(b.token_cap)
    .bind(b.warn_at_percent)
    .bind(b.hard_stop)
    .bind(b.usd_cap_micros)
    .fetch_one(&mut *tx)
    .await
    .and_then(budget)?;
    let company: Option<i64> = sqlx::query_scalar(concat!(
        "SELECT ",
        budget_company!(),
        " FROM budgets b WHERE b.id = ?"
    ))
    .bind(set.id.0)
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"scope": scope, "scope_id": scope_id, "period": b.period.as_str(),
                         "token_cap": b.token_cap, "usd_cap_micros": b.usd_cap_micros,
                         "warn_at_percent": b.warn_at_percent, "hard_stop": b.hard_stop});
    append_budget_event(
        &mut tx,
        set.id,
        company.map(CompanyId),
        actor,
        if replace {
            "budget.set"
        } else {
            "budget.created"
        },
        details,
    )
    .await?;
    recompute_in(&mut tx, Some(set.id)).await?;
    tx.commit().await?;
    Ok(Some(set))
}

/// Every budget of the company, as it stands in the period containing `now`, by id.
pub async fn company_budgets(
    pool: &SqlitePool,
    company: CompanyId,
    now: &str,
) -> Result<Vec<Standing>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        budget_columns!(),
        ", ",
        period_key!("?2"),
        " AS period_key, coalesce(s.tokens, 0) AS spent, coalesce(s.raised, 0) AS raised, \
         coalesce(s.usd_micros, 0) AS usd_spent, \
         coalesce(s.raised_usd_micros, 0) AS raised_usd \
         FROM budgets b LEFT JOIN budget_spend s ON s.budget_id = b.id AND s.period_key = ",
        period_key!("?2"),
        " WHERE ",
        budget_company!(),
        " = ?1 ORDER BY b.id"
    ))
    .bind(company.0)
    .bind(now)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(standing)
    .collect()
}

/// Rebuilds every budget's spend counters from the ledger (as the org stands now), keeping the
/// raises and warnings, and appends `budget.recomputed` by `actor`. For repair: the trigger
/// keeps them in step. Returns how many (budget, period) counters hold spend.
pub async fn recompute_budget_spend(pool: &SqlitePool, actor: AuditActor) -> Result<u64, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let counted = recompute_in(&mut tx, None).await?;
    let event = NewAuditEvent {
        actor,
        action: "budget.recomputed".to_owned(),
        entity: None,
        company_id: None,
        run_id: None,
        details: json!({"counters": counted}).to_string(),
    };
    crate::store::audit::append(&mut *tx, &event).await?;
    tx.commit().await?;
    Ok(counted)
}

/// Recounts the spend of budget `only` (every budget with `None`) from the ledger.
pub(crate) async fn recompute_in(
    conn: &mut SqliteConnection,
    only: Option<BudgetId>,
) -> Result<u64, Error> {
    let only = only.map(|b| b.0);
    sqlx::query(
        "UPDATE budget_spend SET tokens = 0, usd_micros = 0 WHERE ?1 IS NULL OR budget_id = ?1",
    )
    .bind(only)
    .execute(&mut *conn)
    .await?;
    sqlx::query(concat!(
        "INSERT INTO budget_spend (budget_id, period_key, tokens, usd_micros) SELECT b.id, ",
        period_key!("c.created_at"),
        " AS key, sum(c.input_tokens + c.output_tokens + c.cache_tokens), \
         coalesce(sum(c.cost_usd_micros), 0) \
         FROM budgets b JOIN cost_events c ON ",
        applies!("c.agent_id", "c.issue_id"),
        " WHERE ?1 IS NULL OR b.id = ?1 GROUP BY b.id, key \
         ON CONFLICT (budget_id, period_key) DO UPDATE SET tokens = excluded.tokens, \
         usd_micros = excluded.usd_micros"
    ))
    .bind(only)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

/// Appends `action` by `actor` about budget `id`.
async fn append_budget_event(
    conn: &mut SqliteConnection,
    id: BudgetId,
    company: Option<CompanyId>,
    actor: AuditActor,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "budget".to_owned(),
            id: id.0,
        }),
        company_id: company,
        run_id: None,
        details: details.to_string(),
    };
    crate::store::audit::append(&mut *conn, &event)
        .await
        .map(drop)
}

mod guard;
pub use guard::*;

/// A new budget's warning threshold when none is given: the `budget.warn_percent` setting
/// (E15.17) of the company the budget's scope belongs to, else the server's.
pub async fn default_warn_percent(pool: &SqlitePool, scope: &BudgetScope) -> Result<u8, Error> {
    use citadel_core::settings::{Key, Scope};
    let company = scope_company(pool, scope).await?;
    let at = company.map_or(Scope::Server, |c| Scope::Company(CompanyId(c)));
    let warn = crate::store::settings::value(pool, Key::BudgetWarnPercent, at).await?;
    Ok(warn as u8)
}

/// The company owning what `scope` names; `None` when it names nothing.
pub async fn scope_company(pool: &SqlitePool, scope: &BudgetScope) -> Result<Option<i64>, Error> {
    let (sql, id) = match scope {
        BudgetScope::Company(c) => ("SELECT id FROM companies WHERE id = ?", c.0),
        BudgetScope::Department(d) => ("SELECT company_id FROM departments WHERE id = ?", d.0),
        BudgetScope::Project(p) => ("SELECT company_id FROM projects WHERE id = ?", p.0),
        BudgetScope::Agent(a) => ("SELECT company_id FROM agents WHERE id = ?", a.0),
        BudgetScope::Sprint(s) => (
            "SELECT p.company_id FROM sprints s JOIN projects p ON p.id = s.project_id \
             WHERE s.id = ?",
            s.0,
        ),
        BudgetScope::Issue(i) => (
            "SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id \
             WHERE i.id = ?",
            i.0,
        ),
    };
    sqlx::query_scalar(sql).bind(id).fetch_optional(pool).await
}
