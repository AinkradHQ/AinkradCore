//! Raw budget writers, test-only (`cfg(test)` or the `test-support` feature): unaudited, with no
//! spend counted; production code uses `set_budget`, `add_budget` and `remove_budget`.

use super::*;

/// A second budget for the same scope and period is a constraint error. Test-only (and
/// `test-support`), like `update_budget` and `delete_budget`: unaudited; use `set_budget`.
pub async fn create_budget(
    pool: impl sqlx::SqliteExecutor<'_>,
    b: &NewBudget,
) -> Result<Budget, Error> {
    let (scope, scope_id) = scope_parts(b.scope);
    // `scope = 'x'` selects which id column receives the value; the rest stay NULL.
    sqlx::query(concat!(
        "INSERT INTO citadel_budgets (scope, company_id, department_id, project_id, agent_id, \
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

/// Updates period, cap, warning threshold and hard stop; the scope is fixed.
pub async fn update_budget(pool: impl sqlx::SqliteExecutor<'_>, b: &Budget) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE citadel_budgets SET period = ?, token_cap = ?, usd_cap_micros = ?, \
         warn_at_percent = ?, hard_stop = ? WHERE id = ?",
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

pub async fn delete_budget(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: BudgetId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM citadel_budgets WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(crate::store::org::affected)
}
