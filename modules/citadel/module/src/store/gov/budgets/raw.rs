//! Raw budget writers, test-only (`cfg(test)` or the `test-support` feature): unaudited, with no
//! spend counted; production code uses `set_budget`, `add_budget` and `remove_budget`. They write the
//! Core's budget table, bound to the company that owns the scope.

use super::*;

/// A second budget for the same scope and period is a constraint error.
pub async fn create_budget(pool: &SqlitePool, b: &NewBudget) -> Result<Budget, Error> {
    let (kind, id) = scope_parts(b.scope);
    let company = scope_company(pool, &b.scope).await?.map(|c| c.to_string());
    let made: i64 = sqlx::query_scalar(
        "INSERT INTO core_budgets (subject_kind, subject_id, company, period, token_cap, \
         usd_cap_micros, warn_at_percent, hard_stop, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
         strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) RETURNING id",
    )
    .bind(kind)
    .bind(id.to_string())
    .bind(company)
    .bind(b.period.as_str())
    .bind(b.token_cap)
    .bind(b.usd_cap_micros)
    .bind(b.warn_at_percent)
    .bind(b.hard_stop)
    .fetch_one(pool)
    .await?;
    Ok(get_budget(pool, BudgetId(made))
        .await?
        .expect("just inserted"))
}

/// Updates period, cap, warning threshold and hard stop; the scope is fixed.
pub async fn update_budget(pool: &SqlitePool, b: &Budget) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE core_budgets SET period = ?, token_cap = ?, usd_cap_micros = ?, \
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

pub async fn delete_budget(pool: &SqlitePool, id: BudgetId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM core_budgets WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(crate::store::org::affected)
}
