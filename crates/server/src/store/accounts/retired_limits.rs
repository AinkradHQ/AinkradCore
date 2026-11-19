//! The audit half of migration 0049 (per-account limits became budgets). SQL cannot append to the
//! hash-chained audit log, so the migration leaves `core_limit_retired` (one row per converted limit)
//! and this runs once at the Core's start: one `account.limit_cleared` row per limit, then the table
//! is dropped in the same transaction. The table's existence is the marker: after the commit there
//! is nothing to do, and a crash before it leaves every row for the next start.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqlitePool;

use super::{Error, audit};

/// Writes the audit rows for the limits 0049 converted and drops the staging table. How many rows.
pub async fn audit_retired(pool: &SqlitePool) -> Result<usize, Error> {
    let mut tx = super::super::begin_write(pool).await?;
    let there: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'core_limit_retired'",
    )
    .fetch_one(&mut *tx)
    .await?;
    if there == 0 {
        return Ok(0);
    }
    let rows: Vec<(i64, String, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT account_id, unit, window_secs, cap, period FROM core_limit_retired \
         ORDER BY account_id, unit, window_secs",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (account, unit, window_secs, cap, period) in &rows {
        let became = period.as_deref().unwrap_or("dropped");
        let details = json!({"retired": true, "unit": unit, "window_secs": window_secs,
                             "cap": cap, "became": became});
        audit(
            &mut tx,
            AuditActor::System,
            "account.limit_cleared",
            *account,
            details,
        )
        .await?;
    }
    sqlx::query("DROP TABLE core_limit_retired")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(rows.len())
}
