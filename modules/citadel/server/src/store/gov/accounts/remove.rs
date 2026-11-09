//! Deleting an account from the pool (API minor 17), audited as `account.deleted`. An account a
//! live run uses stays (the run needs it); one that ever ran or was billed stays too, because
//! the cost ledger is insert-only and names it: disable it instead.

use std::fmt;

use citadel_core::audit::AuditActor;
use citadel_core::exec::RunId;
use citadel_core::gov::AccountId;
use serde_json::json;
use sqlx::Error;
use sqlx::sqlite::SqlitePool;

use super::{append_account_event, get_account_in};

/// Why an account was not deleted.
#[derive(Debug)]
pub enum DeleteAccountError {
    /// These runs are live on it.
    LiveRuns(Vec<RunId>),
    /// It has run or been billed (this many runs and cost events); the ledger keeps its name.
    HasHistory {
        runs: i64,
        cost_events: i64,
    },
    Db(Error),
}

impl From<Error> for DeleteAccountError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for DeleteAccountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveRuns(runs) => {
                let ids: Vec<String> = runs.iter().map(|r| r.0.to_string()).collect();
                write!(
                    f,
                    "live runs use it ({}); stop them or let them end",
                    ids.join(", ")
                )
            }
            Self::HasHistory { runs, cost_events } => write!(
                f,
                "it has history ({runs} runs, {cost_events} cost events) that the cost ledger \
                 keeps; disable it instead"
            ),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DeleteAccountError {}

/// Deletes the account with its company assignments, limits and events; `false` when there is
/// no such account.
pub async fn delete_account(
    pool: &SqlitePool,
    id: AccountId,
    actor: AuditActor,
) -> Result<bool, DeleteAccountError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(a) = get_account_in(&mut tx, id).await? else {
        return Ok(false);
    };
    let live: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM runs WHERE account_id = ? AND state IN ('queued', 'claimed', 'running') \
         ORDER BY id",
    )
    .bind(id.0)
    .fetch_all(&mut *tx)
    .await?;
    if !live.is_empty() {
        return Err(DeleteAccountError::LiveRuns(
            live.into_iter().map(RunId).collect(),
        ));
    }
    let (runs, cost_events): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM runs WHERE account_id = ?1), \
                (SELECT count(*) FROM cost_events WHERE account_id = ?1)",
    )
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    if runs + cost_events > 0 {
        return Err(DeleteAccountError::HasHistory { runs, cost_events });
    }
    sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(id.0)
        .execute(&mut *tx)
        .await?;
    let details = json!({"harness": a.harness.as_str(), "label": a.label,
                         "companies": a.companies});
    append_account_event(&mut tx, actor, id, None, "account.deleted", details).await?;
    tx.commit().await?;
    Ok(true)
}
