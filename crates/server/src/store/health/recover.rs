//! A state that is timed ends by itself: lazy recovery, and which states may start a run.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::super::audit;

/// Whether a state may start a fresh run: `active`, or a timed rate-limit cooldown for a run the
/// runner restarted (it already holds the account; the harness retries on its own).
pub fn startable(state: &str, resume: bool) -> bool {
    state == "active" || (resume && state == "cooling")
}

pub(super) async fn audited(
    conn: &mut SqliteConnection,
    account: i64,
    details: Value,
) -> Result<(), sqlx::Error> {
    let e = NewAuditEvent {
        actor: AuditActor::System,
        action: "account.state_set".to_owned(),
        entity: Some(AuditEntity {
            kind: "account".to_owned(),
            id: account,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &e).await.map(drop)
}

/// Puts an account whose timed state has ended back to `active` (audited), in the caller's write
/// transaction; whether it did. A state with no end (`auth_suspected`, `disabled`) stays.
pub async fn recover_in(
    conn: &mut SqliteConnection,
    account: i64,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let due: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT label, state, state_reason FROM core_accounts WHERE id = ?1 \
         AND state IN ('cooling', 'limited', 'unhealthy') AND state_until IS NOT NULL \
         AND julianday(state_until) <= julianday(?2)",
    )
    .bind(account)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((label, from, was)) = due else {
        return Ok(false);
    };
    sqlx::query(
        "UPDATE core_accounts SET state = 'active', state_reason = NULL, state_until = NULL, \
         updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(account)
    .execute(&mut *conn)
    .await?;
    let details = json!({"label": label, "from": from, "to": "active", "reason": "recovered",
        "was": was, "source": "lazy"});
    audited(conn, account, details).await?;
    Ok(true)
}

/// [`recover_in`] for a caller with no transaction: it looks first and takes the write lock only
/// when a window has ended.
pub async fn recover(pool: &SqlitePool, account: i64, now: &str) -> Result<(), sqlx::Error> {
    let due: bool = sqlx::query_scalar(
        "SELECT count(*) > 0 FROM core_accounts WHERE id = ?1 \
         AND state IN ('cooling', 'limited', 'unhealthy') AND state_until IS NOT NULL \
         AND julianday(state_until) <= julianday(?2)",
    )
    .bind(account)
    .bind(now)
    .fetch_one(pool)
    .await?;
    if due {
        let mut tx = crate::store::begin_write(pool).await?;
        recover_in(&mut tx, account, now).await?;
        tx.commit().await?;
    }
    Ok(())
}
