//! A state that is timed ends by itself: lazy recovery, and which states may start a run.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::{Value, json};
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::super::audit;

/// Whether a state may start a run. `active` may. A run the runner restarted already holds its
/// account, so it may also resume through this module's own short windows: a rate-limit cooldown
/// and an `upstream_errors` unhealthy window (ten minutes; the harness retries on its own, and a
/// running session must not die because the runner restarted). It never resumes through `limited`
/// (the provider has said no, the run would only fail), `auth_suspected`, `disabled` or a state an
/// admin set (`manual`).
pub fn startable(state: &str, reason: Option<&str>, resume: bool) -> bool {
    state == "active"
        || (resume
            && matches!(
                (state, reason),
                ("cooling", Some("rate_limited")) | ("unhealthy", Some("upstream_errors"))
            ))
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
/// transaction; whether it did. Only a state this module set (its own reason codes) ends: a state
/// with no end (`auth_suspected`, `disabled`) stays, and so does an admin's (`manual`), even with an
/// `until`: it stays until an admin changes it.
///
/// Recovery is lazy, so every reader that decides on an account's state must call it first:
/// `on_signal`, `gateway::grant` and the subscription lease do, and **the allocator's `pick_in`
/// (S4) must call `recover_in` before it filters candidates**.
pub async fn recover_in(
    conn: &mut SqliteConnection,
    account: i64,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let due: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT label, state, state_reason FROM core_accounts WHERE id = ?1 \
         AND state IN ('cooling', 'limited', 'unhealthy') AND state_until IS NOT NULL \
         AND state_reason IN ('rate_limited', 'upstream_errors', 'quota') \
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
         AND state_reason IN ('rate_limited', 'upstream_errors', 'quota') \
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
