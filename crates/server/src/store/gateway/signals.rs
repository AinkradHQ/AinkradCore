//! The auth failures a gateway reported (KAN-435 G5), kept until a one-shot test decides them. A
//! signal is recorded, and its end without a verdict is recorded, with an audit row in the same
//! transaction; the verdict that matters (the account disabled) is `account.state_set`.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::super::audit;
use super::MAX_CONFIRM_TRIES;

async fn audited(
    conn: &mut SqliteConnection,
    action: &str,
    account: i64,
    details: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let e = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "account".to_owned(),
            id: account,
        }),
        details: details.to_string(),
    };
    audit::append(conn, &e).await.map(drop)
}

/// Keeps one upstream `auth_failed` (`key`: `gw:<session>:<epoch>:<gw_seq>`) as pending, audited
/// `account.auth_failed`; a resent report is the same signal and adds nothing.
pub(super) async fn record(
    conn: &mut SqliteConnection,
    account: i64,
    session: &str,
    key: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    let added = sqlx::query(
        "INSERT INTO core_account_auth_signals (account_id, session, gw_key, seen_at) \
         VALUES (?, ?, ?, ?) ON CONFLICT (gw_key) DO NOTHING",
    )
    .bind(account)
    .bind(session)
    .bind(key)
    .bind(now)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if added > 0 {
        let details = json!({"session": session, "report": key, "state": "pending"});
        audited(conn, "account.auth_failed", account, details).await?;
    }
    Ok(())
}

/// The pending auth signal of `account` and how often it was tried, oldest first.
pub async fn pending_auth(
    pool: &SqlitePool,
    account: i64,
) -> Result<Option<(i64, i64)>, sqlx::Error> {
    pending_auth_in(&mut *pool.acquire().await?, account).await
}

/// [`pending_auth`] in the caller's transaction (the allocator's).
pub async fn pending_auth_in(
    conn: &mut sqlx::SqliteConnection,
    account: i64,
) -> Result<Option<(i64, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, tries FROM core_account_auth_signals WHERE account_id = ? AND state = 'pending' \
         ORDER BY id LIMIT 1",
    )
    .bind(account)
    .fetch_optional(conn)
    .await
}

/// One more test of the pending signal came back without an answer; after
/// [`MAX_CONFIRM_TRIES`] it is `inconclusive` and nothing more is asked.
pub async fn tried(pool: &SqlitePool, signal: i64, now: &str) -> Result<(), sqlx::Error> {
    let mut tx = super::super::begin_write(pool).await?;
    let ended: Option<(i64, i64)> = sqlx::query_as(
        "UPDATE core_account_auth_signals SET tries = tries + 1, \
         state = iif(tries + 1 >= ?1, 'inconclusive', state), \
         decided_at = iif(tries + 1 >= ?1, ?2, decided_at) WHERE id = ?3 \
         RETURNING account_id, state = 'inconclusive'",
    )
    .bind(MAX_CONFIRM_TRIES)
    .bind(now)
    .bind(signal)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((account, true)) = ended.map(|(a, i)| (a, i == 1)) {
        let details = json!({"state": "inconclusive", "tries": MAX_CONFIRM_TRIES});
        audited(&mut tx, "account.auth_inconclusive", account, details).await?;
    }
    tx.commit().await
}

/// Settles every pending signal of `account` as `state` (`confirmed`, `cleared` or `inconclusive`);
/// an `inconclusive` end is audited `account.auth_inconclusive`, `why` saying why.
pub async fn decide(
    pool: &SqlitePool,
    account: i64,
    state: &str,
    why: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = super::super::begin_write(pool).await?;
    let n = sqlx::query(
        "UPDATE core_account_auth_signals SET state = ?, decided_at = ? \
         WHERE account_id = ? AND state = 'pending'",
    )
    .bind(state)
    .bind(now)
    .bind(account)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n > 0 && state == "confirmed" {
        // The provider refused the key and a one-shot test said so: the account is expired (the
        // caller disables it). `user` is who is told.
        let user: i64 = sqlx::query_scalar("SELECT user_id FROM core_accounts WHERE id = ?")
            .bind(account)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or(1);
        let payload = json!({"account": account, "user": user, "reason": "auth_confirmed"});
        super::super::events::append(&mut tx, "account.expired", &payload).await?;
    }
    if n > 0 && state == "inconclusive" {
        let details = json!({"state": "inconclusive", "why": why});
        audited(&mut tx, "account.auth_inconclusive", account, details).await?;
    }
    tx.commit().await
}
