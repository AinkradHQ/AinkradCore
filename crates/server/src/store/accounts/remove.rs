//! Removing an account with Undo (E7 closeout). The API's delete only marks the account
//! ([`soft_delete`]): from that instant it is gone to every reader and to the allocator (it is
//! disabled, out of its pools, its leases dropped), yet its key and its row stay for [`UNDO_SECS`] so
//! [`restore`] can bring it back exactly as it was. [`wipe_due`] ends the window with the real wipe
//! ([`super::delete`]), and a runner-bound account's login on its runner is wiped from the
//! `core_account_wipes` rows the real wipe leaves.

use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;

use super::{Error, audit, find, find_in, refused};
use crate::scheduler::{iso_of_unix, unix_secs};

/// How long a removed account can still be brought back.
pub const UNDO_SECS: i64 = 10;

/// Marks account `id` removed at `now` and answers when the Undo window ends. One transaction: the
/// state it had and the pool seats it held are kept for the restore, then it is disabled
/// (`state_reason` `deleted`), out of every pool (so out of allocation and of the AI order) and its
/// unredeemed leases are dropped. Audited `account.deleted`, no value.
pub async fn soft_delete(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<String, Error> {
    let until = iso_of_unix(unix_secs(now).unwrap_or_default() + UNDO_SECS);
    let mut tx = super::super::begin_write(pool).await?;
    let a = find(&mut tx, id).await?;
    let seats: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT pool_id, position FROM core_pool_members WHERE account_id = ? ORDER BY pool_id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let pools: Vec<i64> = seats.iter().map(|s| s.0).collect();
    let kept: Vec<Value> = seats
        .iter()
        .map(|(p, pos)| json!({"pool": p, "position": pos}))
        .collect();
    let prev = json!({"state": a.state, "reason": a.state_reason, "until": a.state_until});
    sqlx::query("DELETE FROM core_pool_members WHERE account_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE core_accounts SET deleted_at = ?, deleted_prev = ?, deleted_seats = ?, \
         state = 'disabled', state_reason = 'deleted', state_until = NULL, updated_at = ? \
         WHERE id = ?",
    )
    .bind(now)
    .bind(prev.to_string())
    .bind(Value::Array(kept).to_string())
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    super::super::account_keys::revoke_leases_in(&mut tx, &a.secret_name).await?;
    let details = json!({"provider": a.provider, "label": a.label, "pools": pools,
                         "undo_until": until, "by_device": by_device});
    audit(&mut tx, actor, "account.deleted", id, details).await?;
    tx.commit().await?;
    Ok(until)
}

/// Brings a removed account back within its Undo window: its state and its pool seats as they were
/// (a seat whose pool is gone is not restored; one whose position was taken goes last). Audited
/// `account.restored`. `not_found` for an account that is not removed or whose window has ended.
pub async fn restore(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(), Error> {
    let mut tx = super::super::begin_write(pool).await?;
    let a = find_in(&mut tx, id, true).await?;
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT deleted_at, deleted_prev, deleted_seats FROM core_accounts \
         WHERE id = ? AND deleted_at IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((at, prev, seats)) = row else {
        return refused("not_found", "no such removed account");
    };
    let due = unix_secs(&at).unwrap_or_default() + UNDO_SECS;
    if unix_secs(now).unwrap_or(i64::MAX) >= due {
        return refused("not_found", "the undo window has ended");
    }
    let prev: Value = prev
        .and_then(|p| serde_json::from_str(&p).ok())
        .unwrap_or(Value::Null);
    let state = prev["state"].as_str().filter(|s| super::STATES.contains(s));
    sqlx::query(
        "UPDATE core_accounts SET state = ?, state_reason = ?, state_until = ?, deleted_at = NULL, \
         deleted_prev = NULL, deleted_seats = NULL, updated_at = ? WHERE id = ?",
    )
    .bind(state.unwrap_or("active"))
    .bind(prev["reason"].as_str())
    .bind(prev["until"].as_str())
    .bind(now)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let seats: Vec<Value> = seats
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let user: i64 = sqlx::query_scalar("SELECT user_id FROM core_accounts WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    for seat in &seats {
        let (Some(p), Some(pos)) = (seat["pool"].as_i64(), seat["position"].as_i64()) else {
            continue;
        };
        sqlx::query(
            "INSERT OR IGNORE INTO core_pool_members (user_id, pool_id, account_id, position) \
             SELECT ?1, p.id, ?2, CASE WHEN EXISTS (SELECT 1 FROM core_pool_members m \
                    WHERE m.pool_id = p.id AND m.position = ?4) \
                 THEN (SELECT max(position) + 1 FROM core_pool_members WHERE pool_id = p.id) \
                 ELSE ?4 END \
             FROM core_pools p WHERE p.id = ?3",
        )
        .bind(user)
        .bind(id)
        .bind(p)
        .bind(pos)
        .execute(&mut *tx)
        .await?;
    }
    audit(
        &mut tx,
        actor,
        "account.restored",
        id,
        json!({"provider": a.provider, "label": a.label, "by_device": by_device}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Wipes every removed account whose Undo window has ended at `now`, or every removed account with
/// `all` (the Core is stopping). The real wipe is [`super::delete`], so the key, the row, the seats and
/// the budgets go and `account.wiped` is audited. How many were wiped.
pub async fn wipe_due(pool: &SqlitePool, now: &str, all: bool) -> Result<usize, Error> {
    let cutoff = iso_of_unix(unix_secs(now).unwrap_or_default() - UNDO_SECS);
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM core_accounts WHERE deleted_at IS NOT NULL \
         AND (?1 OR julianday(deleted_at) <= julianday(?2)) ORDER BY id",
    )
    .bind(all)
    .bind(&cutoff)
    .fetch_all(pool)
    .await?;
    for id in &ids {
        super::delete(pool, *id, "core", AuditActor::System).await?;
    }
    Ok(ids.len())
}

/// A login still to be wiped on its runner: which runner, and which home key under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWipe {
    pub id: i64,
    pub runner: String,
    pub home: String,
}

/// The wipes the runners still owe, oldest first.
pub async fn pending_wipes(pool: &SqlitePool) -> Result<Vec<PendingWipe>, sqlx::Error> {
    let rows: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id, runner, home FROM core_account_wipes ORDER BY id LIMIT 50")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, runner, home)| PendingWipe { id, runner, home })
        .collect())
}

/// A login that finished on `runner` but never became an account: its home `home` is owed a wipe,
/// so nothing is left behind there. Idempotent.
pub async fn owe_wipe(
    pool: &SqlitePool,
    runner: &str,
    home: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO core_account_wipes (runner, home, created_at) VALUES (?, ?, ?)",
    )
    .bind(runner)
    .bind(home)
    .bind(now)
    .execute(pool)
    .await
    .map(drop)
}

/// The runner wiped an Antigravity home but its login also lives in the runner user's OS keyring,
/// which cannot be cleared per account: audited `account.wipe_note` and an event
/// `account.wipe.note` the app shows in plain words. No credential, only where.
pub async fn note_keyring_left(pool: &SqlitePool, runner: &str, home: &str) -> Result<(), Error> {
    let message = "The Antigravity sign-in's files were deleted, but its login may still be kept in that computer's keychain. Remove it there if you want it gone.";
    let details = json!({"runner": runner, "home": home, "note": "keyring_not_cleared"});
    let mut tx = super::super::begin_write(pool).await?;
    let e = ainkrad_core::audit::NewAuditEvent {
        actor: AuditActor::System,
        action: "account.wipe_note".to_owned(),
        entity: None,
        details: details.to_string(),
    };
    super::super::audit::append(&mut tx, &e).await?;
    let mut payload = details;
    payload["message"] = json!(message);
    super::super::events::append(&mut tx, "account.wipe.note", &payload).await?;
    tx.commit().await?;
    Ok(())
}

/// The runner wiped it (or there is nothing to wipe): forget the row.
pub async fn wipe_done(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM core_account_wipes WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}

/// The runner could not be reached or refused: keep the row, count the try.
pub async fn wipe_tried(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE core_account_wipes SET tries = tries + 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map(drop)
}
