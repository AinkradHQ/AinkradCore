//! The pushes an account's state calls for (design `2026-11-06-core-account-scheduler` §13, S7).
//!
//! - `account.health` with reason `auth_suspected` (a subscription whose sign-in looks gone, which
//!   only an admin can answer) is pushed as `account_health`, to the `admin` devices of the
//!   account's own user (the event names it). Any other `account.health`, and every
//!   `account.limited` (a cooldown the Core waits out by itself), is in-app only: no notification.
//! - The notification is a fixed title and the account's id, nothing else: never the label, a key,
//!   a token or a word an upstream said. `policy::clean` still runs over it before it leaves.
//! - A device opts in or out per kind (`setPushKinds`) as for every kind; a burst of one account's
//!   merges by its collapse key.

use std::collections::HashMap;

use serde_json::json;
use sqlx::SqlitePool;

use super::Notification;
use crate::store::events::StoredEvent;

/// The push for an account event, if it calls for one. An event that names no user is pushed to
/// no one.
pub(super) fn notification(e: &StoredEvent) -> Option<Notification> {
    let p = &e.payload.0;
    if e.kind != "account.health" || p["reason"].as_str() != Some("auth_suspected") {
        return None;
    }
    let (account, user) = (p["account"].as_i64()?, p["user"].as_i64()?);
    Some(Notification {
        collapse: Some(format!("account_health:{account}")),
        user: Some(user),
        ..Notification::new(
            "account_health",
            "admin",
            "An account needs your answer",
            "",
            json!({"account": account}),
        )
    })
}

/// Each device's user (by its row number), when any of `all` is for one user only.
pub(super) async fn device_users(
    pool: &SqlitePool,
    all: &[Notification],
) -> Result<HashMap<i64, i64>, sqlx::Error> {
    if all.iter().all(|n| n.user.is_none()) {
        return Ok(HashMap::new());
    }
    let rows: Vec<(i64, i64)> = sqlx::query_as("SELECT seq, user_id FROM core_devices")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().collect())
}
