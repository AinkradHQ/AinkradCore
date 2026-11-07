//! The pushes an account's state calls for (design `2026-11-06-core-account-scheduler` §13, S7).
//!
//! - Pushed, to the `admin` devices of the user the event names (and to no one when it names none):
//!   `account.health` with reason `auth_suspected` (a subscription whose sign-in looks gone, which
//!   only an admin can answer) as `account_health`; `account.expired` (a key the provider refused,
//!   confirmed, so the account is disabled) as `account_expired`; `account.failover` (a run moved
//!   to another account, or ended with none left) as `account_failover`.
//! - In-app only, no notification: any other `account.health`, `account.limited` (a cooldown the
//!   Core waits out by itself) and `account.budget`.
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
    let user = p["user"].as_i64()?;
    let (kind, title, data, collapse) = match e.kind.as_str() {
        "account.health" if p["reason"].as_str() == Some("auth_suspected") => {
            let account = p["account"].as_i64()?;
            (
                "account_health",
                "An account needs your answer",
                json!({"account": account}),
                format!("account_health:{account}"),
            )
        }
        "account.expired" => {
            let account = p["account"].as_i64()?;
            (
                "account_expired",
                "An account was disabled",
                json!({"account": account}),
                format!("account_expired:{account}"),
            )
        }
        "account.failover" => {
            let run = p["run"].as_str()?;
            let title = match p["to_session"].is_null() {
                true => "A run ended: no account is left",
                false => "A run moved to another account",
            };
            (
                "account_failover",
                title,
                json!({"run": run, "hop": p["hop"].as_i64()?}),
                format!("account_failover:{run}"),
            )
        }
        _ => return None,
    };
    Some(Notification {
        collapse: Some(collapse),
        user: Some(user),
        ..Notification::new(kind, "admin", title, "", data)
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
