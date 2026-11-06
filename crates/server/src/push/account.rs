//! The pushes an account's state calls for (design `2026-11-06-core-account-scheduler` §13, S7).
//!
//! - `account.health` with reason `auth_suspected` (a subscription whose sign-in looks gone, which
//!   only an admin can answer) is pushed as `account_health`, to `admin` devices. Any other
//!   `account.health`, and every `account.limited` (a cooldown the Core waits out by itself), is
//!   in-app only: no notification.
//! - The notification is a fixed title and the account's id, nothing else: never the label, a key,
//!   a token or a word an upstream said. `policy::clean` still runs over it before it leaves.
//! - A device opts in or out per kind (`setPushKinds`) as for every kind; a burst of one account's
//!   merges by its collapse key.

use serde_json::json;

use super::Notification;
use crate::store::events::StoredEvent;

/// The push for an account event, if it calls for one.
pub(super) fn notification(e: &StoredEvent) -> Option<Notification> {
    let p = &e.payload.0;
    if e.kind != "account.health" || p["reason"].as_str() != Some("auth_suspected") {
        return None;
    }
    let account = p["account"].as_i64()?;
    Some(Notification {
        collapse: Some(format!("account_health:{account}")),
        ..Notification::new(
            "account_health",
            "admin",
            "An account needs your answer",
            "",
            json!({"account": account}),
        )
    })
}
