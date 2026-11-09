//! The events a change of an account's state raises (design `2026-11-06-core-account-scheduler`
//! §13, S7), written in the transaction of the change itself, beside its `account.state_set` audit
//! row. Ids, fixed codes and one time only: never a label, a key, a token or an upstream's text.
//!
//! - `account.limited {account, class, until, source}`: the account cooled (`rate_limited`,
//!   `plan_limit`) or was limited (`quota`) until `until`. `source` is `gateway` (trusted) or
//!   `harness`.
//! - `account.health {account, user, state, reason}`: the account went `unhealthy` (`upstream_errors`
//!   for ten minutes, `auth_suspected` until an admin answers).

use serde_json::json;
use sqlx::SqliteConnection;

use super::super::events;

/// What an account entered, as the events say it.
pub(super) struct Entered<'a> {
    pub account: i64,
    pub state: &'a str,
    pub reason: &'a str,
    pub class: &'a str,
    pub until: Option<&'a str>,
    pub source: &'a str,
}

/// Appends the event the new state calls for: a limit or an unhealthy account. Any other state
/// raises none.
pub(super) async fn entered(
    conn: &mut SqliteConnection,
    e: Entered<'_>,
) -> Result<(), sqlx::Error> {
    let (kind, payload) = match e.state {
        "cooling" | "limited" => (
            "account.limited",
            json!({"account": e.account, "class": e.class, "until": e.until, "source": e.source}),
        ),
        "unhealthy" => {
            // The account's user, so a push reaches only that user's admins.
            let user: i64 = sqlx::query_scalar("SELECT user_id FROM core_accounts WHERE id = ?")
                .bind(e.account)
                .fetch_optional(&mut *conn)
                .await?
                .unwrap_or(1);
            (
                "account.health",
                json!({"account": e.account, "user": user, "state": e.state, "reason": e.reason}),
            )
        }
        _ => return Ok(()),
    };
    events::append(conn, kind, &payload).await.map(drop)
}
