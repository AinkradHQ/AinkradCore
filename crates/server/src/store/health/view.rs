//! What the accounts API reads of an account's health and load (S7): the streaks the Core keeps,
//! the sessions that hold its cap now, and the last status class its gateway reported. Nothing
//! here writes, and nothing is a key, a token or an upstream's text.

use std::collections::HashMap;

use sqlx::Row;
use sqlx::sqlite::SqlitePool;

/// One account's health and load.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Status {
    /// Sessions that hold a slot of its cap now (`starting`, `running`, `interrupted`).
    pub live: i64,
    /// Upstream errors counted in the current ten-minute window.
    pub fail_streak: i64,
    /// A subscription's failed sessions in a row.
    pub auth_streak: i64,
    pub last_success_at: Option<String>,
    /// The newest status class a gateway report gave on a session of this account.
    pub upstream_class: Option<String>,
}

/// Every account's [`Status`], by account id.
pub async fn statuses(pool: &SqlitePool) -> Result<HashMap<i64, Status>, sqlx::Error> {
    // The holding states are `alloc::live`'s own.
    let rows = sqlx::query(
        "SELECT a.id, a.fail_streak, a.auth_streak, a.last_success_at, \
         (SELECT count(*) FROM core_agent_sessions s WHERE s.account_id = a.id \
            AND s.state IN ('starting', 'running', 'interrupted')) AS live, \
         (SELECT s.upstream_class FROM core_agent_sessions s WHERE s.account_id = a.id \
            AND s.upstream_class IS NOT NULL ORDER BY s.updated_at DESC, s.n DESC LIMIT 1) \
            AS upstream_class \
         FROM core_accounts a",
    )
    .fetch_all(pool)
    .await?;
    let mut out = HashMap::with_capacity(rows.len());
    for r in rows {
        out.insert(
            r.try_get("id")?,
            Status {
                live: r.try_get("live")?,
                fail_streak: r.try_get("fail_streak")?,
                auth_streak: r.try_get("auth_streak")?,
                last_success_at: r.try_get("last_success_at")?,
                upstream_class: r.try_get("upstream_class")?,
            },
        );
    }
    Ok(out)
}
