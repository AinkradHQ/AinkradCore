//! What the API reads of a session's scheduling and of a caller's user (S7): one row per session
//! for the chain it walks, the account it holds and why it waits; nothing here writes.

use serde_json::Value;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;

use super::ChainEntry;

/// Why a chain session is not started yet: it waits for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// Unix seconds of its first wait; the allocator gives up `scheduler.wait_max_secs` after it.
    pub since: Option<i64>,
    /// When the earliest account may be back (a stored ISO time).
    pub until: String,
    pub why: String,
}

/// A session's chain, account and wait, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sched {
    /// The session's user.
    pub user: i64,
    /// The opaque agent id the create named.
    pub agent: Option<String>,
    pub chain_id: Option<i64>,
    /// The snapshot the run walks (an edit of the chain never moves it).
    pub chain: Option<Vec<ChainEntry>>,
    /// The entry the run sits on.
    pub chain_pos: Option<i64>,
    /// The account it holds, whatever its delivery.
    pub account: Option<i64>,
    pub waiting: Option<Waiting>,
    /// How many accounts a launch refused after the pick before this one was taken.
    pub repicked: i64,
    /// The last status class its own gateway reported.
    pub upstream_class: Option<String>,
}

/// `session`'s scheduling, `None` for no such session.
pub async fn sched_of(pool: &SqlitePool, session: &str) -> Result<Option<Sched>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT user_id, agent, chain_id, chain, chain_pos, account_id, waiting, tried_accounts, \
         upstream_class FROM core_agent_sessions WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let json = |col: &str| -> Result<Option<Value>, sqlx::Error> {
        Ok(r.try_get::<Option<String>, _>(col)?
            .and_then(|s| serde_json::from_str(&s).ok()))
    };
    let waiting = json("waiting")?.map(|w| Waiting {
        since: w["since"].as_i64(),
        until: w["until"].as_str().unwrap_or_default().to_owned(),
        why: w["why"].as_str().unwrap_or_default().to_owned(),
    });
    let tried = json("tried_accounts")?
        .and_then(|v| v.as_array().map(Vec::len))
        .unwrap_or(0);
    Ok(Some(Sched {
        user: r.try_get("user_id")?,
        agent: r.try_get("agent")?,
        chain_id: r.try_get("chain_id")?,
        chain: json("chain")?.and_then(|v| serde_json::from_value(v).ok()),
        chain_pos: r.try_get("chain_pos")?,
        account: r.try_get("account_id")?,
        waiting,
        repicked: i64::try_from(tried).unwrap_or(i64::MAX),
        upstream_class: r.try_get("upstream_class")?,
    }))
}

/// The user a device acts as (`core_devices.user_id`); the admin user for a device the Core does
/// not know. A new session and a new chain take this user, so a chain, a pool and a session of one
/// user never meet another's.
pub async fn user_of(pool: &SqlitePool, device: &str) -> Result<i64, sqlx::Error> {
    let user: Option<i64> = sqlx::query_scalar("SELECT user_id FROM core_devices WHERE id = ?")
        .bind(device)
        .fetch_optional(pool)
        .await?;
    Ok(user.unwrap_or(1))
}
