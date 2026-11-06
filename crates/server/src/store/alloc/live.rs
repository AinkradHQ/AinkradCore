//! Which sessions hold a slot of an account's cap, and whether a session coming back (a wake, a
//! client's resume) may take its slot again.
//!
//! A session holds its account's slot from `starting` until it is `ended` or `lost`, `interrupted`
//! included and with no age limit: an interrupted session can still resume on its account until its
//! supervisor gives up and ends it as `lost`, and a restart of the Core restarts that timer. A
//! `lost` or `ended` session holds nothing, so a wake has to ask for the slot again.

use sqlx::SqliteConnection;

/// The states that hold a slot.
pub(super) const HOLDING: &str = "'starting', 'running', 'interrupted'";

/// The account a session row names by its account secret, as SQL over the table `t`: the account
/// of a session from before `account_id` existed.
pub fn derived_account(t: &str) -> String {
    format!(
        "(SELECT min(a.id) FROM core_accounts a WHERE a.secret_name GLOB 'acct.*' \
         AND a.secret_name IN (SELECT json_extract(j.value, '$.name') FROM json_each({t}.secrets) j))"
    )
}

/// How many sessions other than `except` hold a slot of `account`.
pub async fn live_in(
    conn: &mut SqliteConnection,
    account: i64,
    except: &str,
) -> Result<i64, sqlx::Error> {
    let sql = format!(
        "SELECT count(*) FROM core_agent_sessions WHERE account_id = ? AND id != ? \
         AND state IN ({HOLDING})"
    );
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(account)
        .bind(except)
        .fetch_one(conn)
        .await
}

/// Whether `session` may come back to life: it already holds its slot (`starting`, `running`,
/// `interrupted`), or draws from a chain and its account has a slot free, or it names its account
/// itself (the cap never bound such a session). A session with no account is not held back.
pub async fn may_return_in(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<bool, sqlx::Error> {
    let sql = format!(
        "SELECT s.state, s.chain IS NOT NULL, coalesce(s.account_id, {}) \
         FROM core_agent_sessions s WHERE s.id = ?",
        derived_account("s")
    );
    let row: Option<(String, bool, Option<i64>)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(session)
        .fetch_optional(&mut *conn)
        .await?;
    let Some((state, chain, Some(account))) = row else {
        return Ok(true);
    };
    if !chain || matches!(state.as_str(), "starting" | "running" | "interrupted") {
        return Ok(true);
    }
    let cap: Option<i64> = sqlx::query_scalar("SELECT cap FROM core_accounts WHERE id = ?")
        .bind(account)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(match cap {
        Some(cap) if cap > 0 => live_in(conn, account, session).await? < cap,
        _ => true,
    })
}

/// Records the account a session names on its row, when the row has none (a session from before
/// `account_id`): what the cap counts it by.
pub async fn stamp_account_in(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<(), sqlx::Error> {
    let sql = format!(
        "UPDATE core_agent_sessions SET account_id = {} WHERE id = ? AND account_id IS NULL",
        derived_account("core_agent_sessions")
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(session)
        .execute(conn)
        .await
        .map(drop)
}
