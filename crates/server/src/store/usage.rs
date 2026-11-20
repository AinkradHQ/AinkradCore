//! Account usage, read from the cost ledger (KAN-449; Citadel's E15.2
//! `accounts/usage.rs` and `limits.rs`, ported for Core accounts): tokens, messages and dollars over
//! the last five hours and seven days, a split by company (the ledger's `company` subjects), and
//! recent provider drops. Limits live in budgets (`store::budgets`), not here.
//!
//! These are READERS plus the plain writes behind them (a limit, a message, a drop). Moving an account
//! to `cooling` when a limit is reached, the drop threshold and failover are the scheduler's story
//! (KAN-436); the numbers it needs are here. Nothing here names a secret, a delivery or a runner: a
//! usage report is `read`, and what it returns is built for that (11b: the `read` scope saw routing
//! detail through the Citadel report).

use sqlx::SqliteConnection;
use sqlx::sqlite::SqlitePool;

use super::secrets::Error;

pub const FIVE_HOURS: i64 = 5 * 3600;
pub const SEVEN_DAYS: i64 = 7 * 24 * 3600;
/// Provider drops are counted over this window by [`AccountUsage::recent_drops`].
pub const DROP_WINDOW: i64 = 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Window {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub total_tokens: i64,
    pub messages: i64,
    pub cost_usd_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanySlice {
    pub company: String,
    pub five_hours: Window,
    pub seven_days: Window,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUsage {
    pub account_id: i64,
    pub five_hours: Window,
    pub seven_days: Window,
    pub recent_drops: i64,
    pub by_company: Vec<CompanySlice>,
}

fn refused<T>(message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code: "bad_request",
        message: message.to_owned(),
    })
}

/// Usage of `account` in the `window_secs` before `now`; of one company's agents with `company`.
async fn window_in(
    conn: &mut SqliteConnection,
    account: i64,
    company: Option<&str>,
    window_secs: i64,
    now: &str,
) -> Result<Window, sqlx::Error> {
    let back = format!("-{window_secs} seconds");
    let (input, output, cache, cost): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(e.input_tokens), 0), coalesce(sum(e.output_tokens), 0), \
         coalesce(sum(e.cache_tokens), 0), coalesce(sum(e.cost_usd_micros), 0) \
         FROM core_cost_events e WHERE e.account_id = ?1 \
         AND julianday(e.occurred_at) > julianday(?2, ?3) AND julianday(e.occurred_at) <= julianday(?2) \
         AND (?4 IS NULL OR e.id IN (SELECT event_id FROM core_cost_subjects \
                                     WHERE kind = 'company' AND subject_id = ?4))",
    )
    .bind(account)
    .bind(now)
    .bind(&back)
    .bind(company)
    .fetch_one(&mut *conn)
    .await?;
    let messages = match company {
        None => used_in(conn, account, "messages", window_secs, now).await?,
        Some(_) => 0,
    };
    Ok(Window {
        input_tokens: input,
        output_tokens: output,
        cache_tokens: cache,
        total_tokens: input + output + cache,
        messages,
        cost_usd_micros: cost,
    })
}

/// What `account` used of `unit` (`tokens` or `messages`) in the `window_secs` before `now`.
pub async fn used_in(
    conn: &mut SqliteConnection,
    account: i64,
    unit: &str,
    window_secs: i64,
    now: &str,
) -> Result<i64, sqlx::Error> {
    let back = format!("-{window_secs} seconds");
    let sql = match unit {
        "tokens" => {
            "SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) \
             FROM core_cost_events WHERE account_id = ?1 \
             AND julianday(occurred_at) > julianday(?2, ?3) AND julianday(occurred_at) <= julianday(?2)"
        }
        _ => {
            "SELECT count(*) FROM core_account_events WHERE account_id = ?1 AND kind = 'message' \
             AND julianday(at) > julianday(?2, ?3) AND julianday(at) <= julianday(?2)"
        }
    };
    sqlx::query_scalar(sql)
        .bind(account)
        .bind(now)
        .bind(&back)
        .fetch_one(&mut *conn)
        .await
}

/// Every account's usage at `now` (or one account's), oldest account first.
pub async fn report(
    pool: &SqlitePool,
    only: Option<i64>,
    now: &str,
) -> Result<Vec<AccountUsage>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM core_accounts WHERE deleted_at IS NULL AND (?1 IS NULL OR id = ?1) ORDER BY id")
            .bind(only)
            .fetch_all(&mut *conn)
            .await?;
    let back = format!("-{SEVEN_DAYS} seconds");
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let companies: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT s.subject_id FROM core_cost_events e JOIN core_cost_subjects s \
             ON s.event_id = e.id AND s.kind = 'company' WHERE e.account_id = ?1 \
             AND julianday(e.occurred_at) > julianday(?2, ?3) ORDER BY 1",
        )
        .bind(id)
        .bind(now)
        .bind(&back)
        .fetch_all(&mut *conn)
        .await?;
        let mut by_company = Vec::with_capacity(companies.len());
        for c in companies {
            by_company.push(CompanySlice {
                five_hours: window_in(&mut conn, id, Some(&c), FIVE_HOURS, now).await?,
                seven_days: window_in(&mut conn, id, Some(&c), SEVEN_DAYS, now).await?,
                company: c,
            });
        }
        out.push(AccountUsage {
            account_id: id,
            five_hours: window_in(&mut conn, id, None, FIVE_HOURS, now).await?,
            seven_days: window_in(&mut conn, id, None, SEVEN_DAYS, now).await?,
            recent_drops: drops_in(&mut conn, id, DROP_WINDOW, now).await?,
            by_company,
        });
    }
    Ok(out)
}

/// Provider drops of `account` in the `window_secs` before `now`.
pub async fn drops_in(
    conn: &mut SqliteConnection,
    account: i64,
    window_secs: i64,
    now: &str,
) -> Result<i64, sqlx::Error> {
    let back = format!("-{window_secs} seconds");
    sqlx::query_scalar(
        "SELECT count(*) FROM core_account_events WHERE account_id = ?1 AND kind = 'drop' \
         AND julianday(at) > julianday(?2, ?3) AND julianday(at) <= julianday(?2)",
    )
    .bind(account)
    .bind(now)
    .bind(&back)
    .fetch_one(&mut *conn)
    .await
}

/// Notes a message (a limit unit) or a provider drop on `account` at `now`.
pub async fn record_event_in(
    conn: &mut SqliteConnection,
    account: i64,
    session: Option<&str>,
    kind: &str,
    now: &str,
) -> Result<(), Error> {
    if !["message", "drop"].contains(&kind) || session.is_some_and(|s| s.is_empty() || s.len() > 64)
    {
        return refused(
            "an account event is a message or a drop, of a session of 1 to 64 characters",
        );
    }
    sqlx::query(
        "INSERT INTO core_account_events (account_id, session, kind, at) VALUES (?, ?, ?, ?)",
    )
    .bind(account)
    .bind(session)
    .bind(kind)
    .bind(now)
    .execute(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => Error::Refused {
            code: "not_found",
            message: "no such account".to_owned(),
        },
        e => e.into(),
    })?;
    Ok(())
}
