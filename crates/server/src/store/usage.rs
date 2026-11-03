//! Account usage and rolling limits, read from the cost ledger (KAN-449; Citadel's E15.2
//! `accounts/usage.rs` and `limits.rs`, ported for Core accounts): tokens, messages and dollars over
//! the last five hours and seven days, a split by company (the ledger's `company` subjects), the
//! configured limits with how much of each is used, and recent provider drops.
//!
//! These are READERS plus the plain writes behind them (a limit, a message, a drop). Moving an account
//! to `cooling` when a limit is reached, the drop threshold and failover are the scheduler's story
//! (KAN-436); the numbers it needs are here. Nothing here names a secret, a delivery or a runner: a
//! usage report is `read`, and what it returns is built for that (11b: the `read` scope saw routing
//! detail through the Citadel report).

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::secrets::Error;

pub const FIVE_HOURS: i64 = 5 * 3600;
pub const SEVEN_DAYS: i64 = 7 * 24 * 3600;
/// The longest window a limit may name (a leap year).
pub const MAX_WINDOW: i64 = 31_622_400;
/// A limit's warning threshold when it names none.
pub const DEFAULT_WARN: i64 = 80;
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
pub struct Limit {
    pub account_id: i64,
    /// `tokens` or `messages`.
    pub unit: String,
    pub window_secs: i64,
    pub cap: i64,
    pub warn_percent: Option<i64>,
}

/// A limit with how much of it is used at `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub unit: String,
    pub window_secs: i64,
    pub cap: i64,
    pub used: i64,
    pub warn_percent: i64,
    pub exhausted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUsage {
    pub account_id: i64,
    pub five_hours: Window,
    pub seven_days: Window,
    pub limits: Vec<Standing>,
    /// The highest used/cap of any limit, in basis points (10000 is at the cap).
    pub max_utilisation_bps: i64,
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

/// `account`'s limits with their use at `now`, and the highest use in basis points.
pub async fn standings_in(
    conn: &mut SqliteConnection,
    account: i64,
    now: &str,
) -> Result<(Vec<Standing>, i64), sqlx::Error> {
    let limits = limits_in(conn, account).await?;
    let mut out = Vec::with_capacity(limits.len());
    let mut max_bps = 0;
    for l in limits {
        let used = used_in(conn, account, &l.unit, l.window_secs, now).await?;
        let bps = i64::try_from(i128::from(used) * 10_000 / i128::from(l.cap)).unwrap_or(i64::MAX);
        max_bps = max_bps.max(bps);
        out.push(Standing {
            exhausted: used >= l.cap,
            warn_percent: l.warn_percent.unwrap_or(DEFAULT_WARN),
            unit: l.unit,
            window_secs: l.window_secs,
            cap: l.cap,
            used,
        });
    }
    Ok((out, max_bps))
}

pub async fn limits_in(
    conn: &mut SqliteConnection,
    account: i64,
) -> Result<Vec<Limit>, sqlx::Error> {
    sqlx::query(
        "SELECT account_id, unit, window_secs, cap, warn_percent FROM core_account_limits \
         WHERE account_id = ? ORDER BY window_secs, unit",
    )
    .bind(account)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|r| {
        Ok(Limit {
            account_id: r.try_get("account_id")?,
            unit: r.try_get("unit")?,
            window_secs: r.try_get("window_secs")?,
            cap: r.try_get("cap")?,
            warn_percent: r.try_get("warn_percent")?,
        })
    })
    .collect()
}

/// Every account's usage at `now` (or one account's), oldest account first.
pub async fn report(
    pool: &SqlitePool,
    only: Option<i64>,
    now: &str,
) -> Result<Vec<AccountUsage>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM core_accounts WHERE ?1 IS NULL OR id = ?1 ORDER BY id")
            .bind(only)
            .fetch_all(&mut *conn)
            .await?;
    let back = format!("-{SEVEN_DAYS} seconds");
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let (limits, max_utilisation_bps) = standings_in(&mut conn, id, now).await?;
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
            limits,
            max_utilisation_bps,
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

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    account: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "account".to_owned(),
            id: account,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

/// Sets `account`'s limit of `unit` over `window_secs` (a new one, or a change of the cap and the
/// warning), audited as `account.limit_set`.
#[allow(clippy::too_many_arguments)]
pub async fn set_limit(
    pool: &SqlitePool,
    account: i64,
    unit: &str,
    window_secs: i64,
    cap: i64,
    warn_percent: Option<i64>,
    by_device: &str,
    actor: AuditActor,
) -> Result<Limit, Error> {
    if !["tokens", "messages"].contains(&unit)
        || !(1..=MAX_WINDOW).contains(&window_secs)
        || cap < 1
        || warn_percent.is_some_and(|w| !(1..=100).contains(&w))
    {
        return refused(
            "a limit is tokens or messages, over 1 to 31622400 seconds, a cap of 1 or more, warning at 1-100%",
        );
    }
    let mut tx = super::begin_write(pool).await?;
    if sqlx::query_scalar::<_, i64>("SELECT count(*) FROM core_accounts WHERE id = ?")
        .bind(account)
        .fetch_one(&mut *tx)
        .await?
        == 0
    {
        return Err(Error::Refused {
            code: "not_found",
            message: "no such account".to_owned(),
        });
    }
    sqlx::query(
        "INSERT INTO core_account_limits (account_id, unit, window_secs, cap, warn_percent) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (account_id, unit, window_secs) DO UPDATE SET \
         cap = excluded.cap, warn_percent = excluded.warn_percent",
    )
    .bind(account)
    .bind(unit)
    .bind(window_secs)
    .bind(cap)
    .bind(warn_percent)
    .execute(&mut *tx)
    .await?;
    let details = json!({"unit": unit, "window_secs": window_secs, "cap": cap,
                         "warn_percent": warn_percent, "by_device": by_device});
    audit(&mut tx, actor, "account.limit_set", account, details).await?;
    tx.commit().await?;
    Ok(Limit {
        account_id: account,
        unit: unit.to_owned(),
        window_secs,
        cap,
        warn_percent,
    })
}

/// Clears one limit, audited as `account.limit_cleared`; `false` when there was none.
pub async fn clear_limit(
    pool: &SqlitePool,
    account: i64,
    unit: &str,
    window_secs: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = super::begin_write(pool).await?;
    if sqlx::query_scalar::<_, i64>("SELECT count(*) FROM core_accounts WHERE id = ?")
        .bind(account)
        .fetch_one(&mut *tx)
        .await?
        == 0
    {
        return Err(Error::Refused {
            code: "not_found",
            message: "no such account".to_owned(),
        });
    }
    let gone = sqlx::query(
        "DELETE FROM core_account_limits WHERE account_id = ? AND unit = ? AND window_secs = ?",
    )
    .bind(account)
    .bind(unit)
    .bind(window_secs)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if gone {
        let details = json!({"unit": unit, "window_secs": window_secs, "by_device": by_device});
        audit(&mut tx, actor, "account.limit_cleared", account, details).await?;
    }
    tx.commit().await?;
    Ok(gone)
}
