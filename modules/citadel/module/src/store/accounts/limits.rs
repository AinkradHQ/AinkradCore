//! Rolling account usage limits and provider-drop health (S9, E15.2).

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::begin_write;
use serde_json::json;
use sqlx::sqlite::{SqliteConnection, SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use super::{Account, AccountSignal, append_account_event, get_account_in};
use crate::domain::gov::{AccountId, LimitUnit};
use crate::domain::work::RunId;
use crate::store::org::{affected, text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLimit {
    pub id: i64,
    pub account_id: AccountId,
    pub unit: LimitUnit,
    pub window_secs: i64,
    pub cap: i64,
    pub warn_percent: Option<u8>,
}

/// One configured limit with its live usage at `now`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitStanding {
    pub id: i64,
    pub unit: LimitUnit,
    pub window_secs: i64,
    pub cap: i64,
    pub used: i64,
    pub warn_percent: u8,
    pub exhausted: bool,
}

fn limit_row(row: SqliteRow) -> Result<AccountLimit, Error> {
    let warn: Option<i64> = row.try_get("warn_percent")?;
    Ok(AccountLimit {
        id: row.try_get("id")?,
        account_id: AccountId(row.try_get("account_id")?),
        unit: text(&row, "unit")?,
        window_secs: row.try_get("window_secs")?,
        cap: row.try_get("cap")?,
        warn_percent: warn.map(|w| w as u8),
    })
}

pub async fn set_account_limit(
    pool: &SqlitePool,
    limit: &AccountLimit,
    actor: AuditActor,
) -> Result<AccountLimit, Error> {
    if limit.window_secs <= 0 || limit.cap <= 0 {
        return Err(Error::InvalidArgument(
            "window_secs and cap must be positive".to_owned(),
        ));
    }
    if limit.warn_percent.is_some_and(|w| !(1..=100).contains(&w)) {
        return Err(Error::InvalidArgument("warn_percent is 1..=100".to_owned()));
    }
    let mut tx = begin_write(pool).await?;
    let warn = match limit.warn_percent {
        Some(w) => w,
        None => crate::settings::handle()
            .get_in(&mut tx, "account.warn_percent")
            .await
            .map_err(|e| Error::Configuration(e.to_string().into()))? as u8,
    };
    let row = sqlx::query(
        "INSERT INTO citadel_account_limits (account_id, unit, window_secs, cap, warn_percent, warned_at) \
         VALUES (?, ?, ?, ?, ?, NULL) \
         ON CONFLICT (account_id, unit, window_secs) DO UPDATE SET \
             cap = excluded.cap, warn_percent = excluded.warn_percent, warned_at = NULL \
         RETURNING id, account_id, unit, window_secs, cap, warn_percent",
    )
    .bind(limit.account_id.0)
    .bind(limit.unit.as_str())
    .bind(limit.window_secs)
    .bind(limit.cap)
    .bind(i64::from(warn))
    .fetch_one(&mut *tx)
    .await
    .and_then(limit_row)?;
    let details = json!({
        "unit": row.unit.as_str(),
        "window_secs": row.window_secs,
        "cap": row.cap,
        "warn_percent": row.warn_percent,
    });
    append_account_event(
        &mut tx,
        row.account_id,
        None,
        actor,
        "account.limit_set",
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(row)
}

pub async fn clear_account_limit(
    pool: &SqlitePool,
    account: AccountId,
    unit: LimitUnit,
    window_secs: i64,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = begin_write(pool).await?;
    let cleared = sqlx::query(
        "DELETE FROM citadel_account_limits WHERE account_id = ? AND unit = ? AND window_secs = ?",
    )
    .bind(account.0)
    .bind(unit.as_str())
    .bind(window_secs)
    .execute(&mut *tx)
    .await
    .map(affected)?;
    if cleared {
        let details = json!({"unit": unit.as_str(), "window_secs": window_secs});
        append_account_event(
            &mut tx,
            account,
            None,
            actor,
            "account.limit_cleared",
            details,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(cleared)
}

pub async fn list_account_limits(
    pool: &SqlitePool,
    account: AccountId,
) -> Result<Vec<AccountLimit>, Error> {
    let mut conn = pool.acquire().await?;
    limits_in(&mut conn, account).await
}

pub(crate) async fn limits_in(
    conn: &mut SqliteConnection,
    account: AccountId,
) -> Result<Vec<AccountLimit>, Error> {
    sqlx::query(
        "SELECT id, account_id, unit, window_secs, cap, warn_percent FROM citadel_account_limits \
         WHERE account_id = ? ORDER BY window_secs, unit",
    )
    .bind(account.0)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(limit_row)
    .collect()
}

pub(crate) async fn used_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    unit: LimitUnit,
    window_secs: i64,
    now: &str,
) -> Result<i64, Error> {
    let offset = format!("-{window_secs} seconds");
    match unit {
        LimitUnit::Tokens => {
            sqlx::query_scalar(
                "SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) \
                 FROM citadel_cost_events WHERE account_id = ? \
                 AND julianday(created_at) > julianday(?, ?) \
                 AND julianday(created_at) <= julianday(?)",
            )
            .bind(account.0)
            .bind(now)
            .bind(&offset)
            .bind(now)
            .fetch_one(&mut *conn)
            .await
        }
        LimitUnit::Messages => {
            sqlx::query_scalar(
                "SELECT count(*) FROM citadel_account_events WHERE account_id = ? \
                 AND kind = 'message' AND julianday(at) > julianday(?, ?) \
                 AND julianday(at) <= julianday(?)",
            )
            .bind(account.0)
            .bind(now)
            .bind(&offset)
            .bind(now)
            .fetch_one(&mut *conn)
            .await
        }
    }
}

pub(crate) async fn utilisation_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    now: &str,
) -> Result<(Vec<LimitStanding>, u32), Error> {
    let default_warn = crate::settings::handle()
        .get_in(conn, "account.warn_percent")
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))? as u8;
    let limits = limits_in(conn, account).await?;
    let mut standings = Vec::with_capacity(limits.len());
    let mut max_bps = 0u32;
    for l in limits {
        let used = used_in(conn, account, l.unit, l.window_secs, now).await?;
        let bps = ((used as u128 * 10_000) / l.cap as u128).min(u32::MAX as u128) as u32;
        max_bps = max_bps.max(bps);
        standings.push(LimitStanding {
            id: l.id,
            unit: l.unit,
            window_secs: l.window_secs,
            cap: l.cap,
            used,
            warn_percent: l.warn_percent.unwrap_or(default_warn),
            exhausted: used >= l.cap,
        });
    }
    Ok((standings, max_bps))
}

pub async fn record_message_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    run: Option<RunId>,
    now: &str,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO citadel_account_events (account_id, run_id, kind, at) VALUES (?, ?, 'message', ?)")
        .bind(account.0)
        .bind(run.map(|r| r.0))
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Checks `account`'s limits at `now`, emitting `account.warning` / `account.limited` and placing
/// the account in `cooling` when a cap is reached.
pub async fn check_limits_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    now: &str,
) -> Result<Vec<LimitStanding>, Error> {
    let (standings, _) = utilisation_in(conn, account, now).await?;
    for s in &standings {
        let threshold = (i128::from(s.cap) * i128::from(s.warn_percent) + 99) / 100;
        if i128::from(s.used) >= threshold {
            let warned = sqlx::query_scalar::<_, i64>(
                "UPDATE citadel_account_limits SET warned_at = ? \
                 WHERE account_id = ? AND unit = ? AND window_secs = ? \
                 AND (warned_at IS NULL OR julianday(warned_at) <= julianday(?, '-' || window_secs || ' seconds')) \
                 RETURNING 1",
            )
            .bind(now)
            .bind(account.0)
            .bind(s.unit.as_str())
            .bind(s.window_secs)
            .bind(now)
            .fetch_optional(&mut *conn)
            .await?
            .is_some();
            if warned {
                let details = json!({
                    "unit": s.unit.as_str(), "window_secs": s.window_secs,
                    "used": s.used, "cap": s.cap, "warn_percent": s.warn_percent,
                });
                append_account_event(
                    conn,
                    account,
                    None,
                    AuditActor::System,
                    "account.warning",
                    details,
                )
                .await?;
            }
        }
        if s.exhausted {
            let until = reset_at_in(conn, account, s.unit, s.window_secs, now).await?;
            let reason = format!(
                "{} limit ({}/{}) in {}s reached",
                s.unit.as_str(),
                s.used,
                s.cap,
                s.window_secs
            );
            let cooled = sqlx::query(
                "UPDATE citadel_accounts SET status = 'cooling', status_reason = ?, \
                 status_until = CASE WHEN status_until IS NULL OR julianday(?) > julianday(status_until) \
                     THEN ? ELSE status_until END WHERE id = ? AND status <> 'disabled'",
            )
            .bind(&reason)
            .bind(&until)
            .bind(&until)
            .bind(account.0)
            .execute(&mut *conn)
            .await
            .map(affected)?;
            if cooled {
                let details = json!({
                    "unit": s.unit.as_str(), "window_secs": s.window_secs,
                    "used": s.used, "cap": s.cap, "until": until,
                });
                append_account_event(
                    conn,
                    account,
                    None,
                    AuditActor::System,
                    "account.limited",
                    details,
                )
                .await?;
            }
        }
    }
    Ok(standings)
}

async fn reset_at_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    unit: LimitUnit,
    window_secs: i64,
    now: &str,
) -> Result<String, Error> {
    let win = format!("-{window_secs} seconds");
    let plus = format!("+{window_secs} seconds");
    let oldest: Option<String> = match unit {
        LimitUnit::Tokens => {
            sqlx::query_scalar(
                "SELECT min(created_at) FROM citadel_cost_events WHERE account_id = ? \
                 AND julianday(created_at) > julianday(?, ?)",
            )
            .bind(account.0)
            .bind(now)
            .bind(&win)
            .fetch_one(&mut *conn)
            .await?
        }
        LimitUnit::Messages => {
            sqlx::query_scalar(
                "SELECT min(at) FROM citadel_account_events WHERE account_id = ? \
                 AND kind = 'message' AND julianday(at) > julianday(?, ?)",
            )
            .bind(account.0)
            .bind(now)
            .bind(&win)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    let base = oldest.as_deref().unwrap_or(now);
    sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, ?)")
        .bind(base)
        .bind(&plus)
        .fetch_one(&mut *conn)
        .await
}

pub(crate) async fn refresh_in(conn: &mut SqliteConnection, now: &str) -> Result<(), Error> {
    sqlx::query(
        "UPDATE citadel_accounts SET status = 'active', status_reason = NULL, status_until = NULL \
         WHERE status = 'cooling' AND status_until IS NOT NULL \
         AND julianday(status_until) <= julianday(?)",
    )
    .bind(now)
    .execute(&mut *conn)
    .await?;
    let cooling: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM citadel_accounts WHERE status = 'cooling' AND status_until IS NULL",
    )
    .fetch_all(&mut *conn)
    .await?;
    for id in cooling {
        let (standings, _) = utilisation_in(conn, AccountId(id), now).await?;
        if standings.iter().all(|s| !s.exhausted) {
            sqlx::query(
                "UPDATE citadel_accounts SET status = 'active', status_reason = NULL WHERE id = ?",
            )
            .bind(id)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn drops_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    now: &str,
) -> Result<i64, Error> {
    let window = crate::settings::handle()
        .get_in(conn, "account.drop_window_secs")
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))?;
    drops_over_in(conn, account, window, now).await
}

pub(crate) async fn drops_over_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    window_secs: i64,
    now: &str,
) -> Result<i64, Error> {
    let win = format!("-{window_secs} seconds");
    sqlx::query_scalar(
        "SELECT count(*) FROM citadel_account_events WHERE account_id = ? AND kind = 'drop' \
         AND julianday(at) > julianday(?, ?) AND julianday(at) <= julianday(?)",
    )
    .bind(account.0)
    .bind(now)
    .bind(&win)
    .bind(now)
    .fetch_one(&mut *conn)
    .await
}

/// Records a provider drop on `account` at `now` and marks the account cooling (`account.unhealthy`)
/// if drops in `account.drop_window_secs` reach `account.drop_threshold`.
pub async fn record_drop_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    run: Option<RunId>,
    now: &str,
) -> Result<bool, Error> {
    sqlx::query(
        "INSERT INTO citadel_account_events (account_id, run_id, kind, at) VALUES (?, ?, 'drop', ?)",
    )
    .bind(account.0)
    .bind(run.map(|r| r.0))
    .bind(now)
    .execute(&mut *conn)
    .await?;
    let window = crate::settings::handle()
        .get_in(conn, "account.drop_window_secs")
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))?;
    let threshold = crate::settings::handle()
        .get_in(conn, "account.drop_threshold")
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))?;
    let unhealthy_secs = crate::settings::handle()
        .get_in(conn, "account.unhealthy_secs")
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))?;
    let drops = drops_over_in(conn, account, window, now).await?;
    if drops < threshold {
        return Ok(false);
    }
    let plus = format!("+{unhealthy_secs} seconds");
    let until: String = sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, ?)")
        .bind(now)
        .bind(&plus)
        .fetch_one(&mut *conn)
        .await?;
    let reason = format!("unhealthy: {drops} provider drops in {window}s");
    let cooled = sqlx::query(
        "UPDATE citadel_accounts SET status = 'cooling', status_reason = ?, \
         status_until = CASE WHEN status_until IS NULL OR julianday(?) > julianday(status_until) \
             THEN ? ELSE status_until END \
         WHERE id = ? AND status <> 'disabled'",
    )
    .bind(&reason)
    .bind(&until)
    .bind(&until)
    .bind(account.0)
    .execute(&mut *conn)
    .await
    .map(affected)?;
    if cooled {
        let details = json!({"drops": drops, "window_secs": window, "until": until});
        append_account_event(
            conn,
            account,
            None,
            AuditActor::System,
            "account.unhealthy",
            details,
        )
        .await?;
    }
    Ok(cooled)
}

/// Applies a quota signal reported by a runner on `account`.
pub async fn apply_signal(
    pool: &SqlitePool,
    account: AccountId,
    signal: &AccountSignal,
) -> Result<Option<Account>, Error> {
    let mut tx = begin_write(pool).await?;
    let json = serde_json::to_string(signal).map_err(|e| Error::Protocol(e.to_string()))?;
    let changed = sqlx::query(
        "UPDATE citadel_accounts SET signal = ?, \
         plan_tier = coalesce(?, plan_tier), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(&json)
    .bind(signal.plan_tier.map(|t| t.as_str()))
    .bind(account.0)
    .execute(&mut *tx)
    .await
    .map(affected)?;
    if !changed {
        return Ok(None);
    }
    let out = get_account_in(&mut tx, account).await?;
    tx.commit().await?;
    Ok(out)
}
