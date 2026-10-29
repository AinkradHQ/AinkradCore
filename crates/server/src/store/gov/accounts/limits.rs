//! Usage limits per account (E15.2). A limit counts an account's use over a rolling window
//! (`window_secs` back from `now`): its cost events' tokens, or the prompts sent as it
//! (`account_events`). At `warn_percent` the admin is warned (`account.warning`: audit, event
//! stream, push) once per window; at the limit the account turns `limited` (`account.limited`)
//! and dispatch skips it. Nothing waits on a timer: `refresh_in`, run before each pick, brings
//! an account back (`account.restored`) once its window has rolled below every limit, or once
//! a reset the harness reported has passed.
//!
//! Harness signals: Claude reports its plan windows in-stream (`rate_limit_event`, relayed as a
//! `rate_limit` transcript chunk); `apply_signal` keeps the latest, warns at the threshold and
//! limits the account until the reset the harness gave when it says `rejected` or a window is
//! full. Codex reports `account/rateLimits/updated` (`usedPercent`), not yet relayed; OpenCode
//! and agy report none, so their accounts rely on counted limits.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::gov::{AccountId, AccountLimit, AccountStatus, LimitUnit, NewAccountLimit};
use ainkrad_core::settings::{Key, Scope};
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use super::append_account_event;
use crate::store::org::text;
use crate::store::settings::value_in;

fn limit(row: SqliteRow) -> Result<AccountLimit, Error> {
    Ok(AccountLimit {
        id: row.try_get("id")?,
        account_id: AccountId(row.try_get("account_id")?),
        window_secs: row.try_get("window_secs")?,
        unit: text(&row, "unit")?,
        max: row.try_get("max")?,
        warn_percent: row.try_get("warn_percent")?,
    })
}

/// Sets the account's limit for `window_secs` of `unit` (replacing one already set), and
/// appends `account.limit_set`. The account is checked against it at once.
pub async fn set_account_limit(
    pool: &SqlitePool,
    account: AccountId,
    new: NewAccountLimit,
    actor: AuditActor,
    now: &str,
) -> Result<AccountLimit, Error> {
    let NewAccountLimit {
        window_secs,
        unit,
        max,
        warn_percent,
    } = new;
    let mut tx = crate::store::begin_write(pool).await?;
    let warn_percent = match warn_percent {
        Some(w) => w,
        None => value_in(&mut tx, Key::AccountWarnPercent, Scope::Account(account)).await?,
    };
    if window_secs <= 0 || max <= 0 || !(1..=100).contains(&warn_percent) {
        let why = "a limit needs a window and a maximum above 0, and a warning at 1-100%";
        return Err(Error::InvalidArgument(why.to_owned()));
    }
    let set = sqlx::query(
        "INSERT INTO account_limits (account_id, window_secs, unit, max, warn_percent) \
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (account_id, window_secs, unit) DO UPDATE SET \
         max = excluded.max, warn_percent = excluded.warn_percent, warned_at = NULL \
         RETURNING id, account_id, window_secs, unit, max, warn_percent",
    )
    .bind(account.0)
    .bind(window_secs)
    .bind(unit.as_str())
    .bind(max)
    .bind(warn_percent)
    .fetch_one(&mut *tx)
    .await
    .and_then(limit)?;
    let details = json!({"window_secs": window_secs, "unit": unit.as_str(), "max": max,
                         "warn_percent": warn_percent});
    append_account_event(&mut tx, actor, account, None, "account.limit_set", details).await?;
    check_limits_in(&mut tx, account, now).await?;
    tx.commit().await?;
    Ok(set)
}

/// Removes the account's limit for `window_secs` of `unit` and appends
/// `account.limit_cleared`; `false` when there was none.
pub async fn clear_account_limit(
    pool: &SqlitePool,
    account: AccountId,
    window_secs: i64,
    unit: LimitUnit,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let gone = sqlx::query(
        "DELETE FROM account_limits WHERE account_id = ? AND window_secs = ? AND unit = ?",
    )
    .bind(account.0)
    .bind(window_secs)
    .bind(unit.as_str())
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if gone {
        let details = json!({"window_secs": window_secs, "unit": unit.as_str()});
        append_account_event(
            &mut tx,
            actor,
            account,
            None,
            "account.limit_cleared",
            details,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(gone)
}

pub(crate) async fn limits_in(
    conn: &mut SqliteConnection,
    account: AccountId,
) -> Result<Vec<AccountLimit>, Error> {
    sqlx::query(
        "SELECT id, account_id, window_secs, unit, max, warn_percent FROM account_limits \
         WHERE account_id = ? ORDER BY window_secs, unit",
    )
    .bind(account.0)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(limit)
    .collect()
}

/// What the account used of `unit` in the `window_secs` up to `now` (after its start).
pub(crate) async fn used_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    window_secs: i64,
    unit: LimitUnit,
    now: &str,
) -> Result<i64, Error> {
    let sql = match unit {
        LimitUnit::Tokens => {
            "SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) \
             FROM cost_events WHERE account_id = ?1 \
             AND julianday(created_at) > julianday(?2) - ?3 / 86400.0"
        }
        LimitUnit::Messages => {
            "SELECT count(*) FROM account_events WHERE account_id = ?1 AND kind = 'message' \
             AND julianday(at) > julianday(?2) - ?3 / 86400.0"
        }
    };
    sqlx::query_scalar(sql)
        .bind(account.0)
        .bind(now)
        .bind(window_secs)
        .fetch_one(&mut *conn)
        .await
}

/// The account's most used limit's share used, 0.0 with no limit: what dispatch spreads by.
pub(crate) async fn utilisation_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    now: &str,
) -> Result<f64, Error> {
    let mut most = 0.0_f64;
    for l in limits_in(conn, account).await? {
        let used = used_in(conn, account, l.window_secs, l.unit, now).await?;
        most = most.max(used as f64 / l.max as f64);
    }
    Ok(most)
}

/// A status change the server makes on its own.
pub(crate) struct Mark<'a> {
    pub to: AccountStatus,
    pub reason: Option<&'a str>,
    pub until: Option<&'a str>,
    /// The audit action, e.g. `account.limited`.
    pub action: &'a str,
    pub details: Value,
}

/// Moves the account from one of `from` as `mark` says, appending its action by the system;
/// `false` when it was in none of `from` (a disabled account stays so).
pub(crate) async fn mark_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    from: &[AccountStatus],
    mark: Mark<'_>,
) -> Result<bool, Error> {
    let Mark {
        to,
        reason,
        until,
        action,
        details,
    } = mark;
    let from: Vec<&str> = from.iter().map(|s| s.as_str()).collect();
    let moved = sqlx::query(
        "UPDATE accounts SET status = ?, status_reason = ?, status_until = ? \
         WHERE id = ? AND status IN (SELECT value FROM json_each(?))",
    )
    .bind(to.as_str())
    .bind(reason)
    .bind(until)
    .bind(account.0)
    .bind(serde_json::to_string(&from).expect("statuses serialise"))
    .execute(&mut *conn)
    .await?
    .rows_affected()
        > 0;
    if moved {
        append_account_event(conn, AuditActor::System, account, None, action, details).await?;
    }
    Ok(moved)
}

/// `5h`-style text for a window, for reasons people read.
pub(crate) fn window_text(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Checks the account's limits at `now`: warns once per window at each limit's threshold, and
/// limits an active account that reached one.
pub(crate) async fn check_limits_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    now: &str,
) -> Result<(), Error> {
    for l in limits_in(conn, account).await? {
        let used = used_in(conn, account, l.window_secs, l.unit, now).await?;
        let what = format!("{} {}", window_text(l.window_secs), l.unit.as_str());
        let details = json!({"window_secs": l.window_secs, "unit": l.unit.as_str(),
                             "used": used, "max": l.max, "source": "counted"});
        if used >= l.max {
            let reason = format!("{what} limit reached: {used} of {}", l.max);
            let mark = Mark {
                to: AccountStatus::Limited,
                reason: Some(&reason),
                until: None,
                action: "account.limited",
                details,
            };
            mark_in(conn, account, &[AccountStatus::Active], mark).await?;
            continue;
        }
        if used * 100 < l.max * l.warn_percent {
            continue;
        }
        let first = sqlx::query(
            "UPDATE account_limits SET warned_at = ?1 WHERE id = ?2 AND (warned_at IS NULL \
             OR julianday(warned_at) <= julianday(?1) - ?3 / 86400.0)",
        )
        .bind(now)
        .bind(l.id)
        .bind(l.window_secs)
        .execute(&mut *conn)
        .await?
        .rows_affected()
            > 0;
        if first {
            append_account_event(
                conn,
                AuditActor::System,
                account,
                None,
                "account.warning",
                {
                    let mut d = details;
                    d["percent"] = json!(used * 100 / l.max);
                    d
                },
            )
            .await?;
        }
    }
    Ok(())
}

/// Brings back every account whose limit has passed: a reset time at or before `now`, or a
/// counted limit whose windows have all rolled below their maxima.
pub(crate) async fn refresh_in(conn: &mut SqliteConnection, now: &str) -> Result<(), Error> {
    let waiting: Vec<(i64, Option<String>, String)> = sqlx::query_as(
        "SELECT id, status_until, status FROM accounts WHERE status IN ('limited', 'unhealthy')",
    )
    .fetch_all(&mut *conn)
    .await?;
    for (id, until, status) in waiting {
        let account = AccountId(id);
        let over = match until {
            Some(until) => {
                sqlx::query_scalar("SELECT julianday(?) <= julianday(?)")
                    .bind(&until)
                    .bind(now)
                    .fetch_one(&mut *conn)
                    .await?
            }
            None if status == "limited" => {
                let mut below = true;
                for l in limits_in(conn, account).await? {
                    below &= used_in(conn, account, l.window_secs, l.unit, now).await? < l.max;
                }
                below
            }
            None => false,
        };
        if over {
            let from = [AccountStatus::Limited, AccountStatus::Unhealthy];
            let mark = Mark {
                to: AccountStatus::Active,
                reason: None,
                until: None,
                action: "account.restored",
                details: json!({"was": status}),
            };
            mark_in(conn, account, &from, mark).await?;
        }
    }
    Ok(())
}

/// Records a prompt sent as `account` for `run` at `now`, then checks its limits.
pub(crate) async fn record_message_in(
    conn: &mut SqliteConnection,
    account: AccountId,
    run: i64,
    now: &str,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO account_events (account_id, run_id, kind, at) VALUES (?, ?, 'message', ?)",
    )
    .bind(account.0)
    .bind(run)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    check_limits_in(conn, account, now).await
}

/// Applies a harness's plan-limit report (`rate_limit` chunk) of `run` to the run's account:
/// keeps it, warns when a window crosses the threshold, and limits the account until the
/// reset the harness gave when it refused or a window is full. Nothing for a run with no
/// account or a chunk of another type.
pub async fn apply_signal(
    pool: &SqlitePool,
    run: ainkrad_core::exec::RunId,
    payload: &Value,
    now: &str,
) -> Result<(), Error> {
    if payload["type"] != "rate_limit" {
        return Ok(());
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let found: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT a.id, a.signal FROM runs r JOIN accounts a ON a.id = r.account_id WHERE r.id = ?",
    )
    .bind(run.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, before)) = found else {
        return Ok(());
    };
    let account = AccountId(id);
    let before: Value = before
        .and_then(|b| serde_json::from_str(&b).ok())
        .unwrap_or_default();
    let was = |name: &str| {
        before["windows"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|w| w["name"] == name)
            .and_then(|w| w["utilization"].as_f64())
            .unwrap_or(0.0)
    };
    let windows = payload["windows"].as_array().cloned().unwrap_or_default();
    let at = Scope::Account(account);
    let threshold = value_in(&mut tx, Key::AccountWarnPercent, at).await? as f64 / 100.0;
    let mut full_until: Option<i64> = None;
    for w in &windows {
        let (name, used) = (w["name"].as_str().unwrap_or("?"), w["utilization"].as_f64());
        let Some(used) = used else { continue };
        if used >= 1.0 {
            full_until = full_until.max(w["resets_at"].as_i64().or(Some(0)));
        }
        if used >= threshold && was(name) < threshold {
            let details = json!({"window": name, "utilization": used, "source": "harness",
                                 "percent": (used * 100.0).round() as i64});
            append_account_event(
                &mut tx,
                AuditActor::System,
                account,
                None,
                "account.warning",
                details,
            )
            .await?;
        }
    }
    let refused = payload["status"] == "rejected";
    if refused || full_until.is_some() {
        let latest = windows.iter().filter_map(|w| w["resets_at"].as_i64()).max();
        let reset = full_until.filter(|t| *t > 0).or(latest);
        let until: String = match reset {
            Some(epoch) => {
                sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?, 'unixepoch')")
                    .bind(epoch)
                    .fetch_one(&mut *tx)
                    .await?
            }
            None => {
                sqlx::query_scalar(
                    "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', julianday(?) + ? / 86400.0)",
                )
                .bind(now)
                .bind(value_in(&mut tx, Key::RefusedSecs, at).await?)
                .fetch_one(&mut *tx)
                .await?
            }
        };
        let reason = format!("the harness reports the plan limit reached, until {until}");
        let from = [AccountStatus::Active, AccountStatus::Limited];
        let mark = Mark {
            to: AccountStatus::Limited,
            reason: Some(&reason),
            until: Some(&until),
            action: "account.limited",
            details: json!({"until": until, "source": "harness", "status": payload["status"]}),
        };
        mark_in(&mut tx, account, &from, mark).await?;
    }
    sqlx::query("UPDATE accounts SET signal = ? WHERE id = ?")
        .bind(payload.to_string())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}
