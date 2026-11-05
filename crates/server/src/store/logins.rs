//! Subscription sign-ins (KAN-441 L1; plan `2026-11-05-claude-subscription-sign-in`): where a
//! one-shot sign-in on a runner has got to. **State only.** A row never holds the token or the
//! approval code (the code is passed to the runner and dropped; the token goes from the runner
//! straight into the broker), only the sign-in URL the user opens. Rows are transient: a backup and an
//! export drop them (`ops::backup::drop_logins`).
//!
//! ```text
//! starting -> open_url{url} -> waiting_code -> storing -> done{account_id}
//!     \____________\______________\_____________\______-> failed{reason} | cancelled
//! ```
//!
//! - `starting`: the runner was asked to begin; `open_url`: its URL is known, the user opens it
//!   and pastes the code; `waiting_code`: the code was handed to the runner, which finishes the
//!   sign-in; `storing`: the token arrived and is being stored.
//! - A login lives [`TTL_SECS`]; one past `expires_at` is `failed` (`expired`) the next time it is read.
//! - Every move is one compare-and-set write with its audit row and event in the same
//!   transaction (events `account.login.started|url|done|failed`; a cancel is a `failed` with the
//!   reason `cancelled`). Text from a provider or a runner passes the redactor.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::secrets::Error;
use crate::scheduler::iso_of_unix;

/// How long a login may take.
pub const TTL_SECS: i64 = 600;
/// The most logins open at once.
const MAX_OPEN: i64 = 4;
const CLOSED: &str = "('done', 'failed', 'cancelled')";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Login {
    pub id: String,
    pub provider: String,
    pub label: String,
    pub runner: String,
    pub device: String,
    pub state: String,
    pub url: Option<String>,
    pub account_id: Option<i64>,
    pub reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
}

/// What a move records beside the new state.
#[derive(Default)]
pub struct Change<'a> {
    pub url: Option<&'a str>,
    pub account_id: Option<i64>,
    pub reason: Option<&'a str>,
}

fn refused<T>(code: &'static str, message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.to_owned(),
    })
}

fn row(r: &SqliteRow) -> Result<Login, sqlx::Error> {
    Ok(Login {
        id: r.try_get("id")?,
        provider: r.try_get("provider")?,
        label: r.try_get("label")?,
        runner: r.try_get("runner")?,
        device: r.try_get("device")?,
        state: r.try_get("state")?,
        url: r.try_get("url")?,
        account_id: r.try_get("account_id")?,
        reason: r.try_get("reason")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
        expires_at: r.try_get("expires_at")?,
    })
}

const COLUMNS: &str = "id, provider, label, runner, device, state, url, account_id, reason, \
                       created_at, updated_at, expires_at";

async fn find(conn: &mut SqliteConnection, id: &str) -> Result<Option<Login>, sqlx::Error> {
    let sql = format!("SELECT {COLUMNS} FROM core_account_logins WHERE id = ?");
    let r = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(conn)
        .await?;
    r.as_ref().map(row).transpose()
}

async fn event(conn: &mut SqliteConnection, kind: &str, l: &Login) -> Result<(), sqlx::Error> {
    let mut p = json!({"login_id": l.id, "provider": l.provider, "label": l.label,
                       "runner": l.runner, "state": l.state});
    if let Some(a) = l.account_id {
        p["account_id"] = json!(a);
    }
    if let Some(r) = &l.reason {
        p["reason"] = json!(r);
    }
    super::events::append(conn, kind, &p).await.map(drop)
}

async fn audit(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    l: &Login,
) -> Result<(), Error> {
    let details = json!({"login_id": l.id, "provider": l.provider, "label": l.label,
                         "runner": l.runner, "by_device": l.device, "reason": l.reason});
    let e = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: None,
        details: details.to_string(),
    };
    super::audit::append(conn, &e).await?;
    Ok(())
}

/// Starts a login in `starting`, at `now` (unix seconds). One open login per label, a few at once.
pub async fn create(
    pool: &SqlitePool,
    (provider, label, runner): (&str, &str, &str),
    device: &str,
    actor: AuditActor,
    now: i64,
) -> Result<Login, Error> {
    let mut tx = super::begin_write(pool).await?;
    expire_in(&mut tx, actor, now).await?;
    let open: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM core_account_logins WHERE state NOT IN {CLOSED}"
    )))
    .fetch_one(&mut *tx)
    .await?;
    if open >= MAX_OPEN {
        return refused("limit_reached", "too many sign-ins are open");
    }
    let same: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM core_account_logins WHERE label = ? AND state NOT IN {CLOSED}"
    )))
    .bind(label)
    .fetch_one(&mut *tx)
    .await?;
    if same > 0 {
        return refused("conflict", "a sign-in of that label is already open");
    }
    let (at, until) = (iso_of_unix(now), iso_of_unix(now + TTL_SECS));
    let id = crate::auth::crypto::random_id("lg_");
    sqlx::query(
        "INSERT INTO core_account_logins (id, provider, label, runner, device, state, created_at, \
         updated_at, expires_at) VALUES (?, ?, ?, ?, ?, 'starting', ?, ?, ?)",
    )
    .bind(&id)
    .bind(provider)
    .bind(label)
    .bind(runner)
    .bind(device)
    .bind(&at)
    .bind(&at)
    .bind(&until)
    .execute(&mut *tx)
    .await?;
    let l = find(&mut tx, &id).await?.expect("just inserted");
    audit(&mut tx, actor, "account.login_started", &l).await?;
    event(&mut tx, "account.login.started", &l).await?;
    tx.commit().await?;
    Ok(l)
}

/// The login `id`, after any that are past `expires_at` have failed.
pub async fn get(
    pool: &SqlitePool,
    id: &str,
    actor: AuditActor,
    now: i64,
) -> Result<Option<Login>, Error> {
    let due: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM core_account_logins WHERE state NOT IN {CLOSED} AND expires_at <= ?"
    )))
    .bind(iso_of_unix(now))
    .fetch_one(pool)
    .await?;
    if due > 0 {
        let mut tx = super::begin_write(pool).await?;
        expire_in(&mut tx, actor, now).await?;
        tx.commit().await?;
    }
    let mut conn = pool.acquire().await?;
    Ok(find(&mut conn, id).await?)
}

/// Fails every open login past its `expires_at`.
async fn expire_in(conn: &mut SqliteConnection, actor: AuditActor, now: i64) -> Result<(), Error> {
    let ids: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT id FROM core_account_logins WHERE state NOT IN {CLOSED} AND expires_at <= ?"
    )))
    .bind(iso_of_unix(now))
    .fetch_all(&mut *conn)
    .await?;
    let why = Change {
        reason: Some("expired"),
        ..Change::default()
    };
    for id in ids {
        move_in(conn, &id, &[], "failed", &why, actor, now).await?;
    }
    Ok(())
}

/// Moves login `id` to `to` when it is in one of `from` (any open state when `from` is empty);
/// `None` when it is not (it moved, ended or never was): nothing is written then.
pub async fn step(
    pool: &SqlitePool,
    id: &str,
    from: &[&str],
    to: &str,
    change: &Change<'_>,
    actor: AuditActor,
    now: i64,
) -> Result<Option<Login>, Error> {
    let mut tx = super::begin_write(pool).await?;
    let moved = move_in(&mut tx, id, from, to, change, actor, now).await?;
    tx.commit().await?;
    Ok(moved)
}

async fn move_in(
    conn: &mut SqliteConnection,
    id: &str,
    from: &[&str],
    to: &str,
    change: &Change<'_>,
    actor: AuditActor,
    now: i64,
) -> Result<Option<Login>, Error> {
    let Some(old) = find(conn, id).await? else {
        return Ok(None);
    };
    let allowed = match from.is_empty() {
        true => !matches!(old.state.as_str(), "done" | "failed" | "cancelled"),
        false => from.contains(&old.state.as_str()),
    };
    if !allowed {
        return Ok(None);
    }
    // Provider and runner text may carry a credential shape: redacted, and cut.
    let reason = change
        .reason
        .or((to == "cancelled").then_some("cancelled"))
        .map(|r| {
            ainkrad_proto::redact::Redactor::new()
                .text(r)
                .chars()
                .take(200)
                .collect::<String>()
        });
    sqlx::query(
        "UPDATE core_account_logins SET state = ?, url = COALESCE(?, url), \
         account_id = COALESCE(?, account_id), reason = COALESCE(?, reason), updated_at = ? \
         WHERE id = ?",
    )
    .bind(to)
    .bind(change.url)
    .bind(change.account_id)
    .bind(reason)
    .bind(iso_of_unix(now))
    .bind(id)
    .execute(&mut *conn)
    .await?;
    let l = find(conn, id).await?.expect("just updated");
    match to {
        "open_url" => event(conn, "account.login.url", &l).await?,
        "done" => event(conn, "account.login.done", &l).await?,
        "failed" | "cancelled" => {
            event(conn, "account.login.failed", &l).await?;
            let action = if to == "failed" {
                "account.login_failed"
            } else {
                "account.login_cancelled"
            };
            audit(conn, actor, action, &l).await?;
        }
        _ => {}
    }
    Ok(Some(l))
}
