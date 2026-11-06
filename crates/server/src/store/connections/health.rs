//! A connection's health: S3's states, cooldowns and lazy recovery (`store::health`, whose
//! constants, ranks and `startable` this follows), over `core_connections`.
//!
//! - **Two trust levels.** [`Signal::Upstream`] is the Core's own call (the broker, a feature):
//!   trusted, it may cool, count errors and mark unhealthy. [`Signal::Agent`] is what an agent or
//!   a harness says: forgeable, so it may only COOL (`rate_limited`, `quota`) an active
//!   connection, for at most `HARNESS_MAX_SECS`; it never disables, never counts, never extends.
//! - **Auth failure needs a test** (`verdict`). An upstream `auth_failed` marks the connection `unhealthy`
//!   with reason `auth_suspected` and `auth_pending`: it is out of use, but NOT disabled. Only
//!   [`record_test`] decides: a test the service rejects disables it (`auth_failed`), a test that
//!   passes clears it, and a test that says nothing ([`TestOutcome::Inconclusive`]) is retried;
//!   after [`MAX_CONFIRM_TRIES`] the suspicion ends (audited) and the connection is active again.
//! - **Lazy recovery.** A timed state past its `state_until` is `active` the next time anything
//!   looks ([`recover`], audited by the system); no timer.

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;
use sqlx::{Row, SqliteConnection};

use super::audit;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::health::{
    BACKOFF_MAX_SECS, BACKOFF_START_SECS, FAIL_LIMIT, FAIL_WINDOW_SECS, HARNESS_MAX_SECS,
    QUOTA_COOLDOWN_SECS, QUOTA_MAX_SECS, RATE_MAX_SECS, UNHEALTHY_SECS,
};
use crate::store::secrets::Error;
use ainkrad_core::audit::AuditActor;

/// A suspected auth failure is tested this many times before it is dropped as inconclusive.
pub const MAX_CONFIRM_TRIES: i64 = 3;

/// What happened to a connection.
pub enum Signal<'a> {
    /// An upstream status of the Core's own call (trusted).
    Upstream {
        status: UpstreamStatus,
        retry_after: Option<u64>,
        reset_at: Option<&'a str>,
    },
    /// An agent or harness said this class (forgeable): only `rate_limited` and `quota` count.
    Agent { class: &'a str },
    /// A call went well: streaks and backoff start over.
    Success,
}

fn rank(reason: &str) -> Option<i32> {
    match reason {
        "rate_limited" => Some(1),
        "upstream_errors" => Some(2),
        "quota" => Some(3),
        "auth_suspected" => Some(4),
        _ => None,
    }
}

fn state_of(reason: &str) -> &'static str {
    match reason {
        "rate_limited" => "cooling",
        "quota" => "limited",
        _ => "unhealthy",
    }
}

fn next_backoff(prev: i64) -> i64 {
    match prev {
        p if p <= 0 => BACKOFF_START_SECS,
        p => (p * 2).min(BACKOFF_MAX_SECS),
    }
}

pub(super) struct Health {
    pub(super) name: String,
    pub(super) state: String,
    reason: Option<String>,
    until: Option<i64>,
    fail_streak: i64,
    backoff: i64,
    fail_since: Option<String>,
    pub(super) auth_pending: bool,
    pub(super) auth_tries: i64,
}

pub(super) async fn load(
    conn: &mut SqliteConnection,
    id: i64,
) -> Result<Option<Health>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT name, status, state_reason, state_until, fail_streak, backoff_secs, fail_since, \
         auth_pending, auth_tries FROM core_connections WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(Health {
        name: r.try_get("name")?,
        state: r.try_get("status")?,
        reason: r.try_get("state_reason")?,
        until: r
            .try_get::<Option<String>, _>("state_until")?
            .as_deref()
            .and_then(unix_secs),
        fail_streak: r.try_get("fail_streak")?,
        backoff: r.try_get("backoff_secs")?,
        fail_since: r.try_get("fail_since")?,
        auth_pending: r.try_get::<i64, _>("auth_pending")? == 1,
        auth_tries: r.try_get("auth_tries")?,
    }))
}

pub(super) async fn sys_audit(
    conn: &mut SqliteConnection,
    action: &str,
    id: i64,
    details: Value,
) -> Result<(), sqlx::Error> {
    match audit(conn, AuditActor::System, action, id, details).await {
        Ok(()) => Ok(()),
        Err(Error::Db(e)) => Err(e),
        Err(Error::Refused { message, .. }) => Err(sqlx::Error::Protocol(message)),
    }
}

/// Puts a connection whose timed state has ended back to `active` (audited), in the caller's
/// write transaction; whether it did. Only a state this module set ends; `auth_suspected` and
/// `disabled` stay until a test or an admin decides.
pub async fn recover_in(
    conn: &mut SqliteConnection,
    id: i64,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let due: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT name, status, state_reason FROM core_connections WHERE id = ?1 \
         AND status IN ('cooling', 'limited', 'unhealthy') AND state_until IS NOT NULL \
         AND state_reason IN ('rate_limited', 'upstream_errors', 'quota') \
         AND julianday(state_until) <= julianday(?2)",
    )
    .bind(id)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((name, from, was)) = due else {
        return Ok(false);
    };
    sqlx::query(
        "UPDATE core_connections SET status = 'active', state_reason = NULL, state_until = NULL, \
         updated_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await?;
    let details = json!({"name": name, "from": from, "to": "active", "reason": "recovered",
        "was": was, "source": "lazy"});
    sys_audit(conn, "connection.state_set", id, details).await?;
    Ok(true)
}

/// [`recover_in`] for a caller with no transaction: it looks first and takes the write lock only
/// when a window has ended.
pub async fn recover(pool: &SqlitePool, id: i64, now: &str) -> Result<(), sqlx::Error> {
    let due: bool = sqlx::query_scalar(
        "SELECT count(*) > 0 FROM core_connections WHERE id = ?1 \
         AND status IN ('cooling', 'limited', 'unhealthy') AND state_until IS NOT NULL \
         AND state_reason IN ('rate_limited', 'upstream_errors', 'quota') \
         AND julianday(state_until) <= julianday(?2)",
    )
    .bind(id)
    .bind(now)
    .fetch_one(pool)
    .await?;
    if due {
        let mut tx = crate::store::begin_write(pool).await?;
        recover_in(&mut tx, id, now).await?;
        tx.commit().await?;
    }
    Ok(())
}

struct Entry<'a> {
    reason: &'static str,
    until: Option<i64>,
    backoff: Option<i64>,
    clear_fails: bool,
    class: &'a str,
}

struct Ctx<'a> {
    trusted: bool,
    now: &'a str,
    now_u: i64,
}

/// Writes the state of `e` if `h` allows it (a higher rank, or only over `active` for an
/// untrusted signal); whether it did.
async fn enter(
    conn: &mut SqliteConnection,
    id: i64,
    h: &Health,
    e: Entry<'_>,
    cx: &Ctx<'_>,
) -> Result<bool, sqlx::Error> {
    let new = rank(e.reason).unwrap_or(i32::MAX);
    let mut until = e.until.map(|u| match cx.trusted {
        true => u,
        false => u.min(cx.now_u + HARNESS_MAX_SECS),
    });
    let old = h.reason.as_deref().and_then(rank);
    let allowed = match (h.state.as_str(), old) {
        ("active", _) => true,
        // Nothing an agent says changes a state that is already set.
        _ if !cx.trusted => false,
        ("cooling" | "limited" | "unhealthy", Some(old)) => {
            new > old || (cx.trusted && new == old && until > h.until)
        }
        _ => false,
    };
    if !allowed {
        return Ok(false);
    }
    if let (Some(n), Some(o)) = (until, h.until) {
        until = Some(n.max(o));
    }
    let (state, until_iso) = (state_of(e.reason), until.map(iso_of_unix));
    sqlx::query(
        "UPDATE core_connections SET status = ?, state_reason = ?, state_until = ?, \
         backoff_secs = coalesce(?, backoff_secs), fail_streak = iif(?, 0, fail_streak), \
         fail_since = iif(?, NULL, fail_since), updated_at = ? WHERE id = ?",
    )
    .bind(state)
    .bind(e.reason)
    .bind(&until_iso)
    .bind(e.backoff)
    .bind(e.clear_fails)
    .bind(e.clear_fails)
    .bind(cx.now)
    .bind(id)
    .execute(&mut *conn)
    .await?;
    if h.state != state || h.reason.as_deref() != Some(e.reason) {
        let source = if cx.trusted { "upstream" } else { "agent" };
        let details = json!({"name": h.name, "from": h.state, "to": state, "reason": e.reason,
            "until": until_iso, "source": source, "class": e.class});
        sys_audit(conn, "connection.state_set", id, details).await?;
    }
    Ok(true)
}

fn until_reset(reset: Option<&str>, now_u: i64, max: i64) -> Option<i64> {
    let at = reset.and_then(unix_secs).filter(|at| *at > now_u)?;
    Some(at.min(now_u + max))
}

async fn rate_limited(
    conn: &mut SqliteConnection,
    id: i64,
    h: &Health,
    reset: Option<i64>,
    class: &str,
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    let open = h.state == "cooling" && h.reason.as_deref() == Some("rate_limited");
    // An agent's word cools for the first step only and never moves the backoff.
    if !cx.trusted {
        let e = Entry {
            reason: "rate_limited",
            until: Some(cx.now_u + BACKOFF_START_SECS),
            backoff: None,
            clear_fails: false,
            class,
        };
        return enter(conn, id, h, e, cx).await.map(drop);
    }
    let (until, backoff) = match open {
        true => (h.until.unwrap_or(cx.now_u).max(reset.unwrap_or(0)), None),
        false => {
            let b = next_backoff(h.backoff);
            (reset.unwrap_or(0).max(cx.now_u + b), Some(b))
        }
    };
    let e = Entry {
        reason: "rate_limited",
        until: Some(until),
        backoff,
        clear_fails: false,
        class,
    };
    enter(conn, id, h, e, cx).await.map(drop)
}

/// What `signal` does to workspace `ws`'s connection `id` (`RowNotFound` for another's), in the caller's write transaction. The single entry
/// for connection health.
pub async fn on_signal(
    conn: &mut SqliteConnection,
    ws: i64,
    id: i64,
    signal: Signal<'_>,
    now: &str,
) -> Result<(), sqlx::Error> {
    let Some(now_u) = unix_secs(now) else {
        return Ok(());
    };
    let own: i64 =
        sqlx::query_scalar("SELECT count(*) FROM core_connections WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(ws)
            .fetch_one(&mut *conn)
            .await?;
    if own == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    recover_in(conn, id, now).await?;
    let Some(h) = load(conn, id).await? else {
        return Ok(());
    };
    let trusted = !matches!(signal, Signal::Agent { .. });
    let cx = Ctx {
        trusted,
        now,
        now_u,
    };
    match signal {
        Signal::Success => success(conn, id, &cx).await,
        Signal::Upstream {
            status,
            retry_after,
            reset_at,
        } => upstream(conn, id, &h, (status, retry_after, reset_at), &cx).await,
        // Nothing an agent prints disables, counts toward a disable, or touches auth.
        Signal::Agent {
            class: "rate_limited",
        } => rate_limited(conn, id, &h, None, "rate_limited", &cx).await,
        Signal::Agent { class: "quota" } => {
            let e = Entry {
                reason: "quota",
                until: Some(now_u + QUOTA_COOLDOWN_SECS),
                backoff: None,
                clear_fails: false,
                class: "quota",
            };
            enter(conn, id, &h, e, &cx).await.map(drop)
        }
        Signal::Agent { .. } => Ok(()),
    }
}

/// [`on_signal`] in a write transaction of its own.
pub async fn signal(
    pool: &SqlitePool,
    ws: i64,
    id: i64,
    signal: Signal<'_>,
    now: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    on_signal(&mut tx, ws, id, signal, now).await?;
    tx.commit().await
}

async fn success(conn: &mut SqliteConnection, id: i64, cx: &Ctx<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_connections SET fail_streak = 0, backoff_secs = 0, fail_since = NULL, \
         last_success_at = ? WHERE id = ? AND (fail_streak != 0 OR backoff_secs != 0 \
         OR fail_since IS NOT NULL OR last_success_at IS NULL \
         OR julianday(last_success_at) < julianday(?) - 60.0 / 86400.0)",
    )
    .bind(cx.now)
    .bind(id)
    .bind(cx.now)
    .execute(conn)
    .await
    .map(drop)
}

async fn upstream(
    conn: &mut SqliteConnection,
    id: i64,
    h: &Health,
    (status, retry_after, reset_at): (UpstreamStatus, Option<u64>, Option<&str>),
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    match status {
        UpstreamStatus::Ok => success(conn, id, cx).await,
        UpstreamStatus::RateLimited => {
            let after = retry_after
                .map(|s| cx.now_u + i64::try_from(s).unwrap_or(i64::MAX).min(RATE_MAX_SECS));
            let reset = until_reset(reset_at, cx.now_u, RATE_MAX_SECS);
            rate_limited(conn, id, h, after.max(reset), "rate_limited", cx).await
        }
        UpstreamStatus::Quota => {
            let until = until_reset(reset_at, cx.now_u, QUOTA_MAX_SECS)
                .unwrap_or(cx.now_u + QUOTA_COOLDOWN_SECS);
            let e = Entry {
                reason: "quota",
                until: Some(until),
                backoff: None,
                clear_fails: false,
                class: "quota",
            };
            enter(conn, id, h, e, cx).await.map(drop)
        }
        UpstreamStatus::ServerError
        | UpstreamStatus::Unreachable
        | UpstreamStatus::TlsFailed
        | UpstreamStatus::RefusedAddress => {
            let fresh = h
                .fail_since
                .as_deref()
                .and_then(unix_secs)
                .is_some_and(|s| cx.now_u - s <= FAIL_WINDOW_SECS);
            let (streak, since) = match (fresh, &h.fail_since) {
                (true, Some(s)) => (h.fail_streak + 1, s.as_str()),
                _ => (1, cx.now),
            };
            sqlx::query("UPDATE core_connections SET fail_streak = ?, fail_since = ? WHERE id = ?")
                .bind(streak)
                .bind(since)
                .bind(id)
                .execute(&mut *conn)
                .await?;
            if streak >= FAIL_LIMIT {
                let e = Entry {
                    reason: "upstream_errors",
                    until: Some(cx.now_u + UNHEALTHY_SECS),
                    backoff: None,
                    clear_fails: true,
                    class: "upstream_errors",
                };
                enter(conn, id, h, e, cx).await?;
            }
            Ok(())
        }
        UpstreamStatus::AuthFailed => auth_failed(conn, id, h, cx).await,
        UpstreamStatus::Unknown => Ok(()),
    }
}

/// Suspects the credential: out of use until a test decides, never disabled by this alone.
async fn auth_failed(
    conn: &mut SqliteConnection,
    id: i64,
    h: &Health,
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    if h.state == "disabled" {
        return Ok(());
    }
    if !h.auth_pending {
        sqlx::query("UPDATE core_connections SET auth_pending = 1, auth_tries = 0 WHERE id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await?;
        let details = json!({"name": h.name, "state": "pending"});
        sys_audit(conn, "connection.auth_failed", id, details).await?;
    }
    let e = Entry {
        reason: "auth_suspected",
        until: None,
        backoff: None,
        clear_fails: false,
        class: "auth",
    };
    enter(conn, id, h, e, cx).await.map(drop)
}
