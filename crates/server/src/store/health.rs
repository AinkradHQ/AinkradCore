//! Account health (KAN-438 part A, S3; design `2026-11-06-core-account-scheduler` §7, §10): what an
//! account's signals do to its state. [`on_signal`] is the one entry; every other function here
//! finds the account and the signal and calls it.
//!
//! - **Two trust levels.** A gateway report ([`Signal::Gateway`]) cannot be forged by the agent (only
//!   the runner's gateway task writes it), so it may cool an account, mark it unhealthy and count.
//!   Everything the harness prints ([`Signal::HarnessEnd`], [`Signal::HarnessPlan`]) can be forged
//!   by a tool beside the harness. Such a signal may only **cool** an account (`rate_limited`,
//!   `quota`), count a subscription's failed sessions toward `auth_suspected`, and nothing else: no
//!   code in this file disables an account, rotates or revokes a secret, or touches a lease.
//! - **Which account.** Always the session row's: `gateway_account_id` for an API key, the
//!   `acct.claude-sub.<id>` secret for a subscription (as `usage_meter` reads it), never anything a
//!   signal names. A gateway session ignores the harness path entirely.
//! - **What a harness signal may write.** Only over `active`, or to a higher rank than one of this
//!   module's own timed states (`rate_limited` < `upstream_errors` < `quota` < `auth_suspected`).
//!   It never extends a window that is open, never writes over `disabled` or an admin's own state
//!   (an admin's state is stored with the reason `manual`, never one of the codes), and its `until` is clamped to [`HARNESS_MAX_SECS`].
//! - **Closed class set.** A harness end counts only when its fingerprint is exactly one of the
//!   eight `ErrorClass::as_str` values ([`CLASSES`]); a runner step name, `core`, `harness_*` or a
//!   raw `<harness>:<code>` is no signal, and the Core never classifies text itself.
//! - **Lazy recovery.** A timed state whose `state_until` has passed is `active` again the next
//!   time anything looks ([`recover`], audited `account.state_set` by the system); no timer.
//! - **No new contract.** A change of state is an `account.state_set` audit row by the system (the
//!   `audit` event follows it); the dedicated `account.limited` and `account.health` event kinds
//!   come with the scheduler API (S7).

use ainkrad_proto::v2::{PlanLimit, UpstreamStatus};
use serde_json::json;
use sqlx::{Row, SqliteConnection};

use crate::scheduler::{iso_of_unix, unix_secs};

/// A rate-limit cooldown starts at this, and doubles per cooldown with no success between.
pub const BACKOFF_START_SECS: i64 = 60;
/// The most a rate-limit backoff grows to.
pub const BACKOFF_MAX_SECS: i64 = 30 * 60;
/// How long a quota-limited account waits when nothing says when its limit resets.
pub const QUOTA_COOLDOWN_SECS: i64 = 6 * 3600;
/// The most an upstream's `retry-after` or reset time cools an account for (rate limit).
pub const RATE_MAX_SECS: i64 = 24 * 3600;
/// The most an upstream's reset time keeps an account limited (quota).
pub const QUOTA_MAX_SECS: i64 = 7 * 24 * 3600;
/// The most any harness-output signal cools an account for.
pub const HARNESS_MAX_SECS: i64 = 6 * 3600;
/// Upstream errors count inside this window, and this many put the account out for
/// [`UNHEALTHY_SECS`].
pub const FAIL_WINDOW_SECS: i64 = 10 * 60;
pub const FAIL_LIMIT: i64 = 3;
pub const UNHEALTHY_SECS: i64 = 10 * 60;
/// This many failed `auth` sessions in a row keep a subscription out of new runs.
pub const AUTH_LIMIT: i64 = 3;
/// A plan window at or above this fraction of its limit cools the account until it resets.
const PLAN_WARN: f64 = 0.95;
/// A success refreshes `last_success_at` at most this often.
const SUCCESS_THROTTLE_SECS: i64 = 60;

/// The `ErrorClass::as_str` set of `ainkrad-harness`, the only fingerprints that are a class. The
/// server does not depend on the harness crate; a test of the runner pins the two together.
pub const CLASSES: [&str; 8] = [
    "model_unavailable",
    "rate_limited",
    "quota",
    "auth",
    "transient",
    "unhealthy",
    "protocol",
    "permanent",
];

/// What happened to an account.
pub enum Signal<'a> {
    /// An upstream status of the account's own gateway (trusted).
    Gateway {
        status: UpstreamStatus,
        retry_after: Option<u64>,
        reset_at: Option<&'a str>,
    },
    /// A harness session on the account ended failed with this fingerprint (forgeable).
    HarnessEnd { class: &'a str },
    /// The harness's latest plan-limit snapshot (forgeable).
    HarnessPlan { plan: &'a PlanLimit },
    /// A request or a session went well: streaks and backoff start over.
    Success,
}

/// The rank of a reason this module writes; a state is overwritten only by a higher one.
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

struct Health {
    label: String,
    state: String,
    reason: Option<String>,
    until: Option<i64>,
    fail_streak: i64,
    auth_streak: i64,
    backoff: i64,
    fail_since: Option<String>,
}

async fn load(conn: &mut SqliteConnection, account: i64) -> Result<Option<Health>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT label, state, state_reason, state_until, fail_streak, auth_streak, backoff_secs, \
         fail_since FROM core_accounts WHERE id = ?",
    )
    .bind(account)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(Health {
        label: r.try_get("label")?,
        state: r.try_get("state")?,
        reason: r.try_get("state_reason")?,
        until: r
            .try_get::<Option<String>, _>("state_until")?
            .as_deref()
            .and_then(unix_secs),
        fail_streak: r.try_get("fail_streak")?,
        auth_streak: r.try_get("auth_streak")?,
        backoff: r.try_get("backoff_secs")?,
        fail_since: r.try_get("fail_since")?,
    }))
}

/// What a signal is judged with.
struct Ctx<'a> {
    session: &'a str,
    trusted: bool,
    now: &'a str,
    now_u: i64,
}

struct Entry<'a> {
    reason: &'static str,
    until: Option<i64>,
    /// The new backoff, when this entry is a new cooldown.
    backoff: Option<i64>,
    /// A new `unhealthy` window starts its error count again.
    clear_fails: bool,
    class: &'a str,
}

/// Writes the state of `e` if `h` allows it (see the module docs); whether it did.
async fn enter(
    conn: &mut SqliteConnection,
    account: i64,
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
        ("cooling" | "limited" | "unhealthy", Some(old)) => {
            new > old || (cx.trusted && new == old && until > h.until)
        }
        _ => false,
    };
    if !allowed {
        return Ok(false);
    }
    // A window this module opened is never shortened by a stronger state: the provider's own
    // 24 h still holds when three 5xx follow its 429. A state with no end stays open-ended.
    if let (Some(n), Some(o)) = (until, h.until) {
        until = Some(n.max(o));
    }
    let (state, until_iso) = (state_of(e.reason), until.map(iso_of_unix));
    sqlx::query(
        "UPDATE core_accounts SET state = ?, state_reason = ?, state_until = ?, \
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
    .bind(account)
    .execute(&mut *conn)
    .await?;
    // One audit row per change of state or reason, not per report: a sustained 429 that only
    // lengthens the open window is written silently.
    if h.state != state || h.reason.as_deref() != Some(e.reason) {
        let source = if cx.trusted { "gateway" } else { "harness" };
        let details = json!({"label": h.label, "from": h.state, "to": state, "reason": e.reason,
            "until": until_iso, "source": source, "class": e.class, "session": cx.session});
        audited(conn, account, details).await?;
    }
    Ok(true)
}

fn next_backoff(prev: i64) -> i64 {
    match prev {
        p if p <= 0 => BACKOFF_START_SECS,
        p => (p * 2).min(BACKOFF_MAX_SECS),
    }
}

/// `reset` as seconds from now when it is a future RFC 3339 time, at most `max`.
fn until_reset(reset: Option<&str>, now_u: i64, max: i64) -> Option<i64> {
    let at = reset.and_then(unix_secs).filter(|at| *at > now_u)?;
    Some(at.min(now_u + max))
}

/// What `signal` does to `account`, in the caller's write transaction. `session` is only named in
/// the audit row. This is the single entry for account health.
pub async fn on_signal(
    conn: &mut SqliteConnection,
    account: i64,
    session: &str,
    signal: Signal<'_>,
    now: &str,
) -> Result<(), sqlx::Error> {
    let Some(now_u) = unix_secs(now) else {
        return Ok(());
    };
    recover_in(conn, account, now).await?;
    let Some(h) = load(conn, account).await? else {
        return Ok(());
    };
    let cx = Ctx {
        session,
        trusted: matches!(signal, Signal::Gateway { .. }),
        now,
        now_u,
    };
    match signal {
        Signal::Success => success(conn, account, &cx).await,
        Signal::Gateway {
            status,
            retry_after,
            reset_at,
        } => gateway(conn, account, &h, (status, retry_after, reset_at), &cx).await,
        Signal::HarnessEnd { class } => harness_end(conn, account, &h, class, &cx).await,
        Signal::HarnessPlan { plan } => harness_plan(conn, account, &h, plan, &cx).await,
    }
}

async fn success(
    conn: &mut SqliteConnection,
    account: i64,
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    let stale = iso_of_unix(cx.now_u - SUCCESS_THROTTLE_SECS);
    sqlx::query(
        "UPDATE core_accounts SET fail_streak = 0, auth_streak = 0, backoff_secs = 0, \
         fail_since = NULL, last_success_at = ?1 WHERE id = ?2 AND (fail_streak != 0 \
         OR auth_streak != 0 OR backoff_secs != 0 OR fail_since IS NOT NULL \
         OR last_success_at IS NULL OR last_success_at < ?3)",
    )
    .bind(cx.now)
    .bind(account)
    .bind(stale)
    .execute(conn)
    .await
    .map(drop)
}

/// A new rate-limit cooldown (or the extension of the one that is open) until `reset` at the
/// earliest; the backoff doubles only when a cooldown starts.
async fn rate_limited(
    conn: &mut SqliteConnection,
    account: i64,
    h: &Health,
    reset: Option<i64>,
    class: &str,
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    let open = h.state == "cooling" && h.reason.as_deref() == Some("rate_limited");
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
    enter(conn, account, h, e, cx).await.map(drop)
}

async fn gateway(
    conn: &mut SqliteConnection,
    account: i64,
    h: &Health,
    (status, retry_after, reset_at): (UpstreamStatus, Option<u64>, Option<&str>),
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    match status {
        UpstreamStatus::Ok => success(conn, account, cx).await,
        UpstreamStatus::RateLimited => {
            let after = retry_after
                .map(|s| cx.now_u + i64::try_from(s).unwrap_or(i64::MAX).min(RATE_MAX_SECS));
            let reset = until_reset(reset_at, cx.now_u, RATE_MAX_SECS);
            rate_limited(conn, account, h, after.max(reset), "rate_limited", cx).await
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
            enter(conn, account, h, e, cx).await.map(drop)
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
            sqlx::query("UPDATE core_accounts SET fail_streak = ?, fail_since = ? WHERE id = ?")
                .bind(streak)
                .bind(since)
                .bind(account)
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
                enter(conn, account, h, e, cx).await?;
            }
            Ok(())
        }
        // An auth failure has its own, confirmed path (`signals`); nothing else is a signal.
        UpstreamStatus::AuthFailed | UpstreamStatus::Unknown => Ok(()),
    }
}

async fn harness_end(
    conn: &mut SqliteConnection,
    account: i64,
    h: &Health,
    class: &str,
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    match class {
        "rate_limited" => rate_limited(conn, account, h, None, class, cx).await,
        "quota" => {
            let e = Entry {
                reason: "quota",
                until: Some(cx.now_u + QUOTA_COOLDOWN_SECS),
                backoff: None,
                clear_fails: false,
                class,
            };
            enter(conn, account, h, e, cx).await.map(drop)
        }
        "auth" => {
            let streak = h.auth_streak + 1;
            sqlx::query("UPDATE core_accounts SET auth_streak = ? WHERE id = ?")
                .bind(streak)
                .bind(account)
                .execute(&mut *conn)
                .await?;
            if streak >= AUTH_LIMIT {
                let e = Entry {
                    reason: "auth_suspected",
                    until: None,
                    backoff: None,
                    clear_fails: false,
                    class,
                };
                enter(conn, account, h, e, cx).await?;
            }
            Ok(())
        }
        // The other classes say the task failed, not the account; a name outside the closed set
        // (a step, `core`, a raw `<harness>:<code>`) says nothing.
        _ => Ok(()),
    }
}

async fn harness_plan(
    conn: &mut SqliteConnection,
    account: i64,
    h: &Health,
    plan: &PlanLimit,
    cx: &Ctx<'_>,
) -> Result<(), sqlx::Error> {
    let future = |at: Option<i64>| at.filter(|at| *at > cx.now_u);
    let rejected = plan.status == "rejected";
    let resets = plan
        .windows
        .iter()
        .filter(|w| rejected || w.utilization >= PLAN_WARN)
        .filter_map(|w| future(w.resets_at))
        .max();
    let warned = plan.windows.iter().any(|w| w.utilization >= PLAN_WARN);
    if !(rejected || (warned && resets.is_some())) || h.state != "active" {
        return Ok(());
    }
    // One cooling per session: a snapshot a running session keeps resending cannot re-cool the
    // account each time a window ends.
    let first = sqlx::query(
        "UPDATE core_agent_sessions SET plan_cooled = 1 WHERE id = ? AND plan_cooled = 0",
    )
    .bind(cx.session)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if first == 0 {
        return Ok(());
    }
    rate_limited(conn, account, h, resets, "plan_limit", cx).await
}

mod recover;
mod session;
pub use recover::*;
pub use session::*;
