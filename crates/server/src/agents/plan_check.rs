//! `POST /accounts/{id}/check` for a Claude plan (N36): the plan's token never goes through the
//! gateway, so the key test cannot say whether it works. The Core leases the token (audited
//! `secret.leased` `"to":"plan-check"`) to a runner that lists `plan-check` and, being in the
//! account's scope, may hold it; the runner runs one `claude -p` with a one-word prompt in its
//! sandbox and answers a word. The outcome is recorded like a key test (`account.tested`), and
//! the plan windows Claude reported on the answer are kept like a session's
//! (`core_accounts.plan_limit`). It spends a little of the plan's quota, never money.
//!
//! A plan account nothing runs on would never say how full its windows are, so [`refresh_loop`]
//! checks one whose windows are unknown or older than [`REFRESH_AFTER_SECS`]: active only (never
//! a turned-off, cooling or failing one), not after its sign-in expired, on an idle runner only,
//! and at most once per [`REFRESH_AFTER_SECS`] per account, a manual check included.
//! Claude's `/usage` reads `api.anthropic.com/api/oauth/usage` with the token and spends no
//! message, but the token goes only to the claude harness as its env (`subscription_problem`),
//! so neither the Core nor a runner calls it itself.

use ainkrad_proto::v2::{Body, PlanCheck, Reply};

use super::*;
use crate::store::{account_keys, accounts, secrets};

/// At most one check an account a minute (it uses the plan's quota).
const EVERY_SECS: i64 = 60;
/// A check, runner side, is bounded to 90 s; the Core waits a little longer.
const WAIT: Duration = Duration::from_secs(100);
/// Plan windows older than this (or none) get a check of their own; and an account is checked
/// by [`refresh_loop`] at most once per this long.
pub const REFRESH_AFTER_SECS: i64 = 4 * 3600;
/// How often [`refresh_loop`] looks, and how long after the Core starts it first does.
const REFRESH_EVERY: Duration = Duration::from_secs(15 * 60);
const REFRESH_FIRST: Duration = Duration::from_secs(5 * 60);

/// What a check answered: `ok` or a reason, and the runner that ran it.
pub struct Checked {
    pub result: String,
    pub latency_ms: u64,
    /// Empty when no runner was asked.
    pub runner: String,
}

/// Why no check was made.
pub enum Failed {
    Gone,
    /// Not a subscription account (the caller uses the key test).
    NotPlan,
    Soon(&'static str),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for Failed {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

fn from_store(e: secrets::Error) -> Failed {
    match e {
        secrets::Error::Refused {
            code: "not_found", ..
        } => Failed::Gone,
        secrets::Error::Refused { .. } => Failed::Soon("the account's token cannot be leased now"),
        secrets::Error::Db(e) => Failed::Db(e),
    }
}

fn reason(result: &str) -> Checked {
    Checked {
        result: result.to_owned(),
        latency_ms: 0,
        runner: String::new(),
    }
}

/// Whether `r` lists `plan-check`.
fn lists_cap(r: &RunnerState) -> bool {
    r.drivers.iter().any(|d| {
        d.commands
            .iter()
            .any(|c| c == ainkrad_proto::v2::CAP_PLAN_CHECK)
    })
}

/// Checks plan account `id` on behalf of `caller`.
pub async fn run(app: &App, caller: &Caller, id: i64) -> Result<Checked, Failed> {
    let a = accounts::get(&app.pool, id).await.map_err(from_store)?;
    // The check is one `claude -p` run with the leased token: a runner-bound account has neither.
    if !account_keys::subscription_provider(&a.provider)
        || ainkrad_proto::v2::bound_harness(&a.provider).is_some()
    {
        return Err(Failed::NotPlan);
    }
    if account_keys::tested_within(&app.pool, id, &app.clock.now(), EVERY_SECS).await? {
        return Err(Failed::Soon("an account is checked at most once a minute"));
    }
    if !app.agents.confirming.lock().unwrap().insert(id) {
        return Err(Failed::Soon("a check of this account is running"));
    }
    let done = once(app, &caller.device.id, crate::api::v1::BY, &a, false).await;
    app.agents.confirming.lock().unwrap().remove(&id);
    done
}

/// A plan account (claude, not runner-bound) whose windows [`refresh`] should check now:
/// active (so never turned off), its sign-in not expired, its windows unknown or older than
/// [`REFRESH_AFTER_SECS`], and not checked within that long (a failing check does not repeat).
pub fn wants_refresh(a: &accounts::Account, plan_at: Option<i64>, now: i64) -> bool {
    let old = |at: Option<i64>| at.is_none_or(|t| now - t >= REFRESH_AFTER_SECS);
    let tested = a
        .last_test_at
        .as_deref()
        .and_then(crate::scheduler::unix_secs);
    account_keys::subscription_provider(&a.provider)
        && ainkrad_proto::v2::bound_harness(&a.provider).is_none()
        && a.state == "active"
        && a.last_test_result.as_deref() != Some("token_expired")
        && old(plan_at)
        && old(tested)
}

/// One pass of [`refresh_loop`]: checks every plan account [`wants_refresh`] picks, one at a time,
/// each on an idle runner only (none idle: nothing is run or recorded, the next pass tries).
pub async fn refresh(app: &App) {
    let now = app.clock.unix();
    let (all, st) = match (
        accounts::list(&app.pool).await,
        crate::store::health::statuses(&app.pool).await,
    ) {
        (Ok(all), Ok(st)) => (all, st),
        _ => return,
    };
    for a in all {
        let plan_at = st
            .get(&a.id)
            .and_then(|s| s.plan_limit.as_ref())
            .and_then(|p| p["at"].as_i64());
        if !wants_refresh(&a, plan_at, now) || !app.agents.confirming.lock().unwrap().insert(a.id) {
            continue;
        }
        // The account's own device stands behind it, as a session's lease names its creator.
        let done = once(app, &a.owner, AuditActor::System, &a, true).await;
        app.agents.confirming.lock().unwrap().remove(&a.id);
        match done {
            Ok(c) => tracing::info!(account = a.id, result = %c.result, "checked a plan's windows"),
            Err(_) => tracing::warn!(account = a.id, "could not check a plan's windows"),
        }
    }
}

/// Runs [`refresh`] every [`REFRESH_EVERY`] until the Core stops.
pub async fn refresh_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let mut tick =
        tokio::time::interval_at(tokio::time::Instant::now() + REFRESH_FIRST, REFRESH_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => refresh(&app).await,
            () = crate::api::stopping(&mut closing) => return,
        }
    }
}

/// `idle`: only on a runner with nothing in flight (the background refresh).
async fn once(
    app: &App,
    by_device: &str,
    actor: AuditActor,
    a: &accounts::Account,
    idle: bool,
) -> Result<Checked, Failed> {
    let mut online: Vec<(String, bool)> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(id, r)| {
            r.online
                && (!idle || r.load == 0)
                && a.runners.contains(id)
                && subscription::lists_cap(r)
        })
        .map(|(id, r)| (id, lists_cap(&r)))
        .collect();
    online.sort();
    // A runner that holds subscription tokens but cannot run the check is an old one.
    let Some((runner, _)) = online.iter().find(|(_, new)| *new).cloned() else {
        return Ok(reason(match online.is_empty() {
            true => "no_runner",
            false => "runner_outdated",
        }));
    };
    let (lease, _) = secrets::lease_to(
        &app.pool,
        &a.secret_name,
        &runner,
        None,
        by_device,
        actor,
        &app.clock.now(),
        app.clock.unix(),
        Some("plan-check"),
    )
    .await
    .map_err(from_store)?;
    let asked = async {
        let sent = app.hub.dispatch_plan_check(
            &runner,
            PlanCheck {
                lease: lease.clone(),
            },
        )?;
        tokio::time::timeout(WAIT, sent.outcome())
            .await
            .map_err(|_| StreamError::new(ErrorCode::Lost, "the runner did not answer in time"))?
    }
    .await;
    let (checked, plan) = match asked {
        Ok(Body::Result(Reply::PlanCheck(c))) => (
            Checked {
                result: c.result,
                latency_ms: c.latency_ms,
                runner: runner.clone(),
            },
            c.plan_limit,
        ),
        other => {
            // Nobody redeemed it: it must not stay live against the runner's cap.
            let _ = account_keys::revoke_unused_lease(&app.pool, &lease).await;
            let why = match other {
                Err(e) if e.code == ErrorCode::Busy => "runner_busy",
                Err(e) if e.code == ErrorCode::UnsupportedCommand => "runner_outdated",
                _ => "runner_failed",
            };
            return Ok(Checked {
                runner,
                ..reason(why)
            });
        }
    };
    // Recorded as a test of the account: when it was last checked, and the answer (a class).
    let at = app.clock.now();
    account_keys::record_test(
        &app.pool,
        a.id,
        &checked.result,
        checked.latency_ms,
        &checked.runner,
        by_device,
        actor,
        &at,
    )
    .await
    .map_err(from_store)?;
    // The windows Claude reported on the answer, kept like a session's (same row, same `at`).
    if let Some(plan) = &plan {
        crate::store::health::keep_checked_plan(&app.pool, a.id, plan, &at).await?;
    }
    Ok(checked)
}
