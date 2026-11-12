//! `POST /accounts/{id}/check` for a Claude plan (N36): the plan's token never goes through the
//! gateway, so the key test cannot say whether it works. The Core leases the token (audited
//! `secret.leased` `"to":"plan-check"`) to a runner that lists `plan-check` and, being in the
//! account's scope, may hold it; the runner runs one `claude -p` with a one-word prompt in its
//! sandbox and answers a word. The outcome is recorded like a key test (`account.tested`).
//! It spends a little of the plan's quota, never money.

use ainkrad_proto::v2::{Body, PlanCheck, Reply};

use super::*;
use crate::store::{account_keys, accounts, secrets};

/// At most one check an account a minute (it uses the plan's quota).
const EVERY_SECS: i64 = 60;
/// A check, runner side, is bounded to 90 s; the Core waits a little longer.
const WAIT: Duration = Duration::from_secs(100);

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
    if !account_keys::subscription_provider(&a.provider) {
        return Err(Failed::NotPlan);
    }
    if account_keys::tested_within(&app.pool, id, &app.clock.now(), EVERY_SECS).await? {
        return Err(Failed::Soon("an account is checked at most once a minute"));
    }
    if !app.agents.confirming.lock().unwrap().insert(id) {
        return Err(Failed::Soon("a check of this account is running"));
    }
    let done = once(app, caller, &a).await;
    app.agents.confirming.lock().unwrap().remove(&id);
    done
}

async fn once(app: &App, caller: &Caller, a: &accounts::Account) -> Result<Checked, Failed> {
    let mut online: Vec<(String, bool)> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(id, r)| r.online && a.runners.contains(id) && subscription::lists_cap(r))
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
        &caller.device.id,
        crate::api::v1::BY,
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
    let checked = match asked {
        Ok(Body::Result(Reply::PlanCheck(c))) => Checked {
            result: c.result,
            latency_ms: c.latency_ms,
            runner: runner.clone(),
        },
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
        &caller.device.id,
        crate::api::v1::BY,
        &at,
    )
    .await
    .map_err(from_store)?;
    Ok(checked)
}
