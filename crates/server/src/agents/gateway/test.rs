//! `POST /accounts/{id}/test` (KAN-435 G7; design §7.1, decision 5): one `gateway.test` through a
//! runner's gateway. The Core never dials a provider URL itself: it picks a runner that is online,
//! offers the gateway and is in the key's scope, leases the key to it (audited `secret.leased`
//! `"to":"gateway"`), and the runner makes one free request to the host the key was bound to. What
//! comes back is a status class and a latency, never a body.

use super::*;
use crate::store::account_keys;

/// A test at most this often per account.
const EVERY_SECS: i64 = 60;

/// The class recorded when a test was sent and did not answer (the runner failed or timed out):
/// the attempt counts for the rate limit, and says so.
const FAILED: &str = "failed";

/// The class of a test of a provider whose model list says nothing about the key.
pub const INCONCLUSIVE: &str = "inconclusive";

/// What a test answered. `result` is a status class (`ok`, `auth_failed`, ...), or `inconclusive`.
pub struct Tested {
    pub result: String,
    pub latency_ms: u64,
    /// The runner that made the request; empty for an `inconclusive` test, which sent none.
    pub runner: String,
}

/// Why no test was made, or why it did not answer.
pub enum Failed {
    /// No such account.
    Gone,
    /// The last test was too recent, or one is running now.
    Soon(&'static str),
    /// No runner in the key's scope is online and offers the gateway.
    NoRunner,
    /// The lease, the provider's definition or the account's URL refused it.
    Refused(String),
    /// The runner failed or did not answer.
    Runner(String),
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
        secrets::Error::Refused { message, .. } => Failed::Refused(message),
        secrets::Error::Db(e) => Failed::Db(e),
    }
}

fn describe_refusal(r: Refusal) -> Failed {
    match r {
        Refusal::Runner(e) => Failed::Refused(e.message),
        Refusal::Secrets(e) => from_store(e),
        Refusal::Db(e) => Failed::Db(e),
    }
}

/// The class a test or a request ended in, as the wire spells it.
pub fn class_name(s: UpstreamStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Tests account `id`'s key through a runner, on behalf of `caller` (an admin), and records the
/// outcome in the account's test columns and the audit. A test that was sent and did not answer is
/// recorded too (`failed`), so a failing runner is limited like a working one. The account stays
/// marked as under test until the record is written.
pub async fn run(app: &App, caller: &Caller, id: i64) -> Result<Tested, Failed> {
    let a = accounts::get(&app.pool, id).await.map_err(from_store)?;
    if account_keys::tested_within(&app.pool, id, &app.clock.now(), EVERY_SECS).await? {
        return Err(Failed::Soon("an account is tested at most once a minute"));
    }
    // One test of a key at a time, also against the auth-failure check that shares the set.
    if !app.agents.confirming.lock().unwrap().insert(id) {
        return Err(Failed::Soon("a test of this account is running"));
    }
    let mut sent_to = None;
    let done = once(app, caller, &a, &mut sent_to).await;
    let by = &caller.device.id;
    let recorded = match (&done, &sent_to) {
        (Ok(t), _) => record(app, id, &t.result, t.latency_ms, &t.runner, by).await,
        (Err(_), Some(runner)) => record(app, id, FAILED, 0, runner, by).await,
        (Err(_), None) => Ok(()),
    };
    app.agents.confirming.lock().unwrap().remove(&id);
    let tested = done?;
    recorded.map_err(from_store)?;
    Ok(tested)
}

async fn record(
    app: &App,
    id: i64,
    result: &str,
    latency_ms: u64,
    runner: &str,
    by_device: &str,
) -> Result<(), secrets::Error> {
    let now = app.clock.now();
    let actor = crate::api::v1::BY;
    account_keys::record_test(
        &app.pool, id, result, latency_ms, runner, by_device, actor, &now,
    )
    .await
    .map(drop)
}

/// The test itself. `sent_to` is set once a lease was minted for a runner: from there the attempt
/// is recorded whatever happens, and a lease the runner never redeemed is revoked.
async fn once(
    app: &App,
    caller: &Caller,
    a: &accounts::Account,
    sent_to: &mut Option<String>,
) -> Result<Tested, Failed> {
    let def = providers::get(&app.pool, &a.provider)
        .await
        .map_err(from_store)?;
    let route = route::of(&def, &a.base_url).map_err(describe_refusal)?;
    // A provider whose model list needs no key (OpenRouter's) cannot say anything about the key
    // without a declared authenticated path: nothing is leased, and the answer is never `ok`.
    if !route.can_test {
        return Ok(Tested {
            result: INCONCLUSIVE.to_owned(),
            latency_ms: 0,
            runner: String::new(),
        });
    }
    let upstream = upstream_of(&a.base_url, route.wire).map_err(describe_refusal)?;
    // Only a runner that is there, offers the gateway and is in the key's scope is asked, and
    // nothing is leased for another: a lease nobody redeems counts against the runner's cap.
    let mut ready: Vec<String> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(id, r)| r.online && a.runners.contains(id) && gateway_refusal(r).is_none())
        .map(|(id, _)| id)
        .collect();
    ready.sort();
    let Some(runner) = ready.into_iter().next() else {
        return Err(Failed::NoRunner);
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
        Some("gateway"),
    )
    .await
    .map_err(from_store)?;
    *sent_to = Some(runner.clone());
    let test = GatewayTest {
        lease: lease.clone(),
        provider: a.provider.clone(),
        user_key: route.user_key,
        upstream,
        test_path: route.test_path,
    };
    let asked = async {
        let sent = app
            .hub
            .dispatch_gateway_test(&runner, test)
            .map_err(|e| Failed::Runner(e.message))?;
        tokio::time::timeout(TEST_WAIT, sent.outcome())
            .await
            .map_err(|_| Failed::Runner("the runner did not answer the test in time".to_owned()))?
            .map_err(|e| Failed::Runner(e.message))
    }
    .await;
    let answer = match asked {
        Ok(answer) => answer,
        Err(e) => {
            // Nobody redeems it now: it must not stay live against the runner's cap.
            let _ = account_keys::revoke_unused_lease(&app.pool, &lease).await;
            return Err(e);
        }
    };
    match answer {
        Body::Result(Reply::GatewayTest(t)) => Ok(Tested {
            result: class_name(t.result),
            latency_ms: t.latency_ms,
            runner,
        }),
        _ => Err(Failed::Runner(
            "the runner answered something else".to_owned(),
        )),
    }
}
