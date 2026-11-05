//! `POST /accounts/{id}/test` (KAN-435 G7; design §7.1, decision 5): one `gateway.test` through a
//! runner's gateway. The Core never dials a provider URL itself: it picks a runner that is online,
//! offers the gateway and is in the key's scope, leases the key to it (audited `secret.leased`
//! `"to":"gateway"`), and the runner makes one free request to the host the key was bound to. What
//! comes back is a status class and a latency, never a body.

use super::*;
use crate::store::account_keys;

/// A test at most this often per account.
const EVERY_SECS: i64 = 60;

/// What a test answered.
pub struct Tested {
    pub result: UpstreamStatus,
    pub latency_ms: u64,
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
/// outcome in the account's test columns and the audit.
pub async fn run(app: &App, caller: &Caller, id: i64) -> Result<Tested, Failed> {
    let a = accounts::get(&app.pool, id).await.map_err(from_store)?;
    let now = app.clock.now();
    if account_keys::tested_within(&app.pool, id, &now, EVERY_SECS).await? {
        return Err(Failed::Soon("an account is tested at most once a minute"));
    }
    // One test of a key at a time, also against the auth-failure check that shares the set.
    if !app.agents.confirming.lock().unwrap().insert(id) {
        return Err(Failed::Soon("a test of this account is running"));
    }
    let done = once(app, caller, &a).await;
    app.agents.confirming.lock().unwrap().remove(&id);
    let tested = done?;
    let by = &caller.device.id;
    let result = class_name(tested.result);
    account_keys::record_test(
        &app.pool,
        id,
        &result,
        tested.latency_ms,
        &tested.runner,
        by,
        crate::api::v1::BY,
        &app.clock.now(),
    )
    .await
    .map_err(from_store)?;
    Ok(tested)
}

async fn once(app: &App, caller: &Caller, a: &accounts::Account) -> Result<Tested, Failed> {
    let def = providers::get(&app.pool, &a.provider)
        .await
        .map_err(from_store)?;
    let route = route::of(&def, &a.base_url).map_err(describe_refusal)?;
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
    let test = GatewayTest {
        lease,
        provider: a.provider.clone(),
        user_key: route.user_key,
        upstream,
    };
    let proof = app.hub.gateway_test_elevation(caller);
    let sent = app
        .hub
        .dispatch_elevated(&runner, Command::GatewayTest(test), proof)
        .map_err(|e| Failed::Runner(e.message))?;
    let answer = tokio::time::timeout(TEST_WAIT, sent.outcome())
        .await
        .map_err(|_| Failed::Runner("the runner did not answer the test in time".to_owned()))?
        .map_err(|e| Failed::Runner(e.message))?;
    match answer {
        Body::Result(Reply::GatewayTest(t)) => Ok(Tested {
            result: t.result,
            latency_ms: t.latency_ms,
            runner,
        }),
        _ => Err(Failed::Runner(
            "the runner answered something else".to_owned(),
        )),
    }
}
