//! The auth gateway as the Core drives it (KAN-435 G5): the grant a session starts with, the stop a
//! budget orders, and the check that decides whether a provider really refuses an account's key.
//! The money itself (the hold, the ledger rows, the cursor) is `store::gateway`.
//!
//! - **Grant.** A session whose secret is an API-key account (`acct.<provider>.<id>`, the account
//!   model's own name) never gets that key as an environment variable. The Core builds a
//!   [`GatewayGrant`] from its own rows: the upstream from the account's frozen `base_url`, the models
//!   and prices from its price book, the ceiling from the budgets' hold, and a lease on the key that
//!   only the session's runner can redeem, into its gateway's memory.
//! - **Stop.** When a hard-stop budget has nothing left, `agent.limit 0` makes the gateway refuse
//!   everything and abort open streams, then `agent.stop` cancels the session (decision 7), and the
//!   runner is told to kill it if it is still there after a grace.
//! - **Auth failure.** One `auth_failed` from an upstream never disables an account. A one-shot
//!   `gateway.test` through the runner's gateway decides: only a provider that refuses the key again
//!   disables it.

use ainkrad_proto::v2::{
    AgentLimit, AgentStop, Ceiling, GatewayGrant, GatewayTest, ModelPrice, Rate, Upstream,
    UpstreamStatus, Wire,
};

mod route;
pub mod test;
pub(super) use route::secrets_problem;

use super::*;
use crate::store::gateway as gw;
use crate::store::{accounts, costs, prices, providers, secrets};

/// How fast a session may call, and how many requests at once (design §4.7: concurrency 2).
const RATE: Rate = Rate {
    per_minute: 120,
    concurrent: 2,
};

/// A session a stop was ordered for is killed if it is still there after this many seconds.
const STOP_GRACE_SECS: i64 = 30;

/// How long a one-shot `gateway.test` may take.
const TEST_WAIT: Duration = Duration::from_secs(60);

fn refuse(why: impl Into<String>) -> Refusal {
    Refusal::Runner(StreamError::new(ErrorCode::InvalidArgs, why))
}

/// A broker or budget error as the launch reports it: a refusal says why, a database error retries.
fn lift(e: secrets::Error) -> Refusal {
    match e {
        secrets::Error::Refused { message, .. } => refuse(message),
        secrets::Error::Db(e) => Refusal::Db(e),
    }
}

/// The upstream the account's frozen `base_url` names: `https://host[/path]`, port 443 only.
pub(super) fn upstream_of(base_url: &str, wire: Wire) -> Result<Upstream, Refusal> {
    if let Some(why) = crate::store::providers::url_problem(base_url) {
        return Err(refuse(format!(
            "the account's base URL is not usable: {why}"
        )));
    }
    let rest = base_url.strip_prefix("https://").unwrap_or(base_url);
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.strip_suffix(":443").unwrap_or(host);
    let path = path.trim_end_matches('/');
    Ok(Upstream {
        host: host.to_owned(),
        base_path: if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        },
        wire,
        auth: wire.auth(),
    })
}

/// A grant, and when its lease ends.
pub(super) struct Issued {
    pub grant: Box<GatewayGrant>,
    pub until: i64,
}

/// The grant `s` starts with, or `None` for a session no gateway serves. Every refusal is final for
/// this start (the account is gone, disabled, unpriced, or the budgets leave too little); a database
/// error is not. The hold it takes is the grant's ceiling: what is left now, so a resume (a new
/// gateway, spent 0) cannot spend what an earlier epoch already did.
pub(super) async fn grant(app: &App, s: &Session) -> Result<Option<Issued>, Refusal> {
    let Some(secret) = gw::gateway_secret(&s.secrets) else {
        return Ok(None);
    };
    let Some((provider, named)) = gw::account_secret(&secret.name) else {
        return Ok(None);
    };
    let id = match s.gateway_account_id {
        Some(id) if id == named => id,
        _ => return Err(refuse("the session's account does not exist")),
    };
    let account = accounts::get(&app.pool, id).await.map_err(lift)?;
    if account.secret_name != secret.name || account.provider != provider {
        return Err(refuse(
            "the session's account is not the one its secret names",
        ));
    }
    if account.state != "active" {
        return Err(refuse(format!(
            "the account is {}, not active",
            account.state
        )));
    }
    // The provider's definition (a built-in's is code) says which harness speaks to it.
    let def = providers::get(&app.pool, provider).await.map_err(lift)?;
    if !costs::HARNESSES.contains(&s.harness.as_str()) || def.harness != s.harness {
        return Err(refuse(
            "a gateway session runs its provider's own harness (claude, codex or agy)",
        ));
    }
    let route = route::of(&def, &account.base_url)?;
    let upstream = upstream_of(&account.base_url, route.wire)?;
    // The allowlist is the price book: a model with no price is refused, so dollar ceilings mean something.
    let mut book: Vec<_> = prices::list(&app.pool)
        .await?
        .into_iter()
        .filter(|p| p.provider == provider)
        .collect();
    // A user definition's own priced models are the fallback, as `prices::rates` reads them (the
    // book wins; the cache rate is the input rate).
    let fallback: Vec<prices::Price> = def
        .models
        .iter()
        .filter(|m| !book.iter().any(|p| p.model == m.id))
        .filter_map(|m| {
            let at = def.priced_at.as_ref().filter(|_| !def.builtin)?;
            Some(prices::Price {
                provider: provider.to_owned(),
                model: m.id.clone(),
                version: 0,
                input_per_mtok_micro: m.input_per_mtok_micro,
                output_per_mtok_micro: m.output_per_mtok_micro,
                cache_per_mtok_micro: m.input_per_mtok_micro,
                priced_at: at.clone(),
                created_at: String::new(),
            })
        })
        .collect();
    book.extend(fallback);
    let rate = |n: i64| u64::try_from(n).unwrap_or(0);
    let prices: Vec<ModelPrice> = book
        .iter()
        .map(|p| ModelPrice {
            model: p.model.clone(),
            input: rate(p.input_per_mtok_micro),
            output: rate(p.output_per_mtok_micro),
            cache_read: rate(p.cache_per_mtok_micro),
            cache_write: rate(p.cache_per_mtok_micro),
        })
        .collect();
    let models: Vec<String> = book.iter().map(|p| p.model.clone()).collect();
    if models.is_empty() {
        return Err(refuse(format!(
            "no model of {provider} has a price: set one in the price book first"
        )));
    }
    if let Some(m) = s.model.as_ref().filter(|m| !models.contains(*m)) {
        return Err(refuse(format!("the model {m} has no price for {provider}")));
    }
    let now = app.clock.now();
    let ceiling = match gw::reserve(
        &app.pool,
        &s.id,
        id,
        gw::min_turn_usd(&prices, s.model.as_deref()),
        &now,
    )
    .await
    .map_err(lift)?
    {
        gw::Hold::Granted(c) => c,
        gw::Hold::Denied(why) => return Err(refuse(why)),
    };
    // What the gateway is given is kept: the Core prices from it if the book loses a model, and
    // tops the ceiling up from it (`agents::topup`).
    gw::save_grant(&app.pool, &s.id, ceiling, &book).await?;
    let (lease, until) = secrets::lease_to(
        &app.pool,
        &account.secret_name,
        &s.runner,
        None,
        &s.created_by,
        AuditActor::System,
        &now,
        app.clock.unix(),
        Some("gateway"),
    )
    .await?;
    Ok(Some(Issued {
        grant: Box::new(GatewayGrant {
            lease,
            account: id,
            provider: provider.to_owned(),
            user_key: route.user_key,
            upstream,
            models,
            prices,
            ceiling,
            rate: RATE,
        }),
        until,
    }))
}

/// Why a session owned by a module may not name an API-key account: the ledger records a gateway
/// session against its account and pools only, so a module's agent, company and issue budgets
/// would not bind it. Until a module's subjects are carried to the gateway's rows, it is refused.
pub(super) fn module_refusal(secrets: &[store::SessionSecret]) -> Option<&'static str> {
    gw::gateway_secret(secrets).map(|_| {
        "a module's session may not use an API-key account yet: its agent, company and issue \
         budgets would not bind the gateway's spend"
    })
}

/// What the Core does about a gateway session after each answer it stored: a stop a budget ordered,
/// and the check of an upstream `auth_failed`. Only the logs hear of a failure: the next answer
/// tries again.
pub(super) async fn after(app: &App, s: &Session) {
    let Some(account) = s.gateway_account_id else {
        return;
    };
    // A gateway that has too little left for a turn is raised, or its session marked to stop.
    if s.state == "running" && s.gw_stop.is_none() {
        super::topup::run(app, s).await;
    }
    // Only a running session is stopped: another one has nothing to refuse or cancel on its runner,
    // and its next start reserves again (a denial ends it, room lifts the mark). The row is read
    // again: the raise above may have marked it.
    let fresh = match store::get(&app.pool, &s.id).await {
        Ok(Some(row)) => row,
        _ => s.clone(),
    };
    if let Some(why) = fresh
        .gw_stop
        .as_deref()
        .filter(|_| fresh.state == "running")
        && let Err(e) = enforce(app, &fresh, why).await
    {
        tracing::warn!(
            session = s.id,
            why = describe(&e),
            "stopping a session a budget ended"
        );
    }
    match gw::pending_auth(&app.pool, account).await {
        Ok(Some(_)) => confirm(app, s, account),
        Ok(None) => {}
        Err(e) => tracing::warn!(session = s.id, error = %e, "reading an account's auth signals"),
    }
}

/// An answer to a stop command: the runner not knowing the session, or it not running, is a session
/// that is already stopped; anything else is a failure.
fn stopped(r: Result<AgentEvents, StreamError>) -> Result<Option<AgentEvents>, Refusal> {
    match r {
        Ok(ev) => Ok(Some(ev)),
        Err(e) if e.code == ErrorCode::InvalidArgs => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Orders the stop of `s` (`why`: the budget that ran out): the gateway refuses everything and
/// aborts open streams, then the session is cancelled, and killed after a grace if it is still
/// there. The time of the order is kept only once both went through.
async fn enforce(app: &App, s: &Session, why: &str) -> Result<(), Refusal> {
    let Some(proof) = app.agents.elevated.lock().unwrap().get(&s.id).copied() else {
        return Err(refuse("a stop needs the session's elevation"));
    };
    let wait = app.agents.config.answer;
    let now = app.clock.unix();
    let stop = |kill| {
        Command::AgentStop(AgentStop {
            session: s.id.clone(),
            kill,
        })
    };
    let answers = match s.gw_stopped_at {
        None => {
            let none = Ceiling {
                tokens: 0,
                usd_micros: 0,
            };
            let limit = Command::AgentLimit(AgentLimit {
                session: s.id.clone(),
                ceiling: none,
            });
            // The cancel goes out even when the limit could not be sent: a session that may still
            // spend must not outlive a failed refusal. A failure of either is tried again.
            let first = stopped(ask(app, &s.runner, limit, wait, Some(proof)).await);
            let then = stopped(ask(app, &s.runner, stop(false), wait, Some(proof)).await);
            let (first, then) = (first?, then?);
            gw::mark_stopped(&app.pool, &s.id, now).await?;
            store::action(
                &app.pool,
                s,
                AuditActor::System,
                "agent.cancelled",
                None,
                gw::stop_details(why),
                "core",
            )
            .await?;
            [first, then]
        }
        Some(at) if now - at >= STOP_GRACE_SECS => [
            stopped(ask(app, &s.runner, stop(true), wait, Some(proof)).await)?,
            None,
        ],
        Some(_) => return Ok(()),
    };
    // What the runner said with its answers (the transcript, the gateway's last reports) is stored.
    for ev in answers.into_iter().flatten() {
        store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
    }
    Ok(())
}

/// Starts the one-shot check of `account`'s key unless one is running already.
fn confirm(app: &App, s: &Session, account: i64) {
    if !app.agents.confirming.lock().unwrap().insert(account) {
        return;
    }
    let (app, s) = (app.clone(), s.clone());
    tokio::spawn(async move {
        if let Err(e) = check(&app, &s, account).await {
            tracing::warn!(account, why = describe(&e), "checking an account's key");
        }
        app.agents.confirming.lock().unwrap().remove(&account);
    });
}

/// One `gateway.test` through the session's runner (it holds a gateway and is in the key's scope).
/// What the provider answers decides the pending signal: it refuses the key again (confirmed: the
/// account is disabled, audited `account.state_set`), it accepts it, or it says something else
/// (rate limit, quota: the key was read, so the failure is cleared), or it cannot be reached (kept,
/// tried a few times, then `inconclusive`). Nothing is ever rotated.
async fn check(app: &App, s: &Session, account: i64) -> Result<(), Refusal> {
    let Some((signal, _)) = gw::pending_auth(&app.pool, account).await? else {
        return Ok(());
    };
    let a = match accounts::get(&app.pool, account).await {
        Ok(a) => a,
        Err(secrets::Error::Refused { .. }) => {
            let why = "the account is gone";
            return Ok(
                gw::decide(&app.pool, account, "inconclusive", why, &app.clock.now()).await?,
            );
        }
        Err(e) => return Err(lift(e)),
    };
    let now = app.clock.now();
    if a.state == "disabled" {
        // Nothing to confirm and nothing tested: it ends without a verdict, not as a confirmation.
        let why = "the account was already disabled";
        return Ok(gw::decide(&app.pool, account, "inconclusive", why, &now).await?);
    }
    let Some(proof) = app.agents.elevated.lock().unwrap().get(&s.id).copied() else {
        return Ok(()); // no elevation to send it under: the next answer tries again
    };
    // Only a runner that is there and offers the gateway is asked, and nothing is leased for one that
    // is not: a lease nobody redeems counts against the runner's cap until it expires, and this runs
    // again on every pass of the supervisor.
    let ready = app
        .hub
        .runners()
        .get(&s.runner)
        .is_some_and(|r| r.online && gateway_refusal(r).is_none());
    if !ready {
        // A live session asks again on its next pass. One that is over has no next pass: its signal
        // ends without a verdict, recorded, rather than waiting for ever on a runner that is gone.
        if !s.live() {
            let why = "no runner was ready to test the key when the session ended";
            gw::decide(&app.pool, account, "inconclusive", why, &now).await?;
        }
        return Ok(());
    }
    // From here a lease is minted: whatever goes wrong counts as a try, so the signal ends
    // `inconclusive` after a few instead of leasing for ever.
    let asked = async {
        let def = providers::get(&app.pool, &a.provider).await.map_err(lift)?;
        let route = route::of(&def, &a.base_url)?;
        let (lease, _) = secrets::lease_to(
            &app.pool,
            &a.secret_name,
            &s.runner,
            None,
            &s.created_by,
            AuditActor::System,
            &now,
            app.clock.unix(),
            Some("gateway"),
        )
        .await?;
        let test = GatewayTest {
            lease,
            provider: a.provider.clone(),
            user_key: route.user_key,
            upstream: upstream_of(&a.base_url, route.wire)?,
        };
        let sent = app
            .hub
            .dispatch_elevated(&s.runner, Command::GatewayTest(test), proof)?;
        let answer = tokio::time::timeout(TEST_WAIT, sent.outcome())
            .await
            .map_err(|_| {
                StreamError::new(ErrorCode::Lost, "the gateway test did not answer in time")
            })??;
        Ok::<_, Refusal>(match answer {
            Body::Result(Reply::GatewayTest(t)) => Some(t.result),
            _ => None,
        })
    }
    .await;
    let result = match asked {
        Ok(result) => result,
        Err(e) => {
            gw::tried(&app.pool, signal, &app.clock.now()).await?;
            return Err(e);
        }
    };
    let now = app.clock.now();
    match result {
        Some(UpstreamStatus::AuthFailed) => {
            let reason = "the provider refused the key (confirmed by a one-shot test)";
            accounts::set_state(
                &app.pool,
                account,
                "disabled",
                Some(reason),
                None,
                "core",
                AuditActor::System,
                &now,
            )
            .await
            .map_err(lift)?;
            gw::decide(&app.pool, account, "confirmed", "", &now).await?;
        }
        Some(UpstreamStatus::Ok | UpstreamStatus::RateLimited | UpstreamStatus::Quota) => {
            gw::decide(&app.pool, account, "cleared", "", &now).await?
        }
        _ => gw::tried(&app.pool, signal, &now).await?,
    }
    Ok(())
}
