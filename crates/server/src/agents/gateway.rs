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

use super::*;
use crate::store::gateway as gw;
use crate::store::{accounts, costs, prices, secrets};

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

/// The wire a built-in provider speaks.
fn wire_of(provider: &str) -> Option<Wire> {
    match provider {
        "anthropic" => Some(Wire::AnthropicMessages),
        "openai" => Some(Wire::OpenaiResponses),
        "google" => Some(Wire::GeminiGenerate),
        _ => None,
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
    if !costs::HARNESSES.contains(&s.harness.as_str())
        || ainkrad_proto::v2::harness_provider(&s.harness) != Some(provider)
    {
        return Err(refuse(
            "a gateway session runs its provider's own harness (claude, codex or agy)",
        ));
    }
    let wire = wire_of(provider).ok_or_else(|| refuse("the account's provider has no wire"))?;
    let upstream = upstream_of(&account.base_url, wire)?;
    // The allowlist is the price book: a model with no price is refused, so dollar ceilings mean something.
    let book: Vec<_> = prices::list(&app.pool)
        .await?
        .into_iter()
        .filter(|p| p.provider == provider)
        .collect();
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
    let ceiling = match gw::reserve(&app.pool, &s.id, id, gw::min_turn_usd(&prices), &now)
        .await
        .map_err(lift)?
    {
        gw::Hold::Granted(c) => c,
        gw::Hold::Denied(why) => return Err(refuse(why)),
    };
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
            user_key: None,
            upstream,
            models,
            prices,
            ceiling,
            rate: RATE,
        }),
        until,
    }))
}

/// What the Core does about a gateway session after each answer it stored: a stop a budget ordered,
/// and the check of an upstream `auth_failed`. Only the logs hear of a failure: the next answer
/// tries again.
pub(super) async fn after(app: &App, s: &Session) {
    let Some(account) = s.gateway_account_id else {
        return;
    };
    if let Some(why) = s.gw_stop.as_deref().filter(|_| s.live())
        && let Err(e) = enforce(app, s, why).await
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
            let first = stopped(ask(app, &s.runner, limit, wait, Some(proof)).await)?;
            let then = stopped(ask(app, &s.runner, stop(false), wait, Some(proof)).await)?;
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
            return Ok(gw::decide(&app.pool, account, "inconclusive", &app.clock.now()).await?);
        }
        Err(e) => return Err(lift(e)),
    };
    let now = app.clock.now();
    if a.state == "disabled" {
        return Ok(gw::decide(&app.pool, account, "confirmed", &now).await?);
    }
    let Some(proof) = app.agents.elevated.lock().unwrap().get(&s.id).copied() else {
        return Ok(()); // no elevation to send it under: the next answer tries again
    };
    let wire = wire_of(&a.provider).ok_or_else(|| refuse("the account's provider has no wire"))?;
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
        user_key: None,
        upstream: upstream_of(&a.base_url, wire)?,
    };
    let sent = app
        .hub
        .dispatch_elevated(&s.runner, Command::GatewayTest(test), proof)?;
    let answer = tokio::time::timeout(TEST_WAIT, sent.outcome())
        .await
        .map_err(|_| {
            StreamError::new(ErrorCode::Lost, "the gateway test did not answer in time")
        })??;
    let result = match answer {
        Body::Result(Reply::GatewayTest(t)) => Some(t.result),
        _ => None,
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
            gw::decide(&app.pool, account, "confirmed", &now).await?;
        }
        Some(UpstreamStatus::Ok | UpstreamStatus::RateLimited | UpstreamStatus::Quota) => {
            gw::decide(&app.pool, account, "cleared", &now).await?
        }
        _ => gw::tried(&app.pool, signal, &now).await?,
    }
    Ok(())
}
