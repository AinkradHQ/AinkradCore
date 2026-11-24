//! A runner-bound subscription account in a session (E7-4, E7-5, E7-5b). Its login lives in a home
//! on one runner and never travels: nothing is leased, no env variable carries it, and the gateway
//! does not serve it. The session's start only names the home (`AgentStart::home`); the runner reads
//! its own files. What is checked here, live, before that: the account is active, is the provider's
//! own harness, is bound, and is bound to the session's runner.

use super::*;
use crate::store::{accounts, providers, secrets};

fn refuse(why: impl Into<String>) -> Refusal {
    Refusal::Runner(StreamError::new(ErrorCode::InvalidArgs, why))
}

/// Whether `s` is a runner-bound account's secret.
pub(super) fn is_bound(s: &store::SessionSecret) -> bool {
    ainkrad_proto::v2::is_bound_secret(&s.name)
}

/// Where a session's plan login comes from.
pub(super) enum Home {
    /// No runner-bound or lent plan account.
    None,
    /// The home key on the session's runner, where the login lives (runner-bound).
    Bound(String),
    /// A lease on the login the Core holds, and its end (unix seconds).
    Lent(String, i64),
}

/// The home the session starts in: its bound home, or a lease on the Core-held login.
pub(super) async fn home(app: &App, s: &Session) -> Result<Home, Refusal> {
    let Some(secret) = s.secrets.iter().find(|x| is_bound(x)) else {
        return Ok(Home::None);
    };
    let Some((provider, id)) = crate::store::gateway::account_secret(&secret.name) else {
        return Err(refuse("the session's account does not exist"));
    };
    crate::store::health::recover(&app.pool, id, &app.clock.now()).await?;
    let account = match accounts::get(&app.pool, id).await {
        Err(secrets::Error::Refused {
            code: "not_found", ..
        }) => return Err(refuse("the subscription account no longer exists")),
        Err(secrets::Error::Refused { message, .. }) => return Err(refuse(message)),
        Err(secrets::Error::Db(e)) => return Err(Refusal::Db(e)),
        Ok(a) => a,
    };
    if account.secret_name != secret.name || account.provider != provider {
        return Err(refuse(
            "the session's account is not the one its secret names",
        ));
    }
    if !crate::store::health::startable(
        &account.state,
        account.state_reason.as_deref(),
        s.state == "interrupted",
    ) {
        return Err(refuse(format!(
            "the subscription account is {}, not active",
            account.state
        )));
    }
    let def = match providers::get(&app.pool, provider).await {
        Ok(d) => d,
        Err(secrets::Error::Db(e)) => return Err(Refusal::Db(e)),
        Err(_) => return Err(refuse("the account's provider is gone")),
    };
    if def.harness != s.harness || ainkrad_proto::v2::bound_harness(provider) != Some(&*s.harness) {
        return Err(refuse(
            "a runner-bound account goes only to its own provider's harness",
        ));
    }
    let mut conn = app.pool.acquire().await?;
    let Some(bound) = crate::store::bound::of(&mut conn, id).await? else {
        drop(conn);
        return lent(app, s, &secret.name, provider).await;
    };
    if bound.runner != s.runner {
        return Err(refuse(
            "the account's login is on another runner: it never moves",
        ));
    }
    Ok(Home::Bound(bound.home))
}

/// A lease on the Core-held login of `name` to the session's runner, which must say it takes one.
async fn lent(app: &App, s: &Session, name: &str, provider: &str) -> Result<Home, Refusal> {
    if !ainkrad_proto::v2::lendable(provider) {
        return Err(refuse("the account holds no login on any runner"));
    }
    let lists = app.hub.runners().get(&s.runner).is_some_and(|r| {
        r.drivers
            .iter()
            .filter(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER)
            .any(|d| {
                d.commands
                    .iter()
                    .any(|c| c == ainkrad_proto::v2::CAP_LENT_HOME)
            })
    });
    if !lists {
        return Err(refuse(
            "a session of an account held by the Core needs a runner that takes a lent login \
             (the lent-home command): update the runner",
        ));
    }
    let (lease, until) = secrets::lease_to(
        &app.pool,
        name,
        &s.runner,
        None,
        &s.created_by,
        AuditActor::System,
        &app.clock.now(),
        app.clock.unix(),
        Some("home"),
    )
    .await
    .map_err(|e| match e {
        secrets::Error::Refused { message, .. } => refuse(message),
        secrets::Error::Db(e) => Refusal::Db(e),
    })?;
    // Which version this session was lent: its write-back is taken only against that one, once.
    let Some((_, id)) = crate::store::gateway::account_secret(name) else {
        return Err(refuse("the session's account does not exist"));
    };
    crate::store::bound::lent(&app.pool, &s.id, id, name, &app.clock.now()).await?;
    Ok(Home::Lent(lease, until))
}
