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

/// The home key the session starts in, or `None` for a session with no bound account.
pub(super) async fn home(app: &App, s: &Session) -> Result<Option<String>, Refusal> {
    let Some(secret) = s.secrets.iter().find(|x| is_bound(x)) else {
        return Ok(None);
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
        return Err(refuse("the account holds no login on any runner"));
    };
    if bound.runner != s.runner {
        return Err(refuse(
            "the account's login is on another runner: it never moves",
        ));
    }
    Ok(Some(bound.home))
}
