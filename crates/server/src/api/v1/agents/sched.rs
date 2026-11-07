//! A session's scheduling over the API (design `2026-11-06-core-account-scheduler` §4.5, §13, S7):
//! what a response shows of its chain, account and wait, and the create of a session that names a
//! chain or an agent. Both live apart from the routes so `agents.rs` stays as it is.
//!
//! - **Show.** Nothing here is a key, a secret's name or an upstream's text. A session answers
//!   only to the user who owns it (another user's is no such session), and the chain it walks,
//!   its snapshot, the agent and the account it holds are shown to `admin` devices only.
//! - **Create.** Naming `chain` or `agent` needs `admin` (attaching account secrets stays
//!   admin-only, KAN-433). With a chain the request names no harness and no model (the allocator's
//!   entry sets them) and no `acct.*` secret, and it passes the checks a plain create does for
//!   EVERY entry's harness (the shape, the secrets, the policy) and is placed by at least one entry
//!   (the runner online, with a slot), all before a row exists: what a plain create refuses, a chain
//!   create refuses, with no row, no pick and no hold.

use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;

use super::super::types::{Timestamp, ts};
use super::super::{ApiError, ApiResult, BY, Caller};
use super::{AgentSession, Session, one};
use crate::agents::{self, Invalid, Refusal};
use crate::api::App;
use crate::scheduler::iso_of_unix;
use crate::store::agents::{NewSession, SessionSecret};
use crate::store::chains as ch;
use crate::store::secrets::ACCOUNT_PREFIX;

/// Why a chain session has not started: it waits for an account to come back.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentWaiting {
    /// Its first wait; it waits `scheduler.wait_max_secs` in all.
    pub since: Option<Timestamp>,
    /// When the earliest account may be back.
    pub until: Timestamp,
    /// A fixed phrase: every account the chain can use is cooling, limited or at its cap.
    pub why: String,
}

/// Who is asking: their user, and whether they hold `admin`.
struct Viewer {
    user: i64,
    admin: bool,
}

async fn viewer(app: &App, me: &Caller) -> Result<Viewer, ApiError> {
    Ok(Viewer {
        user: ch::user_of(&app.pool, &me.device.id).await?,
        admin: me.device.scopes.iter().any(|s| s == "admin"),
    })
}

/// `s` with its chain, account and wait, for `v`; `None` when it is another user's.
async fn present(app: &App, v: &Viewer, s: Session) -> Result<Option<AgentSession>, ApiError> {
    let sched = ch::sched_of(&app.pool, &s.id).await?.unwrap_or_default();
    if sched.user != v.user {
        return Ok(None);
    }
    let mut out = AgentSession::from(s);
    if v.admin {
        out.agent = sched.agent;
        out.chain_id = sched.chain_id;
        out.chain = sched.chain.map(|c| c.into_iter().map(Into::into).collect());
        out.account = sched.account;
    }
    if v.admin {
        out.failover_class = sched.failover_class;
        out.skip_pools = Some(sched.skip_pools);
    }
    out.run = Some(sched.run);
    out.attempt = Some(sched.attempt);
    out.failover_of = sched.failover_of;
    out.failed_over_to = sched.failed_over_to;
    out.chain_pos = sched.chain_pos;
    out.waiting = sched.waiting.map(|w| AgentWaiting {
        since: w.since.map(|s| ts(&iso_of_unix(s))),
        until: ts(&w.until),
        why: w.why,
    });
    out.repicked = (sched.repicked > 0).then_some(sched.repicked);
    out.upstream_class = sched.upstream_class;
    Ok(Some(out))
}

/// `s` is the caller's user's, else no such session (the same answer as a missing one).
pub(super) async fn of_user(app: &App, me: &Caller, s: &Session) -> Result<(), ApiError> {
    let user = ch::user_of(&app.pool, &me.device.id).await?;
    match ch::sched_of(&app.pool, &s.id)
        .await?
        .is_some_and(|c| c.user == user)
    {
        true => Ok(()),
        false => Err(ApiError::not_found("no such agent session")),
    }
}

/// The session `id` as the API shows it to the caller.
pub(super) async fn shown(app: &App, me: &Caller, id: &str) -> ApiResult<AgentSession> {
    let v = viewer(app, me).await?;
    match present(app, &v, one(app, me, id).await?).await? {
        Some(s) => Ok(Json(s)),
        None => Err(ApiError::not_found("no such agent session")),
    }
}

/// A page of sessions, newest first: all of them, or only the attempts of `run`.
pub(super) async fn page(
    app: &App,
    before: Option<i64>,
    limit: u32,
    run: Option<&str>,
) -> Result<Vec<Session>, ApiError> {
    let Some(run) = run else {
        return Ok(crate::store::agents::list(&app.pool, before, limit).await?);
    };
    let mut out = Vec::new();
    for id in ch::ids_of_run(&app.pool, run, before, limit).await? {
        out.extend(crate::store::agents::get(&app.pool, &id).await?);
    }
    Ok(out)
}

/// The caller's own sessions among `all`, as shown.
pub(super) async fn listed(
    app: &App,
    me: &Caller,
    all: Vec<Session>,
) -> Result<Vec<AgentSession>, ApiError> {
    let v = viewer(app, me).await?;
    let mut out = Vec::with_capacity(all.len());
    for s in all {
        out.extend(present(app, &v, s).await?);
    }
    Ok(out)
}

fn forbidden(why: &'static str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "forbidden_scope", why)
}

fn invalid(e: Invalid) -> ApiError {
    match e {
        Invalid::Bad(why) => ApiError::bad_request(why),
        Invalid::Forbidden(why) => forbidden(why),
    }
}

/// Creates the session of a request that names a `chain` or an `agent` (design §4.5). A request
/// whose agent has no binding and no default chain is a plain one: its own harness is required.
pub(super) async fn create_named(
    app: &App,
    me: &Caller,
    new: &NewSession<'_>,
    admin: bool,
    chain: Option<i64>,
    agent: Option<&str>,
) -> Result<Session, ApiError> {
    if !admin {
        return Err(forbidden(
            "naming a chain or an agent requires the admin scope",
        ));
    }
    if agent.is_some_and(|a| !crate::store::pools::valid_agent(a)) {
        return Err(ApiError::bad_request(
            "an agent id is 1 to 64 of [A-Za-z0-9._:-]",
        ));
    }
    let user = ch::user_of(&app.pool, &me.device.id).await?;
    let entries = {
        let mut conn = app.pool.acquire().await?;
        match ch::resolve_for(&mut conn, user, chain, agent).await? {
            Some(id) => Some(ch::load(&mut conn, id).await?),
            None => None,
        }
    };
    match &entries {
        // No chain: a plain create, checked and placed as one.
        None => {
            agents::validate_new(new, admin).map_err(invalid)?;
            agents::admit_holding(app, new.runner, new.harness, new.policy, new.secrets).await?;
        }
        Some(entries) => {
            // The store refuses these too and leaves no row; said here, they come first.
            if !new.harness.is_empty() || new.model.is_some() {
                return Err(ApiError::bad_request(
                    "a session with a chain names no harness or model",
                ));
            }
            if new
                .secrets
                .iter()
                .any(|s| s.name.starts_with(ACCOUNT_PREFIX))
            {
                return Err(ApiError::bad_request(
                    "a session with a chain names no account secret",
                ));
            }
            // Whichever entry the allocator picks sets the harness and adds its account's secret, so
            // the request must pass a plain create's checks as each entry would leave it: the
            // account secret beside the request's own (a proxy or base URL variable, the sandbox
            // the policy needs, the subscription rules).
            for e in entries {
                let def = crate::store::providers::get(&app.pool, &e.provider).await?;
                let mut secrets = new.secrets.to_vec();
                secrets.push(SessionSecret {
                    name: format!("{ACCOUNT_PREFIX}{}.1", e.provider),
                    var: def.auth_var,
                });
                let probe = NewSession {
                    harness: &e.harness,
                    secrets: &secrets,
                    ..*new
                };
                agents::validate_new(&probe, admin).map_err(invalid)?;
            }
            // And at least one entry has to be placeable on the runner now (online, a slot); the
            // allocator places each entry on the pick (`serves`) and skips the others.
            let mut first: Option<Refusal> = None;
            let mut placed = false;
            for e in entries {
                match agents::admit_holding(app, new.runner, &e.harness, new.policy, new.secrets)
                    .await
                {
                    Ok(()) => {
                        placed = true;
                        break;
                    }
                    Err(r) => {
                        first.get_or_insert(r);
                    }
                }
            }
            if let Some(r) = first.filter(|_| !placed) {
                return Err(r.into());
            }
        }
    }
    let req = ch::Request {
        user_id: user,
        chain,
        agent,
    };
    Ok(ch::create_session(&app.pool, new, None, None, req, BY, &app.clock.now()).await?)
}
