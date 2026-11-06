//! A session's scheduling over the API (design `2026-11-06-core-account-scheduler` §4.5, §13, S7):
//! the chain and account a response shows, and the create of a session that names a chain or an
//! agent. Both live apart from the routes so `agents.rs` stays as it is.
//!
//! - **Create.** Naming `chain` or `agent` needs `admin` (attaching account secrets stays
//!   admin-only, KAN-433). With a chain the request names no harness and no model (the allocator's
//!   entry sets them) and no `acct.*` secret; the store refuses each (400) and leaves no row. Every
//!   refusal here comes before the runner is asked.
//! - **Show.** Nothing here is a key, a secret's name or an upstream's text: ids, entry names,
//!   times and fixed codes.

use axum::http::StatusCode;
use serde::Serialize;
use utoipa::ToSchema;

use super::super::types::{Timestamp, ts};
use super::super::{ApiError, BY, Caller};
use super::{AgentSession, Session};
use crate::agents::{self, Invalid};
use crate::api::App;
use crate::scheduler::iso_of_unix;
use crate::store::agents::NewSession;
use crate::store::chains as ch;
use crate::store::secrets::ACCOUNT_PREFIX;
use ainkrad_proto::v2::{AGENT_DRIVER, ErrorCode, StreamError};

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

/// `s` with its chain, account and wait.
pub(super) async fn present(app: &App, s: Session) -> Result<AgentSession, ApiError> {
    let sched = ch::sched_of(&app.pool, &s.id).await?.unwrap_or_default();
    let mut out = AgentSession::from(s);
    out.agent = sched.agent;
    out.chain_id = sched.chain_id;
    out.chain = sched.chain.map(|c| c.into_iter().map(Into::into).collect());
    out.chain_pos = sched.chain_pos;
    out.account = sched.account;
    out.waiting = sched.waiting.map(|w| AgentWaiting {
        since: w.since.map(|s| ts(&iso_of_unix(s))),
        until: ts(&w.until),
        why: w.why,
    });
    out.repicked = (sched.repicked > 0).then_some(sched.repicked);
    out.upstream_class = sched.upstream_class;
    Ok(out)
}

fn forbidden(why: &'static str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "forbidden_scope", why)
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
    let resolved = {
        let mut conn = app.pool.acquire().await?;
        ch::resolve_for(&mut conn, user, chain, agent).await?
    };
    // The store refuses these too and leaves no row; said here, they come before the runner is asked.
    if resolved.is_some() {
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
    }
    // The entry the allocator picks sets the harness, so a request with a chain has none: its
    // other checks run against a placeholder.
    let probe = NewSession {
        harness: if resolved.is_some() && new.harness.is_empty() {
            "claude"
        } else {
            new.harness
        },
        ..*new
    };
    agents::validate_new(&probe, admin).map_err(|e| match e {
        Invalid::Bad(why) => ApiError::bad_request(why),
        Invalid::Forbidden(why) => forbidden(why),
    })?;
    match (resolved.is_some(), new.harness.is_empty()) {
        // The allocator places each entry on the runner (`serves`); here it only has to be there.
        (true, true) => {
            let live = app.hub.runners();
            let offered = live
                .get(new.runner)
                .filter(|r| r.online)
                .map(|r| r.drivers.iter().any(|d| d.name == AGENT_DRIVER));
            let refused = match offered {
                Some(true) => None,
                Some(false) => Some((
                    ErrorCode::UnsupportedCommand,
                    "the runner offers no agent sessions",
                )),
                None => Some((ErrorCode::Offline, "the runner is not connected")),
            };
            if let Some((code, why)) = refused {
                return Err(super::super::runners::failed(&StreamError::new(code, why)));
            }
        }
        // A named harness with a chain is refused by the store (400); without a chain it is placed.
        _ => {
            agents::admit_holding(app, new.runner, new.harness, new.policy, new.secrets).await?;
        }
    }
    let req = ch::Request {
        user_id: user,
        chain,
        agent,
    };
    let s = ch::create_session(&app.pool, new, None, None, req, BY, &app.clock.now()).await?;
    Ok(s)
}
