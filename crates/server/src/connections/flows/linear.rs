//! Sign in with Linear as a flow. `start` makes the authorize address (Core keeps the PKCE
//! verifier inside `Linear`); the Mac app opens it, catches the redirect on its loopback address
//! and hands `code` and `state` to [`callback`]. A sign-in is ONE workspace, so there is no site
//! to choose. The tokens are held only between the exchange and the sealing.
//!
//! A flow that signs in AGAIN for an existing connection must land in the same workspace: team keys
//! (`ENG`) exist in every workspace, so a connection re-signed into another one would silently
//! point its team limits at someone else's teams.

use std::time::Duration;

use zeroize::Zeroizing;

use super::{Flow, Refused, St, Start, StartError, View, blank, finish, new_flow, same};
use crate::api::App;
use crate::connections::linear::{Finished, FlowError, OrgCheck, check_org};
use crate::store::connections;

const LIFE: Duration = Duration::from_secs(600);

pub(super) fn start(app: &App, s: Start<'_>) -> Result<View, StartError> {
    let linear = app.connections.linear();
    // The redirect is the Core's own: the one registered with Linear, never a caller's.
    let Some(redirect) = linear.redirects().into_iter().next() else {
        return Err(StartError::NotConfigured(
            "Sign in with Linear is not set up on this Core yet: an admin enters Ainkrad's \
             Linear app id and secret first",
        ));
    };
    // The cap is asked BEFORE the pending sign-in is made, so a refused start leaves none.
    if !app.conn_flows.room(s.user) {
        return Err(StartError::TooMany);
    }
    let started = linear
        .start(s.user, &redirect, None)
        .map_err(StartError::Linear)?;
    let mut view = blank("linear");
    view.authorize_url = Some(started.authorize_url);
    view.state = Some(started.state.clone());
    let mut flow = new_flow(&s, "linear", LIFE, view, None);
    flow.jira_state = Some(Zeroizing::new(started.state));
    flow.linear = Some(linear.clone());
    // Refused here (a race past `room`): the flow is dropped and takes its pending sign-in along.
    let flow = app.conn_flows.admit(flow)?;
    Ok(flow.view())
}

/// The redirect's `code` and `state`, handed over by the Mac app. A wrong `state` is refused and
/// the flow stays as it was; the first right one spends the flow's wait (a replay is `WrongStep`).
/// What the exchange and the storing come to is the returned view's step.
pub async fn callback(app: &App, flow: &Flow, code: &str, state: &str) -> Result<View, Refused> {
    let own = flow.jira_state.as_ref().ok_or(Refused::WrongStep)?;
    if flow.linear.is_none() {
        return Err(Refused::WrongStep);
    }
    if !same(own, state) {
        return Err(Refused::BadState);
    }
    let mut st = flow.st.lock().await;
    if !matches!(*st, St::Waiting) || flow.step() != "waiting" || flow.view().step != "waiting" {
        return Err(Refused::WrongStep);
    }
    *st = St::Finishing;
    flow.set(|v| v.step = "approved");
    let now = app.clock.now();
    let done = app
        .connections
        .linear()
        .finish(flow.user, state, code, None, &now)
        .await;
    *st = St::Done;
    match done {
        Err(e) => flow.fail(code_of(&e), &e.to_string()),
        Ok(fin) => connect(app, flow, &fin).await,
    }
    Ok(flow.view())
}

fn code_of(e: &FlowError) -> &'static str {
    match e {
        FlowError::NotConfigured => "not_configured",
        FlowError::UnknownState => "unknown_state",
        FlowError::NoRefreshToken => "no_refresh_token",
        FlowError::Exchange(_) => "exchange_failed",
        _ => "bad_request",
    }
}

/// Whether the workspace that signed in is the one connection `id` was made in, by its
/// organization id (the url key can be renamed). A connection with no recorded organization id is
/// `identity_unknown`, which only a confirmed change passes.
async fn check_workspace(
    app: &App,
    flow: &Flow,
    id: i64,
    fin: &Finished,
) -> Result<(), (&'static str, &'static str)> {
    let old = connections::get(&app.pool, flow.user, id)
        .await
        .map_err(|_| {
            (
                "identity_unavailable",
                "Core could not check which workspace that is; try again",
            )
        })?
        .identity;
    match check_org(old.as_deref(), &fin.org) {
        OrgCheck::Same => Ok(()),
        OrgCheck::Different => Err((
            "wrong_workspace",
            "that sign-in is a different Linear workspace than this connection's",
        )),
        OrgCheck::Unknown if flow.confirm_identity_change => Ok(()),
        OrgCheck::Unknown => Err((
            "identity_unknown",
            "this connection has no recorded workspace to compare with; confirm the change to replace it",
        )),
    }
}

async fn connect(app: &App, flow: &Flow, fin: &Finished) {
    if let Some(id) = flow.reconnect
        && let Err((code, why)) = check_workspace(app, flow, id, fin).await
    {
        return flow.fail(code, why);
    }
    let Some(material) = fin.material() else {
        return flow.fail("bad_token", "Linear sent a token Core cannot use");
    };
    let done = finish::store(app, flow, &material, "Linear").await;
    finish::conclude(flow, done);
}
