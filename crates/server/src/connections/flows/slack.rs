//! Add to Slack as a flow. `start` makes the authorize address (Core keeps nothing secret but the
//! `state`: Slack has no PKCE); the person approves in the browser, whatever catches the `https`
//! redirect hands `code` and `state` to [`callback`]. A sign-in is ONE workspace, so there is no
//! site to choose. The tokens are held only between the exchange and the sealing.
//!
//! A flow that signs in AGAIN for an existing connection must land in the same workspace, told by
//! its stable id (`T…`, never the name): channel IDs and a connection's limits belong to one
//! workspace. A different workspace never passes; a connection with no recorded workspace is refused
//! unless the admin confirmed the change (`confirm_identity_change`).

use std::time::Duration;

use zeroize::Zeroizing;

use super::{Flow, Refused, St, Start, StartError, View, blank, finish, new_flow, same};
use crate::api::App;
use crate::connections::slack::{Finished, FlowError, TeamCheck, check_team, workspace_of};
use crate::store::connections;
use crate::store::settings::value_in;
use ainkrad_core::settings::{Key, Scope};

const LIFE: Duration = Duration::from_secs(600);

pub(super) async fn start(app: &App, s: Start<'_>) -> Result<View, StartError> {
    let slack = app.connections.slack();
    // The redirect is the Core's own: the one registered with Slack, never a caller's.
    let Some(redirect) = slack.redirects().into_iter().next() else {
        return Err(StartError::NotConfigured(
            "Add to Slack is not set up on this Core yet: an admin enters Ainkrad's Slack app id, \
             secret and https redirect address, and the https redirect page must be ready (it needs an \
             https redirect page)",
        ));
    };
    // A Slack app with token rotation hands out tokens Core can store only at `secrets.mode` 2:
    // refused here, before a sign-in code is spent on an install that could not be kept.
    if slack.rotation() {
        let store_err = |e: sqlx::Error| StartError::Store(e.into());
        let mut conn = app.pool.acquire().await.map_err(store_err)?;
        let mode = value_in(&mut conn, Key::SecretsMode, Scope::Server).await;
        if mode.map_err(store_err)? < 2 {
            return Err(StartError::Slack(FlowError::NeedsMode2));
        }
    }
    // The cap is asked BEFORE the pending sign-in is made, so a refused start leaves none.
    if !app.conn_flows.room(s.user) {
        return Err(StartError::TooMany);
    }
    // A re-sign-in hints the workspace it must land in; the finish checks it again.
    let hint = match s.reconnect {
        Some(id) => connections::get(&app.pool, s.user, id)
            .await?
            .identity
            .as_deref()
            .and_then(workspace_of)
            .map(str::to_owned),
        None => None,
    };
    let started = slack
        .start(s.user, &redirect, hint.as_deref())
        .map_err(StartError::Slack)?;
    let mut view = blank("slack");
    view.authorize_url = Some(started.authorize_url);
    view.state = Some(started.state.clone());
    let mut flow = new_flow(&s, "slack", LIFE, view, None);
    flow.jira_state = Some(Zeroizing::new(started.state));
    flow.slack = Some(slack.clone());
    // Refused here (a race past `room`): the flow is dropped and takes its pending sign-in along.
    let flow = app.conn_flows.admit(flow)?;
    Ok(flow.view())
}

/// The redirect's `code` and `state`. A wrong `state` is refused and the flow stays as it was;
/// the first right one spends the flow's wait (a replay is `WrongStep`). What the exchange and
/// the storing come to is the returned view's step.
pub async fn callback(app: &App, flow: &Flow, code: &str, state: &str) -> Result<View, Refused> {
    let own = flow.jira_state.as_ref().ok_or(Refused::WrongStep)?;
    if flow.slack.is_none() {
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
        .slack()
        .finish(flow.user, state, code, &now)
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
        FlowError::NotABotInstall => "not_a_bot_install",
        FlowError::Exchange(_) => "exchange_failed",
        _ => "bad_request",
    }
}

/// Whether the workspace that signed in is the one connection `id` was made in, by its stable id
/// (the identity is `<bot user id> in <workspace id>`; the name can be renamed). A different
/// workspace never passes. A connection with no recorded workspace is `identity_unknown`, which
/// only a confirmed change passes.
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
    match check_team(old.as_deref(), &fin.workspace) {
        TeamCheck::Same => Ok(()),
        TeamCheck::Different => Err((
            "wrong_workspace",
            "that sign-in is a different Slack workspace than this connection's",
        )),
        TeamCheck::Unknown if flow.confirm_identity_change => Ok(()),
        TeamCheck::Unknown => Err((
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
        return flow.fail("bad_token", "Slack sent a token Core cannot use");
    };
    let done = finish::store(app, flow, &material, "Slack").await;
    finish::conclude(flow, done);
}
