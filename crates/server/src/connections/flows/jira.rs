//! Sign in with Atlassian as a flow. `start` makes the authorize address (Core keeps the PKCE
//! verifier inside `Jira`); the Mac app opens it, catches the redirect on its loopback address
//! and hands `code` and `state` to [`callback`]. One site is connected at once; several wait in
//! the flow for [`choose`]. The tokens are held only between the exchange and the sealing.

use std::time::Duration;

use super::{Flow, SiteView, St, Start, StartError, View, blank, finish, new_flow, same};
use crate::api::App;
use crate::connections::jira::{Cred, Finished, FlowError, Site, unpack};
use crate::store::connections::secret;

const LIFE: Duration = Duration::from_secs(600);

pub(super) fn start(app: &App, s: Start<'_>) -> Result<View, StartError> {
    let jira = app.connections.jira();
    // The redirect is the Core's own: the one registered with Atlassian, never a caller's.
    let Some(redirect) = jira.redirects().into_iter().next() else {
        return Err(StartError::NotConfigured(
            "Sign in with Atlassian is not set up on this Core yet: an admin enters Ainkrad's \
             Atlassian app id and secret first",
        ));
    };
    let started = jira
        .start(s.user, &redirect, None)
        .map_err(StartError::Jira)?;
    let mut view = blank("jira");
    view.authorize_url = Some(started.authorize_url);
    view.state = Some(started.state.clone());
    let flow = app
        .conn_flows
        .admit(new_flow(&s, "jira", LIFE, view, Some(started.state)))?;
    Ok(flow.view())
}

/// Why a callback or a choice was refused (the flow itself is unchanged).
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The `state` is not the one this flow started with.
    BadState,
    /// The flow is not waiting for this (already handled, over, or not an Atlassian flow).
    WrongStep,
    /// No such site among the choices.
    NoSuchSite,
}

/// The redirect's `code` and `state`, handed over by the Mac app. A wrong `state` is refused and
/// the flow stays as it was; the first right one spends the flow's wait (a replay is `WrongStep`).
/// What the exchange and the storing come to is the returned view's step.
pub async fn callback(app: &App, flow: &Flow, code: &str, state: &str) -> Result<View, Refused> {
    let own = flow.jira_state.as_ref().ok_or(Refused::WrongStep)?;
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
        .jira()
        .finish(flow.user, state, code, None, &now)
        .await;
    match done {
        Err(e) => {
            *st = St::Done;
            flow.fail(code_of(&e), &e.to_string());
        }
        Ok(fin) => settle(app, flow, &mut st, fin).await,
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

/// With the tokens in hand: a flow for an existing connection keeps that connection's site; one
/// site is connected; several wait for the person's choice.
async fn settle(app: &App, flow: &Flow, st: &mut St, fin: Finished) {
    let sites = fin.sites.clone();
    if let Some(id) = flow.reconnect {
        let want = reconnect_site(app, flow, id).await;
        let site = want.and_then(|w| sites.iter().find(|s| s.cloud_id == w));
        *st = St::Done;
        return match site {
            Some(site) => connect(app, flow, &fin, site).await,
            None => flow.fail(
                "wrong_site",
                "that account does not reach this connection's site",
            ),
        };
    }
    match sites.as_slice() {
        [] => {
            *st = St::Done;
            flow.fail("no_site", "that account has no Jira site Core can use");
        }
        [site] => {
            *st = St::Done;
            connect(app, flow, &fin, site).await;
        }
        many => {
            let list = many
                .iter()
                .map(|s| SiteView {
                    id: s.cloud_id.clone(),
                    name: s.name.clone(),
                    url: s.url.clone(),
                })
                .collect();
            flow.set(|v| {
                v.step = "choose_site";
                v.sites = list;
            });
            *st = St::Choose(fin);
        }
    }
}

/// The cloud id of the site connection `id` already has.
async fn reconnect_site(app: &App, flow: &Flow, id: i64) -> Option<String> {
    let sealer = app.secrets.as_ref()?;
    let (m, _) = secret::open(&app.pool, sealer, flow.user, id).await.ok()?;
    match unpack(&m)? {
        Cred::Oauth { cloud_id, .. } => Some(cloud_id),
        Cred::Basic { .. } => None,
    }
}

async fn connect(app: &App, flow: &Flow, fin: &Finished, site: &Site) {
    let Some(material) = fin.material_for(site) else {
        return flow.fail("bad_site", "Atlassian sent a site Core cannot use");
    };
    let label = match site.name.trim().is_empty() {
        true => "Jira",
        false => site.name.as_str(),
    };
    let done = finish::store(app, flow, &material, label).await;
    finish::conclude(flow, done);
}

/// The person's choice among the sites of a waiting flow (by cloud id). One connection is made
/// and the tokens are dropped.
pub async fn choose(app: &App, flow: &Flow, site_id: &str) -> Result<View, Refused> {
    let mut st = flow.st.lock().await;
    let St::Choose(fin) = &*st else {
        return Err(Refused::WrongStep);
    };
    if flow.view().step != "choose_site" {
        return Err(Refused::WrongStep);
    }
    let Some(site) = fin.sites.iter().find(|s| s.cloud_id == site_id).cloned() else {
        return Err(Refused::NoSuchSite);
    };
    let St::Choose(fin) = std::mem::replace(&mut *st, St::Done) else {
        return Err(Refused::WrongStep);
    };
    flow.set(|v| v.step = "approved");
    connect(app, flow, &fin, &site).await;
    Ok(flow.view())
}
