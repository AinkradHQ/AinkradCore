//! Sign in with Microsoft as a flow: the device code flow. `start` asks Entra for a code and hands
//! the screen what to show (the code and Microsoft's own page); a task owns the device code and
//! polls on Microsoft's interval until the person approves, declines or the code ends, then stores
//! the tokens. The task stops when the flow is cancelled, when it ends, or when the Core stops.
//!
//! A flow that signs in AGAIN for an existing connection must land in the same tenant, told by its
//! stable id (`tid`, never a name): team and channel ids and a connection's limits belong to one
//! tenant. The device code is requested AT the connection's tenant, and the finished grant is
//! checked again. A different tenant never passes; a connection with no recorded tenant is refused
//! unless the admin confirmed the change (`confirm_identity_change`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Flow, Start, StartError, View, blank, finish, new_flow};
use crate::api::App;
use crate::connections::teams::{DeviceError, Granted, Pending, Step, TenantCheck};
use crate::connections::teams::{check_tenant, tenant_of};
use crate::store::connections;

pub(super) async fn start(app: &App, s: Start<'_>) -> Result<View, StartError> {
    let teams = app.connections.teams();
    if !teams.app_configured() {
        return Err(StartError::NotConfigured(
            "Sign in with Microsoft is not set up on this Core yet: an admin enters Ainkrad's \
             Microsoft app (client id) first",
        ));
    }
    // The cap is asked BEFORE the device code is requested, so a refused start leaves none.
    if !app.conn_flows.room(s.user) {
        return Err(StartError::TooMany);
    }
    // A re-sign-in asks for its code at the tenant the connection belongs to.
    let hint = match s.reconnect {
        Some(id) => connections::get(&app.pool, s.user, id)
            .await?
            .identity
            .as_deref()
            .and_then(tenant_of)
            .map(str::to_owned),
        None => None,
    };
    let (prompt, pending) = teams
        .device_start(hint.as_deref(), Instant::now())
        .await
        .map_err(StartError::Teams)?;
    let mut view = blank("teams");
    view.prompt = Some(prompt.clone());
    let life = Duration::from_secs(prompt.expires_in);
    let flow = app
        .conn_flows
        .admit(new_flow(&s, "teams", life, view, None))?;
    let first = flow.view();
    tokio::spawn(run(app.clone(), flow, pending));
    Ok(first)
}

async fn run(app: App, flow: Arc<Flow>, pending: Pending) {
    let mut closing = app.closing.subscribe();
    tokio::select! {
        () = poll(&app, &flow, pending) => {}
        () = crate::api::stopping(&mut closing) => {}
    }
}

async fn poll(app: &App, flow: &Arc<Flow>, mut pending: Pending) {
    let teams = app.connections.teams();
    loop {
        if flow.cancelled() {
            return;
        }
        let now = app.clock.now();
        match pending.poll(teams, Instant::now(), &now).await {
            Step::Wait { secs } => tokio::time::sleep(Duration::from_secs(secs.clamp(1, 60))).await,
            Step::Retry => tokio::time::sleep(Duration::from_secs(5)).await,
            Step::Granted(g) => {
                if flow.cancelled() {
                    return;
                }
                flow.set(|v| v.step = "approved");
                return connect(app, flow, &g).await;
            }
            Step::Expired => return flow.set(|v| v.step = "expired"),
            Step::Denied => return flow.set(|v| v.step = "denied"),
            Step::Closed => return,
            Step::Failed(e) => return flow.fail(e.code(), &message(&e)),
        }
    }
}

fn message(e: &DeviceError) -> String {
    e.to_string()
}

/// Whether the tenant that signed in is the one connection `id` was made in, by its stable id. A
/// different tenant never passes. A connection with no recorded tenant is `identity_unknown`,
/// which only a confirmed change passes.
async fn check_same_tenant(
    app: &App,
    flow: &Flow,
    id: i64,
    g: &Granted,
) -> Result<(), (&'static str, &'static str)> {
    let old = connections::get(&app.pool, flow.user, id)
        .await
        .map_err(|_| {
            (
                "identity_unavailable",
                "Core could not check which tenant that is; try again",
            )
        })?
        .identity;
    match check_tenant(old.as_deref(), &g.tenant) {
        TenantCheck::Same => Ok(()),
        TenantCheck::Different => Err((
            "wrong_tenant",
            "that sign-in is a different Microsoft tenant than this connection's",
        )),
        TenantCheck::Unknown if flow.confirm_identity_change => Ok(()),
        TenantCheck::Unknown => Err((
            "identity_unknown",
            "this connection has no recorded tenant to compare with; confirm the change to replace it",
        )),
    }
}

async fn connect(app: &App, flow: &Flow, g: &Granted) {
    if let Some(id) = flow.reconnect
        && let Err((code, why)) = check_same_tenant(app, flow, id, g).await
    {
        return flow.fail(code, why);
    }
    let done = finish::store(app, flow, &g.material, "Microsoft Teams").await;
    finish::conclude(flow, done);
}
