//! A flow's end: the credential becomes ONE connection (or replaces an existing one's), is tested
//! once, and is dropped. Errors are the store's fixed refusals, never a value.

use super::Flow;
use crate::api::App;
use crate::connections::material::Material;
use crate::store::connections::{self, Connection, NewConnection, Who, secret, verdict};
use crate::store::secrets::Error;

fn refused(code: &'static str, message: &str) -> Error {
    Error::Refused {
        code,
        message: message.to_owned(),
    }
}

/// The first `<kind>-<n>` name this workspace does not use.
async fn free_name(app: &App, user: i64, kind: &str) -> Result<String, Error> {
    let have = connections::list(&app.pool, user, Some(kind)).await?;
    (1..100)
        .map(|n| format!("{kind}-{n}"))
        .find(|n| !have.iter().any(|c| &c.name == n))
        .ok_or_else(|| refused("limit_reached", "too many connections of this kind"))
}

/// Stores `material` for `flow` (create, or replace the credential of `flow.reconnect`) and
/// tests it; `fallback_label` is the label when the person gave none. Returns the connection as
/// the test left it.
pub(super) async fn store(
    app: &App,
    flow: &Flow,
    material: &Material,
    fallback_label: &str,
) -> Result<Connection, Error> {
    let Some(sealer) = app.secrets.as_ref() else {
        return Err(refused(
            "secrets_unavailable",
            "this Core has no master key loaded",
        ));
    };
    let now = crate::scheduler::Clock::now(app.clock.as_ref());
    let who = Who {
        workspace: flow.user,
        by_device: &flow.device,
        actor: flow.actor,
        now: &now,
    };
    let reg = app.connections.registry();
    // A GitHub sign-in again must be the same account unless the admin confirmed the change.
    // (Atlassian's check is the site's cloud id, in the flow.) A test that says nothing is no
    // reason to refuse: the test after the write judges the new credential.
    if let (Some(id), "github", false) = (flow.reconnect, flow.kind, flow.confirm_identity_change)
        && let Some(adapter) = reg.get(flow.kind)
    {
        let old = connections::get(&app.pool, flow.user, id).await?.identity;
        if let (Some(old), Ok(now)) = (old, adapter.test(material).await)
            && old != now.subject
        {
            return Err(refused(
                "different_account",
                "that sign-in is a different GitHub account than this connection's; confirm the \
                 change to replace it",
            ));
        }
    }
    let id = {
        // The gate a cancel takes: after it, nothing is made or replaced.
        let _gate = flow.gate.lock().await;
        if flow.cancelled() {
            return Err(refused("cancelled", "the sign-in was cancelled"));
        }
        match flow.reconnect {
            Some(id) => {
                secret::replace(&app.pool, sealer, id, material, who).await?;
                id
            }
            None => {
                let name = match &flow.name {
                    Some(n) => n.clone(),
                    None => free_name(app, flow.user, flow.kind).await?,
                };
                let label = flow.label.as_deref().unwrap_or(fallback_label);
                let new = NewConnection {
                    kind: flow.kind,
                    name: &name,
                    label,
                    auth_method: "oauth",
                };
                connections::create(&app.pool, sealer, reg, &new, material, who)
                    .await?
                    .id
            }
        }
    };
    match flow.kind {
        "jira" => {
            let cx = crate::connections::jira::Ctx {
                pool: &app.pool,
                sealer,
                who,
            };
            app.connections.jira().test_connection(&cx, id).await
        }
        _ => verdict::run_test(&app.pool, sealer, reg, id, who).await,
    }
}

/// Ends `flow` with what [`store`] came to.
pub(super) fn conclude(flow: &Flow, r: Result<Connection, Error>) {
    match r {
        Ok(c) => flow.set(|v| {
            v.step = "connected";
            v.connection = Some(c.id);
            v.identity = c.identity.clone();
        }),
        Err(Error::Refused { code, message }) => flow.fail(code, &message),
        Err(Error::Db(_)) => flow.fail("internal", "Core could not save the connection"),
    }
}
