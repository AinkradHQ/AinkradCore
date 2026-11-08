//! Sign-in flows over the API (C5; `crate::connections::flows`). Starting one is `admin` and
//! destructive (it ends in a stored credential, like an account login); polling, handing over
//! the Atlassian redirect, choosing a site and cancelling are `admin` only and need no step-up:
//! they act on the caller's OWN flow, which belongs to the user and the device that started it
//! (anyone else's id is 404). The redirect's `code` and `state` travel in a POST body, never in
//! a URL (a refused request's path is audited).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;

use super::types::*;
use super::{parse, workspace};
use crate::api::App;
use crate::api::v1::accounts::AccountsDeleted;
use crate::api::v1::{ApiError, ApiResult, BY, Caller};
use crate::auth::crypto::is_id;
use crate::connections::flows::{self as engine, Flow, Refused, Start, StartError, View};

fn shown(v: View) -> ConnectionFlow {
    let (code, message) = v.error.unzip();
    ConnectionFlow {
        id: v.id,
        kind: v.kind.to_owned(),
        step: v.step.to_owned(),
        expires_in_secs: i64::try_from(v.expires_in_secs).unwrap_or(0),
        user_code: v.prompt.as_ref().map(|p| p.user_code.clone()),
        verification_uri: v.prompt.as_ref().map(|p| p.verification_uri.clone()),
        interval: v
            .prompt
            .as_ref()
            .map(|p| i64::try_from(p.interval).unwrap_or(5)),
        authorize_url: v.authorize_url,
        state: v.state,
        sites: v
            .sites
            .into_iter()
            .map(|s| ConnectionFlowSite {
                id: s.id,
                name: s.name,
                url: s.url,
            })
            .collect(),
        connection: v.connection,
        identity: v.identity,
        error_code: code,
        error_message: message,
    }
}

fn refused(r: Refused) -> ApiError {
    match r {
        Refused::BadState => {
            ApiError::bad_request("that redirect does not belong to this sign-in; start again")
        }
        Refused::WrongStep => ApiError::conflict("this sign-in is not waiting for that"),
        Refused::NoSuchSite => ApiError::bad_request("that site is not one of the choices"),
    }
}

fn start_error(e: StartError) -> ApiError {
    use crate::connections::jira::FlowError;
    use crate::connections::linear::FlowError as LinearFlowError;
    match e {
        StartError::NotConfigured(why) => {
            ApiError::new(StatusCode::CONFLICT, "not_configured", why)
        }
        StartError::TooMany | StartError::Jira(FlowError::TooManyFlows) => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_flows",
            "too many sign-ins are waiting; finish or cancel one",
        ),
        StartError::Jira(FlowError::NotConfigured) => ApiError::new(
            StatusCode::CONFLICT,
            "not_configured",
            "Sign in with Atlassian is not set up on this Core yet",
        ),
        StartError::Linear(LinearFlowError::TooManyFlows) => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_flows",
            "too many sign-ins are waiting; finish or cancel one",
        ),
        StartError::Linear(LinearFlowError::NotConfigured) => ApiError::new(
            StatusCode::CONFLICT,
            "not_configured",
            "Sign in with Linear is not set up on this Core yet",
        ),
        StartError::Linear(_) | StartError::Jira(_) => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the sign-in could not be started",
        ),
        StartError::Device(e) => {
            ApiError::new(StatusCode::BAD_GATEWAY, "upstream_failed", e.to_string())
        }
        StartError::Store(e) => e.into(),
    }
}

/// The caller's own flow `id`: the same user AND device, else no such flow.
fn mine(app: &App, me: &Caller, user: i64, id: &str) -> Result<std::sync::Arc<Flow>, ApiError> {
    let found = match is_id(id, "cf_") {
        true => app.conn_flows.get(user, &me.device.id, id),
        false => None,
    };
    found.ok_or_else(|| ApiError::not_found("no such sign-in"))
}

#[utoipa::path(post, path = "/api/v1/connections/start", operation_id = "startConnectionFlow",
    tag = "connections", request_body = StartConnectionFlow,
    responses((status = 200, description = "A sign-in begun, held in Core: GitHub's device flow \
        returns `user_code`, `verification_uri` and `interval` (Core polls GitHub itself, so the \
        person can close the window); Atlassian returns `authorize_url` (the Mac app opens it, \
        catches the redirect on 127.0.0.1 and posts `code` and `state` to \
        `connectionFlowCallback`) and `state`. With `connection`, the credential of that \
        connection is replaced (CN5, sign in again); a GitHub sign-in as another account ends \
        `failed` with `different_account` unless `confirm_identity_change` is true. A flow ends in ONE connection. 409 \
        `not_configured` while Ainkrad's app for the kind is not set up (see \
        `listConnectionKinds`), 429 `too_many_flows` (4 waiting per user), 502 when GitHub could \
        not give a code, 400 for a bad name, label or kind, 404 for another workspace's \
        connection", body = ConnectionFlow)))]
pub async fn start(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<ConnectionFlow> {
    let b: StartConnectionFlow = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let Some(d) = app
        .connections
        .registry()
        .get(&b.kind)
        .map(|a| a.descriptor())
    else {
        return Err(ApiError::bad_request("no such kind of connection"));
    };
    if b.name
        .as_deref()
        .is_some_and(|n| !crate::store::connections::valid_name(n))
        || b.label
            .as_deref()
            .is_some_and(|l| !crate::store::connections::valid_text(l, 80))
    {
        return Err(ApiError::bad_request("that name or label is not valid"));
    }
    // A name that is taken is said now, not after the person has signed in.
    if let (Some(n), None) = (&b.name, b.connection) {
        let have = crate::store::connections::list(&app.pool, user, Some(d.kind)).await?;
        if have.iter().any(|c| &c.name == n) {
            return Err(ApiError::conflict(
                "a connection of that name exists for this kind",
            ));
        }
    }
    if let Some(id) = b.connection {
        let c = crate::store::connections::get(&app.pool, user, id).await?;
        if c.kind != d.kind || c.auth_method != "oauth" {
            return Err(ApiError::bad_request(
                "only a connection made by signing in is signed in again",
            ));
        }
    }
    let view = engine::start(
        &app,
        Start {
            user,
            device: &me.device.id,
            actor: BY,
            kind: d.kind,
            reconnect: b.connection,
            name: b.name.as_deref(),
            label: b.label.as_deref(),
            confirm_identity_change: b.confirm_identity_change == Some(true),
        },
    )
    .await
    .map_err(start_error)?;
    Ok(Json(shown(view)))
}

#[utoipa::path(get, path = "/api/v1/connections/flows/{id}", operation_id = "getConnectionFlow",
    tag = "connections", params(("id" = String, Path, description = "The flow's id, `cf_…`")),
    responses((status = 200, description = "The sign-in's live step: `waiting` (the person acts \
        in the browser), `approved` (a credential came; being stored and tested), \
        `choose_site` (Jira, several sites: `sites`), `connected` (`connection`, `identity`), \
        `expired`, `denied`, `failed` (`error_code`, `error_message`: a plain sentence with the \
        fix). A finished flow is kept for five minutes. 404 for another user's or device's flow \
        and one that is gone", body = ConnectionFlow)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<ConnectionFlow> {
    let user = workspace(&app, &me).await?;
    Ok(Json(shown(mine(&app, &me, user, &id)?.view())))
}

#[utoipa::path(delete, path = "/api/v1/connections/flows/{id}", operation_id = "cancelConnectionFlow",
    tag = "connections", params(("id" = String, Path, description = "The flow's id, `cf_…`")),
    responses((status = 200, description = "The sign-in cancelled and forgotten; Core stops \
        polling. 404 for anyone else's or one that is gone", body = AccountsDeleted)))]
pub async fn cancel(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    let user = workspace(&app, &me).await?;
    mine(&app, &me, user, &id)?;
    app.conn_flows.cancel(user, &me.device.id, &id).await;
    Ok(Json(AccountsDeleted { deleted: true }))
}

#[utoipa::path(post, path = "/api/v1/connections/flows/{id}/callback",
    operation_id = "connectionFlowCallback", tag = "connections",
    params(("id" = String, Path, description = "The flow's id, `cf_…`")),
    request_body = ConnectionFlowCallback,
    responses((status = 200, description = "What the Mac app's loopback listener received for an \
        Atlassian sign-in: Core exchanges the `code` (its own PKCE verifier, never sent out), \
        reads the sites and, with one, connects it; with several the flow waits at \
        `choose_site`. The result is the flow's new step (a failure is `failed`). 400 when \
        `state` is not the one this flow started with (the flow stays as it was); 409 when the \
        flow is not waiting for a redirect (already handled, over, or a GitHub flow); 404 for \
        anyone else's flow", body = ConnectionFlow)))]
pub async fn callback(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<ConnectionFlow> {
    let b: ConnectionFlowCallback = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let flow = mine(&app, &me, user, &id)?;
    let v = engine::callback(&app, &flow, &b.code, &b.state)
        .await
        .map_err(refused)?;
    Ok(Json(shown(v)))
}

#[utoipa::path(post, path = "/api/v1/connections/flows/{id}/choose",
    operation_id = "chooseConnectionSite", tag = "connections",
    params(("id" = String, Path, description = "The flow's id, `cf_…`")),
    request_body = ConnectionFlowChoice,
    responses((status = 200, description = "The Jira site picked at `choose_site`: exactly one \
        connection is made and the tokens are dropped. 400 for a site that is not a choice, 409 \
        when the flow is not at `choose_site`, 404 for anyone else's flow", body = ConnectionFlow)))]
pub async fn choose(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<ConnectionFlow> {
    let b: ConnectionFlowChoice = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let flow = mine(&app, &me, user, &id)?;
    let v = engine::choose(&app, &flow, &b.site)
        .await
        .map_err(refused)?;
    Ok(Json(shown(v)))
}
