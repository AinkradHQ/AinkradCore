//! Connections over the API (C5; design `2026-11-06-core-connections-design` §4, §6; the UI's
//! intent is `2026-11-06-connections-ui-handoff`). A connection links the Core to a service
//! (GitHub, Jira) with a credential the Core keeps sealed: **no route, event, log line or audit
//! row ever carries one**; a credential is written (`createConnection`,
//! `replaceConnectionCredential`, a sign-in flow), never read.
//!
//! - **Who.** Reading kinds, connections and one connection is `read`: an `admin` device sees
//!   every connection of its workspace with its grant count; any other device sees only the
//!   connections granted to it (a grant naming its user, or the role `member`) and only what it
//!   may do with each, never anyone's grants or limits; the rest is 404. Everything else is
//!   `admin`; every write (and starting a sign-in) is also destructive (a step-up). Finishing a
//!   sign-in (a callback, a site choice), polling or cancelling one, and a test are not: they
//!   act only on the caller's own flow or one fixed request, as the account login and test do.
//! - **One workspace.** A connection belongs to the user of the calling device
//!   (`core_devices.user_id`); another workspace's is 404 on every route.
//! - **Sign-in flows** (`flows`): "Sign in with GitHub" (the device flow) and "Sign in with
//!   Atlassian" (OAuth, the Mac app catches the redirect), held in memory, owned by the user and
//!   device that started them, ending in one connection.
//! - **Refusals.** `bad_request` 400, `not_found` 404, `conflict`, `limit_reached` and the
//!   secrets gates 409, `secrets_unavailable` 503: the store's own codes.

use std::collections::HashSet;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use utoipa::{IntoParams, OpenApi};

use super::accounts::AccountsDeleted;
use super::types::{opt_ts, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::connections::adapter::Descriptor;
use crate::store::chains::user_of;
use crate::store::connections::{self as store, Who, bindings, grants};

pub(super) mod apps;
pub(super) mod flows;
pub(super) mod grants_api;
pub(super) mod manage;
mod types;
use types::*;

/// The routes of this module in the contract.
#[derive(OpenApi)]
#[openapi(paths(
    list_kinds,
    list,
    get,
    manage::create,
    update,
    delete,
    manage::replace_credential,
    manage::test,
    activity,
    flows::start,
    flows::get,
    flows::cancel,
    flows::callback,
    flows::choose,
    grants_api::list_grants,
    grants_api::set_grant,
    grants_api::revoke_grant,
    grants_api::list_defaults,
    grants_api::set_default,
    grants_api::clear_default,
    apps::get,
    apps::set
))]
pub struct Doc;

/// The contract with this module's routes merged in (`spec` takes it from here to keep its own
/// size), as a JSON value.
pub(super) fn contract(mut doc: utoipa::openapi::OpenApi) -> serde_json::Value {
    doc.merge(<Doc as OpenApi>::openapi());
    serde_json::to_value(doc).expect("spec serialises")
}

pub(super) fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

/// A numeric path id; anything else is no such connection.
pub(super) fn num(s: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such connection"))
}

pub(super) fn is_admin(me: &Caller) -> bool {
    me.device.scopes.iter().any(|s| s == "admin")
}

pub(super) fn need_admin(me: &Caller) -> Result<(), ApiError> {
    match is_admin(me) {
        true => Ok(()),
        false => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "this requires the admin scope",
        )),
    }
}

pub(super) fn sealer(app: &App) -> Result<&crate::ops::secretbox::SecretBox, ApiError> {
    app.secrets.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "secrets_unavailable",
            "this Core has no master key loaded",
        )
    })
}

/// The workspace of the calling device.
pub(super) async fn workspace(app: &App, me: &Caller) -> Result<i64, ApiError> {
    Ok(user_of(&app.pool, &me.device.id).await?)
}

pub(super) fn who<'a>(me: &'a Caller, user: i64, now: &'a str) -> Who<'a> {
    Who {
        workspace: user,
        by_device: &me.device.id,
        actor: BY,
        now,
    }
}

fn kind_of<'a>(app: &'a App, kind: &str) -> Result<&'a Descriptor, ApiError> {
    app.connections
        .registry()
        .get(kind)
        .map(|a| a.descriptor())
        .ok_or_else(|| ApiError::bad_request("no such kind of connection"))
}

/// Whether Sign in works for `kind`: Ainkrad's app is set up here.
pub(super) fn configured(app: &App, kind: &str) -> bool {
    match kind {
        "github" => app.conn_apps.github_client_id().is_some(),
        "jira" => app.connections.jira().app_configured(),
        "linear" => app.connections.linear().app_configured(),
        "slack" => app.connections.slack().app_configured(),
        _ => false,
    }
}

fn available(app: &App, kind: &str, method: &str) -> bool {
    match method {
        "oauth" => configured(app, kind),
        "app_install" => app.connections.github().installer().configured(),
        _ => true,
    }
}

// ----- kinds ------------------------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/connection-kinds", operation_id = "listConnectionKinds",
    tag = "connections",
    responses((status = 200, description = "The kinds of connection a Core knows, as data a \
        screen draws its setup from: the sign-in methods in order of preference, the capabilities \
        with their read or write class and plain titles, the resource limit shape, help text, and \
        whether Ainkrad's app for the kind is set up on this Core (`configured`, and each \
        method's `available`)", body = Vec<ConnectionKind>)))]
pub async fn list_kinds(State(app): State<App>) -> ApiResult<Vec<ConnectionKind>> {
    let slug = app.conn_apps.github_slug();
    let installer = app.connections.github().installer().configured();
    let kinds = app.connections.registry().descriptors();
    Ok(Json(
        kinds
            .into_iter()
            .map(|d| ConnectionKind {
                kind: d.kind.to_owned(),
                title: d.title.to_owned(),
                summary: d.summary.to_owned(),
                auth_methods: d
                    .auth_methods
                    .iter()
                    .map(|m| KindAuthMethod {
                        id: m.id.to_owned(),
                        title: m.title.to_owned(),
                        help: m.help.to_owned(),
                        steps: m.steps.iter().map(|s| (*s).to_owned()).collect(),
                        advanced: m.advanced,
                        available: available(&app, d.kind, m.id),
                    })
                    .collect(),
                capabilities: d
                    .capabilities
                    .iter()
                    .map(|c| KindCapability {
                        name: c.name.to_owned(),
                        title: c.title.to_owned(),
                        class: if c.write { "write" } else { "read" }.to_owned(),
                        write: c.write,
                    })
                    .collect(),
                limits: d
                    .limits
                    .iter()
                    .map(|l| KindLimit {
                        key: l.key.to_owned(),
                        title: l.title.to_owned(),
                        help: l.help.to_owned(),
                    })
                    .collect(),
                configured: configured(&app, d.kind),
                install_url: match (d.kind, installer, &slug) {
                    ("github", true, Some(s)) => {
                        Some(format!("https://github.com/apps/{s}/installations/new"))
                    }
                    _ => None,
                },
            })
            .collect(),
    ))
}

// ----- reading ----------------------------------------------------------------------------

/// What the caller may do with connection `id`: the capabilities of the grants naming its user
/// or the role `member` (`admin` devices are not asked: they see everything).
fn my_capabilities(all: &[grants::Grant], user: i64) -> Vec<String> {
    let mut caps: Vec<String> = Vec::new();
    for g in all {
        let mine = match g.grantee_kind.as_str() {
            "user" => g.grantee == user.to_string(),
            "role" => g.grantee == "member",
            _ => false,
        };
        if mine {
            for c in &g.capabilities {
                if !caps.contains(c) {
                    caps.push(c.clone());
                }
            }
        }
    }
    caps.sort();
    caps
}

struct Shown {
    admin: bool,
    user: i64,
    defaults: HashSet<i64>,
}

async fn shown(app: &App, me: &Caller, user: i64) -> Result<Shown, ApiError> {
    let defaults = bindings::list(&app.pool, user, None)
        .await?
        .into_iter()
        .filter(|b| b.scope_kind == "workspace")
        .map(|b| b.connection_id)
        .collect();
    Ok(Shown {
        admin: is_admin(me),
        user,
        defaults,
    })
}

/// The connection as the caller may see it; `None` for a device that is not granted it.
async fn view(app: &App, s: &Shown, c: store::Connection) -> Result<Option<Connection>, ApiError> {
    let all = grants::list(&app.pool, s.user, c.id).await?;
    let (grant_count, mine) = match s.admin {
        true => (Some(all.len() as i64), None),
        false => {
            let caps = my_capabilities(&all, s.user);
            if caps.is_empty() {
                return Ok(None);
            }
            (None, Some(caps))
        }
    };
    Ok(Some(Connection {
        id: c.id,
        kind: c.kind,
        name: c.name,
        label: c.label,
        identity: c.identity,
        auth_method: c.auth_method,
        status: c.status,
        state_reason: c.state_reason,
        state_until: opt_ts(c.state_until.as_deref()),
        last_tested_at: opt_ts(c.last_tested_at.as_deref()),
        expires_at: opt_ts(c.expires_at.as_deref()),
        disabled: c.disabled,
        is_default: s.defaults.contains(&c.id),
        created_at: ts(&c.created_at),
        updated_at: ts(&c.updated_at),
        created_by: s.admin.then_some(c.created_by),
        grant_count,
        my_capabilities: mine,
    }))
}

/// The connection `id` as the caller sees it: 404 for another workspace's, and for one a
/// non-admin device is not granted.
pub(super) async fn one(
    app: &App,
    me: &Caller,
    user: i64,
    id: i64,
) -> Result<Connection, ApiError> {
    let c = store::get(&app.pool, user, id).await?;
    let s = shown(app, me, user).await?;
    view(app, &s, c)
        .await?
        .ok_or_else(|| ApiError::not_found("no such connection"))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct KindQuery {
    /// Only this kind's connections.
    pub kind: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/connections", operation_id = "listConnections",
    tag = "connections", params(KindQuery),
    responses((status = 200, description = "The caller's workspace's connections, oldest first \
        (of `kind` when given). An `admin` device sees all of them with their `grant_count`; \
        another device only the ones granted to it, with `my_capabilities`. Never a credential", body = Vec<Connection>)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Query(q): Query<KindQuery>,
) -> ApiResult<Vec<Connection>> {
    let user = workspace(&app, &me).await?;
    let s = shown(&app, &me, user).await?;
    let mut out = Vec::new();
    for c in store::list(&app.pool, user, q.kind.as_deref()).await? {
        out.extend(view(&app, &s, c).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/api/v1/connections/{id}", operation_id = "getConnection",
    tag = "connections", params(("id" = String, Path, description = "The connection's id")),
    responses((status = 200, description = "One connection; 404 for another workspace's, and \
        for one a non-admin device is not granted", body = Connection)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Connection> {
    let user = workspace(&app, &me).await?;
    Ok(Json(one(&app, &me, user, num(&id)?).await?))
}

#[utoipa::path(patch, path = "/api/v1/connections/{id}", operation_id = "updateConnection",
    tag = "connections", params(("id" = String, Path, description = "The connection's id")),
    request_body = UpdateConnection,
    responses((status = 200, description = "Renamed, relabelled, switched off or on (audited \
        `connection.renamed`, `.updated`, `.disabled`, `.enabled`). Switching on also clears a \
        confirmed auth failure: the next test decides again. 400 for no field or a bad one, 409 \
        when the name is taken, 404 for another workspace's", body = Connection)))]
pub async fn update(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Connection> {
    let b: UpdateConnection = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let id = num(&id)?;
    store::get(&app.pool, user, id).await?;
    if b.name.is_none() && b.label.is_none() && b.disabled.is_none() {
        return Err(ApiError::bad_request("name a field to change"));
    }
    if b.name.as_deref().is_some_and(|n| !store::valid_name(n))
        || b.label
            .as_deref()
            .is_some_and(|l| !store::valid_text(l, 80))
    {
        return Err(ApiError::bad_request("that name or label is not valid"));
    }
    let now = app.clock.now();
    // One transaction: a name that is taken leaves the label and the switch as they were.
    let change = store::Edit {
        name: b.name.as_deref(),
        label: b.label.as_deref(),
        disabled: b.disabled,
    };
    store::edit(&app.pool, id, &change, who(&me, user, &now)).await?;
    Ok(Json(one(&app, &me, user, id).await?))
}

#[utoipa::path(delete, path = "/api/v1/connections/{id}", operation_id = "deleteConnection",
    tag = "connections", params(("id" = String, Path, description = "The connection's id")),
    responses((status = 200, description = "Deleted with its grants and its credential, which \
        is wiped (audited `connection.deleted`). 409 `conflict` while it is its kind's default: \
        set another default first (`setConnectionDefault`) or clear it; 404 for another \
        workspace's", body = AccountsDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    let user = workspace(&app, &me).await?;
    let now = app.clock.now();
    store::delete(&app.pool, num(&id)?, who(&me, user, &now)).await?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UseQuery {
    /// Uses with a `seq` below this; absent, from the newest.
    pub before: Option<i64>,
    pub limit: Option<u32>,
}

#[utoipa::path(get, path = "/api/v1/connections/{id}/activity",
    operation_id = "listConnectionActivity", tag = "connections", params(("id" = String, Path,
    description = "The connection's id"), UseQuery),
    responses((status = 200, description = "What agents and features did with the connection, \
        newest first (at most `limit`, 50 by default, 200 at most): the operation, the result \
        class, a refusal code, the session and agent. No payload, no secret, ever. 404 for \
        another workspace's", body = Vec<ConnectionUse>)))]
pub async fn activity(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(q): Query<UseQuery>,
) -> ApiResult<Vec<ConnectionUse>> {
    let user = workspace(&app, &me).await?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let all =
        crate::store::connections::activity::list(&app.pool, user, num(&id)?, q.before, limit)
            .await?;
    Ok(Json(
        all.into_iter()
            .map(|u| ConnectionUse {
                seq: u.seq,
                at: ts(&u.at),
                kind: u.kind,
                action: u.action,
                result: u.result,
                code: u.code,
                session: u.session,
                agent: u.agent,
            })
            .collect(),
    ))
}
