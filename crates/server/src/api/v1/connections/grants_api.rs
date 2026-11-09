//! Who may use a connection and the kind's default connection (C5, CN3 and CN1's "Use by
//! default"). Every route is `admin`, every write destructive. A grant names a user of the
//! workspace, a role or an agent, the capabilities (the kind's read ones unless it names more:
//! a write capability is only ever there because the request names it) and the resource limits
//! of the kind's limit shape. The store validates all of it: capabilities exist, limit keys
//! exist, a value is `owner/name`, `owner/*` or a project key (never `*` alone, never `..`).
//!
//! `grants::list` answers an empty list for another workspace's id, so every route here reads
//! the connection first: another workspace's is 404.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};

use super::types::*;
use super::{need_admin, num, parse, who, workspace};
use crate::api::App;
use crate::api::v1::accounts::AccountsDeleted;
use crate::api::v1::types::ts;
use crate::api::v1::{ApiError, ApiResult, Caller};
use crate::store::connections::grants::{self, NewGrant};
use crate::store::connections::{self as store, bindings};

fn shown(g: grants::Grant) -> ConnectionGrant {
    ConnectionGrant {
        grantee_kind: g.grantee_kind,
        grantee: g.grantee,
        capabilities: g.capabilities,
        limits: g.limits,
        created_at: ts(&g.created_at),
        updated_at: ts(&g.updated_at),
    }
}

#[utoipa::path(get, path = "/api/v1/connections/{id}/grants", operation_id = "listConnectionGrants",
    tag = "connections", params(("id" = String, Path, description = "The connection's id")),
    responses((status = 200, description = "Who may use the connection, with their capabilities \
        and resource limits; 404 for another workspace's", body = Vec<ConnectionGrant>)))]
pub async fn list_grants(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Vec<ConnectionGrant>> {
    need_admin(&me)?;
    let user = workspace(&app, &me).await?;
    let id = num(&id)?;
    store::get(&app.pool, user, id).await?;
    let all = grants::list(&app.pool, user, id).await?;
    Ok(Json(all.into_iter().map(shown).collect()))
}

#[utoipa::path(put, path = "/api/v1/connections/{id}/grants", operation_id = "setConnectionGrant",
    tag = "connections", params(("id" = String, Path, description = "The connection's id")),
    request_body = SetConnectionGrant,
    responses((status = 200, description = "That grantee's grant, replaced (one per grantee; \
        audited `connection.granted`, naming any write capabilities). 400 for a grantee that is \
        not a user of the workspace, a role (`admin`, `member`) or an agent id, a capability or \
        limit key the kind does not have, a bad limit value (`owner/name`, `owner/*`, a project \
        key; never `*` alone or `..`), or an empty capability list; 409 `limit_reached` (32 per \
        connection); 404 for another workspace's connection", body = ConnectionGrant)))]
pub async fn set_grant(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<ConnectionGrant> {
    let b: SetConnectionGrant = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let id = num(&id)?;
    store::get(&app.pool, user, id).await?;
    let limits = b.limits.unwrap_or_default();
    let new = NewGrant {
        grantee_kind: &b.grantee_kind,
        grantee: &b.grantee,
        capabilities: b.capabilities.as_deref(),
        limits: &limits,
    };
    let now = app.clock.now();
    let g = grants::set(
        &app.pool,
        app.connections.registry(),
        id,
        &new,
        who(&me, user, &now),
    )
    .await?;
    Ok(Json(shown(g)))
}

#[utoipa::path(delete, path = "/api/v1/connections/{id}/grants/{grantee_kind}/{grantee}",
    operation_id = "revokeConnectionGrant", tag = "connections",
    params(("id" = String, Path, description = "The connection's id"),
        ("grantee_kind" = String, Path, description = "`user`, `role` or `agent`"),
        ("grantee" = String, Path, description = "A user id, a role or an agent id")),
    responses((status = 200, description = "The grantee's grant taken away (audited \
        `connection.grant_revoked`); a call in flight is refused at once. 404 when there was \
        none, or for another workspace's connection", body = AccountsDeleted)))]
pub async fn revoke_grant(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, kind, grantee)): Path<(String, String, String)>,
) -> ApiResult<AccountsDeleted> {
    let user = workspace(&app, &me).await?;
    let id = num(&id)?;
    store::get(&app.pool, user, id).await?;
    let now = app.clock.now();
    match grants::revoke(&app.pool, id, (&kind, &grantee), who(&me, user, &now)).await? {
        true => Ok(Json(AccountsDeleted { deleted: true })),
        false => Err(ApiError::not_found("no such grant")),
    }
}

#[utoipa::path(get, path = "/api/v1/connection-defaults", operation_id = "listConnectionDefaults",
    tag = "connections",
    responses((status = 200, description = "The default connection of each kind that has one: \
        the one used when several of the kind cover a call", body = Vec<DefaultConnection>)))]
pub async fn list_defaults(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Vec<DefaultConnection>> {
    let user = workspace(&app, &me).await?;
    let all = bindings::list(&app.pool, user, None).await?;
    Ok(Json(
        all.into_iter()
            .filter(|b| b.scope_kind == "workspace")
            .map(|b| DefaultConnection {
                kind: b.kind,
                connection: b.connection_id,
            })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/api/v1/connection-defaults/{kind}",
    operation_id = "setConnectionDefault", tag = "connections",
    params(("kind" = String, Path, description = "`github` or `jira`")),
    request_body = SetDefaultConnection,
    responses((status = 200, description = "That connection is the kind's default from now on, \
        replacing the previous one (audited `connection.bound`). 400 when the connection is \
        not of this kind or the kind is unknown; 404 for another workspace's connection", body = DefaultConnection)))]
pub async fn set_default(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(kind): Path<String>,
    body: Bytes,
) -> ApiResult<DefaultConnection> {
    if app.connections.registry().get(&kind).is_none() {
        return Err(ApiError::not_found("no such kind of connection"));
    }
    let b: SetDefaultConnection = parse(&body)?;
    let user = workspace(&app, &me).await?;
    let c = store::get(&app.pool, user, b.connection).await?;
    if c.kind != kind {
        return Err(ApiError::bad_request("that connection is not of this kind"));
    }
    let now = app.clock.now();
    let bound = bindings::set(&app.pool, c.id, ("workspace", ""), who(&me, user, &now)).await?;
    Ok(Json(DefaultConnection {
        kind: bound.kind,
        connection: bound.connection_id,
    }))
}

#[utoipa::path(delete, path = "/api/v1/connection-defaults/{kind}",
    operation_id = "clearConnectionDefault", tag = "connections",
    params(("kind" = String, Path, description = "`github` or `jira`")),
    responses((status = 200, description = "The kind has no default any more (audited \
        `connection.unbound`): a call several connections cover is then refused as ambiguous. \
        404 when it had none", body = AccountsDeleted)))]
pub async fn clear_default(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(kind): Path<String>,
) -> ApiResult<AccountsDeleted> {
    let user = workspace(&app, &me).await?;
    let now = app.clock.now();
    match bindings::clear(&app.pool, &kind, ("workspace", ""), who(&me, user, &now)).await? {
        true => Ok(Json(AccountsDeleted { deleted: true })),
        false => Err(ApiError::not_found("that kind has no default")),
    }
}
