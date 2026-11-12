//! Secret groups (N24): one level, a description and a runner list its members inherit.
//! Scope `admin`; every write needs a step-up, like the secrets themselves. Leasing a group
//! lends every member that the runner may have. No route returns a value.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::scheduler::iso_of_unix;
use crate::store::secret_groups::{self as store, Group};
use crate::store::secrets as secrets_store;

/// A group, never a value.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretGroupInfo {
    /// `[a-z][a-z0-9_.-]{0,63}`.
    pub name: String,
    /// One line: what the group is for.
    pub description: String,
    /// The runner devices its members may be leased to unless they list their own.
    pub runners: Vec<String>,
    /// The names of its secrets.
    pub members: Vec<String>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Group> for SecretGroupInfo {
    fn from(g: Group) -> Self {
        Self {
            name: g.name,
            description: g.description,
            runners: g.runners,
            members: g.members,
            created_at: ts(&g.created_at),
            updated_at: ts(&g.updated_at),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewSecretGroup {
    pub name: String,
    /// One line, at most 200 characters; default empty.
    pub description: Option<String>,
    /// Active runner device ids; default none.
    pub runners: Option<Vec<String>>,
}

/// What changes; an omitted field is kept.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSecretGroup {
    pub description: Option<String>,
    pub runners: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecretGroupDeleted {
    pub deleted: bool,
}

/// One lease of a group's grant: hand `lease` to the runner. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct GroupLease {
    /// The member's name.
    pub secret: String,
    pub lease: String,
    pub expires_at: Timestamp,
}

/// The leases a group lent, one per member the runner may have. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct GroupLeaseGrant {
    pub leases: Vec<GroupLease>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewGroupLease {
    /// The runner's device id, `d_…`.
    pub runner: String,
    /// Each lease's lifetime; default and most `secrets.lease_secs`.
    pub ttl_secs: Option<i64>,
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

fn name(name: &str) -> Result<&str, ApiError> {
    match secrets_store::valid_name(name) {
        true => Ok(name),
        false => Err(ApiError::not_found("no such secret group")),
    }
}

#[utoipa::path(get, path = "/api/v1/secret-groups", operation_id = "listSecretGroups",
    tag = "secrets",
    responses((status = 200, description = "Every group, by name, with its members", body = Vec<SecretGroupInfo>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<SecretGroupInfo>> {
    let all = store::list(&app.pool).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/secret-groups", operation_id = "createSecretGroup",
    tag = "secrets", request_body = NewSecretGroup,
    responses((status = 200, description = "Made (audited as `secret_group.created`). 409 \
        `conflict` for a name in use; 400 for a runner that is not active", body = SecretGroupInfo)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<SecretGroupInfo> {
    let b: NewSecretGroup = parse(&body)?;
    let g = store::create(
        &app.pool,
        &b.name,
        b.description.as_deref().unwrap_or_default(),
        b.runners.as_deref().unwrap_or_default(),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(g.into()))
}

#[utoipa::path(put, path = "/api/v1/secret-groups/{id}", operation_id = "updateSecretGroup",
    tag = "secrets", params(("id" = String, Path, description = "The group's name")),
    request_body = UpdateSecretGroup,
    responses((status = 200, description = "Changed (audited as `secret_group.updated`)",
        body = SecretGroupInfo)))]
pub async fn update(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
    body: Bytes,
) -> ApiResult<SecretGroupInfo> {
    let b: UpdateSecretGroup = parse(&body)?;
    let g = store::update(
        &app.pool,
        name(&n)?,
        b.description.as_deref(),
        b.runners.as_deref(),
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(g.into()))
}

#[utoipa::path(delete, path = "/api/v1/secret-groups/{id}", operation_id = "deleteSecretGroup",
    tag = "secrets", params(("id" = String, Path, description = "The group's name")),
    responses((status = 200, description = "Deleted (audited as `secret_group.deleted`). 409 \
        `conflict` while it has secrets", body = SecretGroupDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
) -> ApiResult<SecretGroupDeleted> {
    store::delete(&app.pool, name(&n)?, &me.device.id, BY).await?;
    Ok(Json(SecretGroupDeleted { deleted: true }))
}

#[utoipa::path(post, path = "/api/v1/secret-groups/{id}/leases", operation_id = "leaseSecretGroup",
    tag = "secrets", params(("id" = String, Path, description = "The group's name")),
    request_body = NewGroupLease,
    responses((status = 200, description = "One lease for each member the runner may have (its \
        own runners, else the group's), each as `leaseSecret` grants it (audited as \
        `secret.leased`). 400 when the runner may have none; the refusals of `leaseSecret`",
        body = GroupLeaseGrant)))]
pub async fn lease(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
    body: Bytes,
) -> ApiResult<GroupLeaseGrant> {
    let n = name(&n)?;
    let b: NewGroupLease = parse(&body)?;
    let group = store::list(&app.pool)
        .await?
        .into_iter()
        .find(|g| g.name == n)
        .ok_or_else(|| ApiError::not_found("no such secret group"))?;
    let members: Vec<_> = secrets_store::list(&app.pool)
        .await?
        .into_iter()
        .filter(|s| group.members.contains(&s.name) && s.effective_runners.contains(&b.runner))
        .collect();
    if members.is_empty() {
        return Err(ApiError::bad_request(
            "the runner may have none of this group's secrets",
        ));
    }
    // ponytail: one lease at a time; a refusal midway leaves the earlier leases to expire (they
    // are single-use and short). A single transaction if that ever matters.
    let mut leases = Vec::new();
    for s in members {
        let (lease, expires_at) = secrets_store::lease(
            &app.pool,
            &s.name,
            &b.runner,
            b.ttl_secs,
            &me.device.id,
            BY,
            &app.clock.now(),
            app.clock.unix(),
        )
        .await?;
        leases.push(GroupLease {
            secret: s.name,
            lease,
            expires_at: ts(&iso_of_unix(expires_at)),
        });
    }
    Ok(Json(GroupLeaseGrant { leases }))
}
