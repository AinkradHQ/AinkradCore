//! The secrets broker v0 (E2-07, `store::secrets`): store, list, rotate and delete secrets
//! (scope `admin`; every write needs a step-up), grant a runner a lease (`admin`, step-up: it is
//! the only way a value leaves the Core, the spec §8 "reveal"), and the runner's redemption
//! (scope `runner`, the lease's own runner only). No route returns a value to a client.
//!
//! Bodies are parsed here, not by axum's `Json`: a serde error can quote the input, and the
//! input may be the value. A malformed body gets one fixed message.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::iso_of_unix;
use crate::store::secrets::{self as store, Error, Meta, NewValue};

/// A secret, never its value.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretInfo {
    /// `[a-z][a-z0-9_.-]{0,63}`.
    pub name: String,
    /// The device that stored it, `d_…`.
    pub owner: String,
    /// The runner devices it may be leased to (its scope); empty: none.
    pub runners: Vec<String>,
    /// How a runner hands it to a session: `env`, `file` or `askpass`.
    pub delivery: String,
    /// 1 when stored, one more per rotation.
    pub version: i64,
    /// The value's length in bytes.
    pub size: i64,
    /// The master key it is sealed under.
    pub key_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl From<Meta> for SecretInfo {
    fn from(m: Meta) -> Self {
        Self {
            name: m.name,
            owner: m.owner,
            runners: m.runners,
            delivery: m.delivery,
            version: m.version,
            size: m.size,
            key_id: m.key_id,
            created_at: ts(&m.created_at),
            updated_at: ts(&m.updated_at),
        }
    }
}

/// A new secret. Deliberately no `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct NewSecret {
    pub name: String,
    /// UTF-8 text, at most `secrets.max_bytes`; written, never read back.
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Runner device ids it may be leased to; default none.
    pub runners: Option<Vec<String>>,
    /// `env` (the default), `file` or `askpass`.
    pub delivery: Option<String>,
}

/// A rotation: the new value, and optionally a new scope or delivery. No `Debug`.
#[derive(Deserialize, ToSchema)]
pub struct RotateSecret {
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    pub runners: Option<Vec<String>>,
    pub delivery: Option<String>,
}

/// A lease to grant.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewLease {
    /// The runner's device id, `d_…`; it must be in the secret's scope.
    pub runner: String,
    /// Its lifetime; default and most `secrets.lease_secs`.
    pub ttl_secs: Option<i64>,
}

/// A granted lease: hand `lease` to the runner, which redeems it once before `expires_at`.
/// No `Debug` (review L4): a log line must never print a live lease.
#[derive(Serialize, ToSchema)]
pub struct LeaseGrant {
    /// `l_…`; only its runner can redeem it.
    pub lease: String,
    pub expires_at: Timestamp,
}

/// A lease to redeem. No `Debug` (review L4).
#[derive(Deserialize, ToSchema)]
pub struct RedeemLease {
    pub lease: String,
}

/// A redeemed secret, for the runner only. No `Debug`.
#[derive(Serialize, ToSchema)]
pub struct LeasedSecret {
    pub name: String,
    pub version: i64,
    pub delivery: String,
    #[schema(value_type = String)]
    pub value: Zeroizing<String>,
    /// Drop it by then, or at the session's end.
    pub expires_at: Timestamp,
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|_| ApiError::bad_request("the body is not a valid request for this route"))
}

fn sealer(app: &App) -> Result<&SecretBox, ApiError> {
    app.secrets.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "secrets_unavailable",
            "this Core has no master key loaded",
        )
    })
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Db(e) => e.into(),
            Error::Refused { code, message } => {
                let status = match code {
                    "not_found" => StatusCode::NOT_FOUND,
                    "lease_expired" => StatusCode::GONE,
                    "secrets_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
                    "secrets_disabled" | "real_secret_refused" | "conflict" | "limit_reached" => {
                        StatusCode::CONFLICT
                    }
                    _ => StatusCode::BAD_REQUEST,
                };
                ApiError::new(status, code, message)
            }
        }
    }
}

fn name(name: &str) -> Result<&str, ApiError> {
    match store::valid_name(name) {
        true => Ok(name),
        false => Err(ApiError::not_found("no such secret")),
    }
}

#[utoipa::path(get, path = "/api/v1/secrets", operation_id = "listSecrets", tag = "secrets",
    responses((status = 200, description = "Every secret, by name, without its value", body = Vec<SecretInfo>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<SecretInfo>> {
    let all = store::list(&app.pool).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/api/v1/secrets", operation_id = "createSecret", tag = "secrets",
    request_body = NewSecret,
    responses((status = 200, description = "Stored, sealed (audited as `secret.created`). 409 \
        `secrets_disabled` (gate G-SEC, `secrets.mode` 0), `real_secret_refused` (mode 1 and a \
        value shaped like a real credential), `conflict` or `limit_reached`; 400 `too_large`; \
        503 `secrets_unavailable` (no master key)", body = SecretInfo)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<SecretInfo> {
    let b: NewSecret = parse(&body)?;
    let new = NewValue {
        value: &b.value,
        runners: b.runners.as_deref(),
        delivery: b.delivery.as_deref(),
    };
    let m = store::create(
        &app.pool,
        sealer(&app)?,
        &b.name,
        &new,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(m.into()))
}

#[utoipa::path(put, path = "/api/v1/secrets/{id}", operation_id = "rotateSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    request_body = RotateSecret,
    responses((status = 200, description = "A new version (audited as `secret.rotated`); the \
        refusals of `createSecret`", body = SecretInfo)))]
pub async fn rotate(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
    body: Bytes,
) -> ApiResult<SecretInfo> {
    let n = name(&n)?;
    let b: RotateSecret = parse(&body)?;
    let new = NewValue {
        value: &b.value,
        runners: b.runners.as_deref(),
        delivery: b.delivery.as_deref(),
    };
    let m = store::rotate(
        &app.pool,
        sealer(&app)?,
        n,
        &new,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await?;
    Ok(Json(m.into()))
}

/// What a delete answers.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretDeleted {
    pub deleted: bool,
}

#[utoipa::path(delete, path = "/api/v1/secrets/{id}", operation_id = "deleteSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    responses((status = 200, description = "Deleted with its leases (audited as \
        `secret.deleted`); works whatever `secrets.mode` is", body = SecretDeleted)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
) -> ApiResult<SecretDeleted> {
    store::delete(&app.pool, name(&n)?, &me.device.id, BY).await?;
    Ok(Json(SecretDeleted { deleted: true }))
}

#[utoipa::path(post, path = "/api/v1/secrets/{id}/leases", operation_id = "leaseSecret",
    tag = "secrets",
    params(("id" = String, Path, description = "The secret's name")),
    request_body = NewLease,
    responses((status = 200, description = "A lease for one runner in the secret's scope, one \
        redemption, `ttl_secs` at most (audited as `secret.leased`). 409 `secrets_disabled` or \
        `limit_reached`; 400 when the runner is not in scope", body = LeaseGrant)))]
pub async fn lease(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(n): Path<String>,
    body: Bytes,
) -> ApiResult<LeaseGrant> {
    let n = name(&n)?;
    let b: NewLease = parse(&body)?;
    let (lease, expires_at) = store::lease(
        &app.pool,
        n,
        &b.runner,
        b.ttl_secs,
        &me.device.id,
        BY,
        &app.clock.now(),
        app.clock.unix(),
    )
    .await?;
    Ok(Json(LeaseGrant {
        lease,
        expires_at: ts(&iso_of_unix(expires_at)),
    }))
}

#[utoipa::path(post, path = "/api/v1/secret-leases/redeem", operation_id = "redeemSecretLease",
    tag = "secrets",
    request_body = RedeemLease,
    responses((status = 200, description = "The lease's runner (and only it) gets the value, \
        once (audited as `secret.redeemed`). 404 for a lease that is not this runner's or no \
        longer in scope, 410 `lease_expired` when spent or expired, 409 `secrets_disabled`",
        body = LeasedSecret)))]
pub async fn redeem(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> ApiResult<LeasedSecret> {
    let b: RedeemLease = parse(&body)?;
    if me.device.kind != "runner" {
        return Err(ApiError::not_found("no such lease"));
    }
    let r = store::redeem(
        &app.pool,
        sealer(&app)?,
        &b.lease,
        &me.device.id,
        BY,
        &app.clock.now(),
        app.clock.unix(),
    )
    .await?;
    Ok(Json(LeasedSecret {
        name: r.name,
        version: r.version,
        delivery: r.delivery,
        value: r.value,
        expires_at: ts(&iso_of_unix(r.expires_at)),
    }))
}
