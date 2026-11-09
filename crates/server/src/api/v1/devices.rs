//! Devices (handshake spec §3, §8, §10, E1-09.5): list, get, rename, change scopes and revoke.
//! A device enrolls only through pairing (or, for the first, the host's `bootstrap`); there is
//! no key to hand out. Rename, scope change and revoke need `admin` and a step-up
//! (`scopes::DESTRUCTIVE`); the rules (subset, kinds, the last admin) are in
//! `store::gov::manage`. Revocation is immediate: the row is marked and audited in one
//! transaction, then the device's sessions are dropped and its sockets closed with 4001; a
//! scope change closes its sockets with 4003 so they reconnect to a re-filtered stream.

use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::store::gov::{self, Refused, get_kinds, list_devices, set_kinds, set_push_token};
use ainkrad_core::audit::NewAuditEvent;
use serde_json::json;

/// A device: who it is and what it may do. Never a key's private half: the Core has none.
#[derive(Debug, Serialize, ToSchema)]
pub struct Device {
    /// `d_` and 26 characters.
    pub id: String,
    pub name: String,
    /// `device` (an app or CLI), `runner` or `passkey`.
    pub kind: Option<String>,
    /// What it may do (E1-09 enforces them).
    pub scopes: Option<Vec<String>>,
    /// base64url SHA-256 of its routine public key: what pairing shows.
    pub fingerprint: Option<String>,
    /// `pending`, `active`, `rejected`, `expired` or `locked`.
    pub status: Option<String>,
    /// Where its key lives, as the device claims it (not verified).
    pub key_storage: Option<String>,
    pub platform: Option<String>,
    pub created_at: Timestamp,
    /// Marked at most once a minute.
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
    /// Whether it enrolled a step-up key, so it can elevate (E1-09.3).
    pub stepup: Option<bool>,
}

impl From<gov::Device> for Device {
    fn from(d: gov::Device) -> Self {
        Self {
            id: d.id,
            name: d.name,
            kind: Some(d.kind),
            scopes: Some(d.scopes),
            fingerprint: Some(d.fingerprint),
            status: Some(d.status),
            key_storage: d.key_storage,
            platform: d.platform,
            created_at: ts(&d.created_at),
            last_used_at: opt_ts(d.last_used_at.as_deref()),
            revoked_at: opt_ts(d.revoked_at.as_deref()),
            stepup: Some(d.stepup_spki.is_some()),
        }
    }
}

#[utoipa::path(get, path = "/api/v1/devices", operation_id = "listDevices", tag = "devices",
    responses((status = 200, description = "Every device, revoked ones too", body = Vec<Device>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Device>> {
    let devices = list_devices(&app.pool).await?;
    Ok(Json(devices.into_iter().map(Device::from).collect()))
}

/// Revokes at once, the calling device included; the row stays, marked revoked.
#[utoipa::path(delete, path = "/api/v1/devices/{id}", operation_id = "revokeDevice", tag = "devices",
    params(("id" = String, Path, description = "Device id, `d_…`")),
    responses((status = 200, description = "The revoked device. Its sessions end and its open \
        sockets close with 4001 at once (audited as `device.revoked`)", body = Device)))]
pub async fn revoke(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Device> {
    if !is_id(&id, "d_") {
        return Err(ApiError::not_found("no such device"));
    }
    let now = app.clock.now();
    let r = gov::revoke_from_device(&app.pool, &id, BY, &me.device.id, &now).await?;
    last_admin(&app, &me, &id, "revoke", &r).await;
    refused(r)?;
    app.auth.revoked(&id);
    current(&app, &id).await
}

/// Audits a last-admin refusal of `op` on `id` as `device.last_admin_refused`, once per device
/// per window (`auth::refusals`): repeats are only counted, so they never grow the audit log.
async fn last_admin<T>(app: &App, me: &Caller, id: &str, op: &str, r: &Result<T, Refused>) {
    if !matches!(r, Err(Refused::LastAdmin))
        || !app
            .auth
            .refusals
            .note(&format!("last_admin:{id}"), app.clock.unix())
    {
        return;
    }
    let event = NewAuditEvent {
        actor: BY,
        action: "device.last_admin_refused".to_owned(),
        entity: None,
        details: json!({"device": id, "by_device": me.device.id, "op": op}).to_string(),
    };
    if let Err(e) = crate::store::audit::append_one(&app.pool, &event).await {
        tracing::error!(error = %e, "auditing a last-admin refusal failed");
    }
}

/// A refusal from `store::gov::manage` as its answer.
fn refused<T>(r: Result<T, Refused>) -> Result<T, ApiError> {
    r.map_err(|why| match why {
        Refused::NotFound => ApiError::not_found("no live device"),
        Refused::Bad(why) => ApiError::bad_request(why),
        Refused::LastAdmin => {
            ApiError::conflict("that would leave no active admin device; pair another first")
        }
    })
}

async fn current(app: &App, id: &str) -> ApiResult<Device> {
    let device = gov::get_device(&app.pool, id)
        .await?
        .ok_or_else(|| ApiError::not_found("no such device"))?;
    Ok(Json(device.into()))
}

#[utoipa::path(get, path = "/api/v1/devices/{id}", operation_id = "getDevice", tag = "devices",
    params(("id" = String, Path, description = "Device id, `d_…`")),
    responses((status = 200, description = "The device, in any state", body = Device)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Device> {
    if !is_id(&id, "d_") {
        return Err(ApiError::not_found("no such device"));
    }
    current(&app, &id).await
}

/// A device's new name.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    /// 1 to 64 characters, no control characters; trimmed.
    pub name: String,
}

#[utoipa::path(patch, path = "/api/v1/devices/{id}", operation_id = "renameDevice",
    tag = "devices", request_body = Rename,
    params(("id" = String, Path, description = "Device id, `d_…`")),
    responses((status = 200, description = "The renamed device (audited as `device.renamed`)",
        body = Device)))]
pub async fn rename(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<Rename>,
) -> ApiResult<Device> {
    if !is_id(&id, "d_") {
        return Err(ApiError::not_found("no such device"));
    }
    refused(gov::rename_device(&app.pool, &id, &b.name, BY, &me.device.id).await?)?;
    current(&app, &id).await
}

/// A device's new scopes.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetScopes {
    /// From the catalogue, each held by the calling device; a runner holds exactly `runner`.
    pub scopes: Vec<String>,
}

#[utoipa::path(put, path = "/api/v1/devices/{id}/scopes", operation_id = "setDeviceScopes",
    tag = "devices", request_body = SetScopes,
    params(("id" = String, Path, description = "Device id, `d_…`")),
    responses((status = 200, description = "The device with its new scopes (audited as \
        `device.scopes_changed`); its open sockets close with 4003. A scope the caller does not \
        hold, or a runner rule broken, is a 400; leaving no active admin device is a 409",
        body = Device)))]
pub async fn set_scopes(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(b): Json<SetScopes>,
) -> ApiResult<Device> {
    if !is_id(&id, "d_") {
        return Err(ApiError::not_found("no such device"));
    }
    // A passkey that holds `admin` already keeps it (T-PK-3 applies to granting it anew).
    if let Some(d) = gov::get_device(&app.pool, &id).await?
        && !d.scopes.iter().any(|s| s == "admin")
    {
        super::pairing::passkey_admin(&app, &d.kind, &b.scopes).await?;
    }
    let mine = &me.device.scopes;
    let r = gov::set_device_scopes(&app.pool, &id, &b.scopes, mine, BY, &me.device.id).await?;
    last_admin(&app, &me, &id, "set_scopes", &r).await;
    refused(r)?;
    app.auth.rescoped(&id);
    current(&app, &id).await
}

/// The calling device's APNs token (E10.4).
#[derive(Debug, Deserialize, ToSchema)]
pub struct PushToken {
    /// The device token, hex, as the app got it from APNs.
    pub token: String,
    /// A development build's token, for the sandbox gateway.
    #[serde(default)]
    pub sandbox: bool,
}

#[utoipa::path(put, path = "/api/v1/push-token", operation_id = "setPushToken", tag = "devices",
    request_body = PushToken,
    responses((status = 200, description = "The calling device now gets pushes: what the \
        modules' push rules pick", body = Device)))]
pub async fn set_push(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(p): Json<PushToken>,
) -> ApiResult<Device> {
    push(&app, &me, Some((&p.token, p.sandbox))).await
}

#[utoipa::path(delete, path = "/api/v1/push-token", operation_id = "clearPushToken",
    tag = "devices",
    responses((status = 200, description = "The calling device gets no more pushes", body = Device)))]
pub async fn clear_push(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Device> {
    push(&app, &me, None).await
}

/// The notification kinds the calling device is pushed (E2-12.3).
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PushKinds {
    /// The kinds it opted into, e.g. `approval_needed`; `null` is every kind its scopes allow
    /// (the default). A kind needs its scope on top: a `read` device is never sent an approval.
    pub kinds: Option<Vec<String>>,
}

#[utoipa::path(get, path = "/api/v1/push-token/kinds", operation_id = "getPushKinds",
    tag = "devices",
    responses((status = 200, description = "The calling device's opt-in", body = PushKinds)))]
pub async fn get_push_kinds(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<PushKinds> {
    let kinds = get_kinds(&app.pool, &me.device.id).await?;
    Ok(Json(PushKinds { kinds }))
}

#[utoipa::path(put, path = "/api/v1/push-token/kinds", operation_id = "setPushKinds",
    tag = "devices", request_body = PushKinds,
    responses((status = 200, description = "The calling device is now pushed only these \
        kinds (all when `null`)", body = PushKinds)))]
pub async fn set_push_kinds(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(p): Json<PushKinds>,
) -> ApiResult<PushKinds> {
    let set = set_kinds(&app.pool, &me.device.id, p.kinds.as_deref())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?;
    if !set {
        return Err(ApiError::not_found("this device is gone"));
    }
    get_push_kinds(State(app), Extension(me)).await
}

async fn push(app: &App, me: &Caller, token: Option<(&str, bool)>) -> ApiResult<Device> {
    let set = set_push_token(&app.pool, &me.device.id, token)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?;
    let device = gov::get_device(&app.pool, &me.device.id)
        .await?
        .filter(|_| set)
        .ok_or_else(|| ApiError::not_found("this device is gone"))?;
    Ok(Json(device.into()))
}
