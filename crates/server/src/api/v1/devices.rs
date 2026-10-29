//! Devices (handshake spec §3, §10): list and revoke. A device enrolls only through pairing
//! (or, for the first, the host's `bootstrap`); there is no key to hand out. Revocation is
//! immediate: the row is marked and audited in one transaction, then the device's sessions are
//! dropped and its sockets closed with 4001.

use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::store::gov::{self, list_devices, revoke_device, set_push_token};

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
    if !revoke_device(&app.pool, &id, BY, Some(&me.device.id), &app.clock.now()).await? {
        return Err(ApiError::not_found(format!("no live device {id}")));
    }
    app.auth.revoked(&id);
    let device = gov::get_device(&app.pool, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("gone"))?;
    Ok(Json(device.into()))
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
