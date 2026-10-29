//! Device keys (E10.3): list, add (the key is in the answer, once), revoke.

use ainkrad_core::gov::DeviceKeyId;
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::{Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::gov::{issue_device_key, list_device_keys, revoke_device_key, set_push_token};

/// A device's key, without the key.
#[derive(Debug, Serialize, ToSchema)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub created_at: Timestamp,
    /// Marked at most once a minute.
    pub last_used_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl From<ainkrad_core::gov::DeviceKey> for Device {
    fn from(d: ainkrad_core::gov::DeviceKey) -> Self {
        Self {
            id: d.id.0,
            name: d.name,
            created_at: ts(&d.created_at),
            last_used_at: opt_ts(d.last_used_at.as_deref()),
            revoked_at: opt_ts(d.revoked_at.as_deref()),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewDevice {
    pub name: String,
}

/// A new device and its key: the only time the key is ever shown.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuedDevice {
    pub device: Device,
    pub key: String,
}

#[utoipa::path(get, path = "/api/v1/devices", operation_id = "listDevices", tag = "devices",
    responses((status = 200, description = "Every device key, revoked ones too; never a key", body = Vec<Device>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Device>> {
    let devices = list_device_keys(&app.pool).await?;
    Ok(Json(devices.into_iter().map(Device::from).collect()))
}

#[utoipa::path(post, path = "/api/v1/devices", operation_id = "createDevice", tag = "devices",
    request_body = NewDevice,
    responses((status = 200, description = "The new device and its key, shown only now", body = IssuedDevice)))]
pub async fn create(State(app): State<App>, Json(new): Json<NewDevice>) -> ApiResult<IssuedDevice> {
    if new.name.trim().is_empty() {
        return Err(ApiError::bad_request("a device needs a name"));
    }
    let (device, key) = issue_device_key(&app.pool, &new.name, BY).await?;
    Ok(Json(IssuedDevice {
        device: device.into(),
        key,
    }))
}

/// Revokes at once, the calling device's own key included; the row stays, marked revoked.
#[utoipa::path(delete, path = "/api/v1/devices/{id}", operation_id = "revokeDevice", tag = "devices",
    params(("id" = i64, Path, description = "Device id")),
    responses((status = 200, description = "The revoked device", body = Device)))]
pub async fn revoke(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Device> {
    let id = DeviceKeyId(id);
    if !revoke_device_key(&app.pool, id, BY, &app.clock.now()).await? {
        return Err(ApiError::not_found(format!("no live device key {}", id.0)));
    }
    let device = crate::store::gov::get_device_key(&app.pool, id)
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
    responses((status = 200, description = "The calling device now gets pushes for new \
        approvals, blocked and stuck issues and escalations", body = Device)))]
pub async fn set_push(
    State(app): State<App>,
    Extension(me): Extension<super::Device>,
    Json(p): Json<PushToken>,
) -> ApiResult<Device> {
    push(&app, me, Some((&p.token, p.sandbox))).await
}

#[utoipa::path(delete, path = "/api/v1/push-token", operation_id = "clearPushToken",
    tag = "devices",
    responses((status = 200, description = "The calling device gets no more pushes", body = Device)))]
pub async fn clear_push(
    State(app): State<App>,
    Extension(me): Extension<super::Device>,
) -> ApiResult<Device> {
    push(&app, me, None).await
}

async fn push(app: &App, me: super::Device, token: Option<(&str, bool)>) -> ApiResult<Device> {
    let set = set_push_token(&app.pool, me.0, token)
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => ApiError::bad_request(why),
            e => e.into(),
        })?;
    let device = crate::store::gov::get_device_key(&app.pool, me.0)
        .await?
        .filter(|_| set)
        .ok_or_else(|| ApiError::not_found("this device's key is gone"))?;
    Ok(Json(device.into()))
}
