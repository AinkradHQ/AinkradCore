//! Who is calling and what it talks to: the client's key check and version handshake. The
//! app calls `GET /api/v1/me` on connect: a 401 means the key is wrong or revoked; the
//! versions say which server it reached and whether the contract it was built for is there
//! (`api.minor`, see `types::API_MINOR`).

use axum::Json;
use axum::extract::{Extension, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::types::API_MINOR;
use super::{ApiError, ApiResult, Device};
use crate::api::App;
use crate::store::gov;

/// A device: who, by id and name.
#[derive(Debug, Serialize, ToSchema)]
pub struct Named {
    pub id: i64,
    pub name: String,
}

/// The contract a server speaks: `/api/<major>` and its additions so far.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiVersion {
    /// `v1`.
    pub major: String,
    /// Bumped on every additive change within the major.
    pub minor: u32,
}

/// What the server is and speaks.
#[derive(Debug, Serialize, ToSchema)]
pub struct Versions {
    /// The server's crate version, `0.1.0`.
    pub server: String,
    /// The commit it was built from (short sha), when the build knew it.
    pub git_sha: Option<String>,
    pub api: ApiVersion,
}

/// The calling device and what the server speaks.
#[derive(Debug, Serialize, ToSchema)]
pub struct Me {
    pub device: Named,
    pub versions: Versions,
}

#[utoipa::path(get, path = "/api/v1/me", operation_id = "getMe", tag = "devices",
    responses((status = 200, description = "The calling device and the server's and the \
        contract's versions: the key check on connect", body = Me)))]
pub async fn me(State(app): State<App>, Extension(device): Extension<Device>) -> ApiResult<Me> {
    let key = gov::get_device_key(&app.pool, device.0)
        .await?
        .ok_or_else(|| ApiError::not_found("this device's key is gone"))?;
    Ok(Json(Me {
        device: Named {
            id: key.id.0,
            name: key.name,
        },
        versions: Versions::current(),
    }))
}

impl Versions {
    /// This server's.
    pub fn current() -> Self {
        Self {
            server: env!("CARGO_PKG_VERSION").to_owned(),
            git_sha: option_env!("CITADEL_GIT_SHA").map(str::to_owned),
            api: ApiVersion {
                major: "v1".to_owned(),
                minor: API_MINOR,
            },
        }
    }
}
