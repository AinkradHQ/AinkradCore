//! Who is calling and what it talks to: the client's signature check and version handshake.
//! The app calls `GET /api/v1/me` on connect: a 401 means the device or its session is no
//! good; the versions say which server it reached and whether the contract it was built for is there
//! (`api.minor`, see `types::API_MINOR`).

use axum::Json;
use axum::extract::Extension;
use serde::Serialize;
use utoipa::ToSchema;

use super::types::API_MINOR;
use super::{ApiResult, Caller};

/// A device: who, by id and name.
#[derive(Debug, Serialize, ToSchema)]
pub struct Named {
    /// `d_` and 26 characters.
    pub id: String,
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
        contract's versions: the signature check on connect", body = Me)))]
pub async fn me(Extension(me): Extension<Caller>) -> ApiResult<Me> {
    Ok(Json(Me {
        device: Named {
            id: me.device.id,
            name: me.device.name,
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
