//! Who is calling and what it talks to: the client's key check and version handshake. The
//! app calls `GET /api/v1/me` on connect: a 401 means the key is wrong or revoked; the
//! versions say which server it reached and whether the contract it was built for is there
//! (`api.minor`, see `types::API_MINOR`); `latest_seq` is where the event stream is now.

use axum::Json;
use axum::extract::{Extension, State};
use serde::Serialize;
use utoipa::ToSchema;

use super::model::Company;
use super::scope::Acting;
use super::types::API_MINOR;
use super::{ADMIN, ApiError, ApiResult, Device, companies, events};
use crate::api::App;
use crate::store::{gov, org};

/// A device or a user: who, by id and name.
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
    /// The runner protocol it speaks, `major.minor`.
    pub runner_protocol: String,
}

/// The calling device and what it may see.
#[derive(Debug, Serialize, ToSchema)]
pub struct Me {
    pub device: Named,
    /// The user it acts as: the one admin.
    pub user: Named,
    pub versions: Versions,
    /// The companies this key may see: every one, or only the acting one when
    /// `X-Citadel-Company` is sent.
    pub companies: Vec<Company>,
    /// The newest event's seq it would be shown (as `GET /api/v1/events/latest`).
    pub latest_seq: i64,
}

#[utoipa::path(get, path = "/api/v1/me", operation_id = "getMe", tag = "devices",
    responses((status = 200, description = "The calling device, its user, the server's and \
        the contract's versions, the companies it may see and the newest event seq: the key \
        check on connect", body = Me)))]
pub async fn me(
    State(app): State<App>,
    Extension(device): Extension<Device>,
    Extension(acting): Extension<Acting>,
) -> ApiResult<Me> {
    let key = gov::get_device_key(&app.pool, device.0)
        .await?
        .ok_or_else(|| ApiError::not_found("this device's key is gone"))?;
    let user: String = sqlx::query_scalar("SELECT name FROM users WHERE id = ?")
        .bind(ADMIN.0)
        .fetch_one(&app.pool)
        .await?;
    let all = org::list_companies(&app.pool).await?;
    let seen = all.into_iter().filter(|c| acting.sees(Some(c.id.0)));
    let companies = companies::with_accounts(&app, seen.collect()).await?.0;
    Ok(Json(Me {
        device: Named {
            id: key.id.0,
            name: key.name,
        },
        user: Named {
            id: ADMIN.0,
            name: user,
        },
        versions: Versions {
            server: env!("CARGO_PKG_VERSION").to_owned(),
            git_sha: option_env!("CITADEL_GIT_SHA").map(str::to_owned),
            api: ApiVersion {
                major: "v1".to_owned(),
                minor: API_MINOR,
            },
            runner_protocol: ainkrad_proto::runner::PROTOCOL_VERSION.to_owned(),
        },
        companies,
        latest_seq: events::latest_seq(&app, acting).await?,
    }))
}
