//! Lockouts (handshake spec §11, E1-09.4): the persisted locks (`store::gov::limits`) are listed
//! for an admin and can be cleared with a step-up. A key is `ip:<address>`,
//! `ipdev:<address>:<device>` or `stepup:<device>`; it travels in the body, since an IPv6 key
//! holds `::/64`. Clearing also forgets the in-memory counters behind it, and is audited as
//! `auth.lockout_cleared`.

use axum::Json;
use axum::extract::{Extension, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::scheduler::iso_of_unix;
use crate::store::gov;

/// Locks listed at most.
const LIST_MAX: u32 = 1000;

/// A key that is locked now.
#[derive(Debug, Serialize, ToSchema)]
pub struct Lockout {
    /// `ip:<address>`, `ipdev:<address>:<device>` or `stepup:<device>`.
    pub key: String,
    pub locked_until: Timestamp,
    /// Locks in a row; each doubles the next.
    pub strikes: i64,
}

#[utoipa::path(get, path = "/api/v1/auth/lockouts", operation_id = "listLockouts",
    tag = "devices",
    responses((status = 200, description = "Every key locked now, the longest lock first (at \
        most 1000)", body = Vec<Lockout>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Lockout>> {
    let locks = gov::list_lockouts(&app.pool, app.clock.unix(), LIST_MAX).await?;
    Ok(Json(
        locks
            .into_iter()
            .map(|l| Lockout {
                key: l.key,
                locked_until: ts(&iso_of_unix(l.locked_until)),
                strikes: l.strikes,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearLockout {
    /// The key, exactly as listed.
    pub key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Cleared {
    pub key: String,
}

#[utoipa::path(post, path = "/api/v1/auth/lockouts/clear", operation_id = "clearLockout",
    tag = "devices", request_body = ClearLockout,
    responses((status = 200, description = "The key's lock, counters and strikes are gone \
        (audited as `auth.lockout_cleared`); 404 when nothing is recorded for it",
        body = Cleared)))]
pub async fn clear(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<ClearLockout>,
) -> ApiResult<Cleared> {
    if b.key.len() > 256 {
        return Err(ApiError::bad_request("a key is at most 256 bytes"));
    }
    if !gov::clear_lockout(&app.pool, &b.key, BY, &me.device.id).await? {
        return Err(ApiError::not_found("no such key"));
    }
    if let Some(device) = b.key.strip_prefix("stepup:") {
        app.auth.stepup_failures.clear(device);
    } else if b.key.starts_with("ip:") {
        app.auth.failures.forget(&b.key);
    }
    tracing::info!(device = me.device.id, "lockout cleared");
    Ok(Json(Cleared { key: b.key }))
}
