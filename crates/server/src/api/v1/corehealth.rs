//! The Core's own health for the App's Home widgets: its version and uptime, its certificate's end
//! and the newest backup. Read from the same host snapshot as the metrics (`crate::health`), so a
//! polling client cannot make the Core re-read the disk on every request.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::ApiResult;
use super::types::{Timestamp, ts};
use crate::api::App;
use crate::scheduler::iso_of_unix;

/// What the Core can say about itself. A field it cannot know (no certificate on a loopback
/// Core, no backup yet) is absent.
#[derive(Debug, Serialize, ToSchema)]
pub struct CoreHealth {
    /// The server's crate version.
    pub version: String,
    /// Seconds since this Core process started.
    pub uptime_secs: u64,
    /// When the public certificate ends.
    pub cert_not_after: Option<Timestamp>,
    /// Whole days until then; negative once it has ended.
    pub cert_days_left: Option<i64>,
    /// When the newest backup (`<home>/backups/*.age`) was written.
    pub last_backup_at: Option<Timestamp>,
    /// That backup's size in bytes.
    pub last_backup_bytes: Option<u64>,
}

#[utoipa::path(get, path = "/api/v1/core/health", operation_id = "getCoreHealth",
    tag = "system",
    responses((status = 200, description = "The Core's version, uptime, certificate end and \
        newest backup, as of at most five seconds ago. Needs `read`", body = CoreHealth)))]
pub async fn get(State(app): State<App>) -> ApiResult<CoreHealth> {
    let r = &app.health.host().await.readings;
    let now = app.clock.unix();
    let at = |t: i64| ts(&iso_of_unix(t));
    Ok(Json(CoreHealth {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_secs: app.health.uptime_secs(),
        cert_not_after: r.cert_not_after.map(at),
        cert_days_left: r.cert_days_left(now),
        last_backup_at: r.backup_at.map(at),
        last_backup_bytes: r.backup_bytes,
    }))
}
