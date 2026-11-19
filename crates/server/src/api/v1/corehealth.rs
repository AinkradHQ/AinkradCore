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
use crate::hub::RunnerState;
use crate::scheduler::iso_of_unix;
use crate::store::gov;

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
    /// Resident memory of the Core process in bytes (the top bar's Core menu).
    #[schema(required = false)]
    pub memory_bytes: Option<u64>,
    /// Share of the data disk in use, 0 to 100, when the host says.
    #[schema(required = false)]
    pub disk_used_pct: Option<i64>,
    /// Size of the data disk in bytes.
    #[schema(required = false)]
    pub disk_total_bytes: Option<u64>,
    /// The whole host's CPU, 0 to 100, over the last minute (a Linux Core only).
    #[schema(required = false)]
    pub host_cpu_pct: Option<f64>,
    /// The host's memory in use and in total, in bytes (a Linux Core only).
    #[schema(required = false)]
    pub ram_used_bytes: Option<u64>,
    #[schema(required = false)]
    pub ram_total_bytes: Option<u64>,
    /// The data disk in use, in bytes.
    #[schema(required = false)]
    pub disk_used_bytes: Option<u64>,
    /// The runners at a glance.
    #[schema(required = false)]
    pub fleet: Option<Fleet>,
}

/// One runner of the fleet.
#[derive(Debug, Serialize, ToSchema)]
pub struct FleetRunner {
    pub name: String,
    /// `working` (online, commands in flight), `idle` (online, none) or `offline`.
    pub state: String,
    /// Commands in flight over what it takes at once, 0 to 100.
    pub busy_pct: Option<u32>,
}

/// How many runners are working, idle and offline.
#[derive(Debug, Serialize, ToSchema)]
pub struct Fleet {
    pub working: u32,
    pub idle: u32,
    pub offline: u32,
    pub runners: Vec<FleetRunner>,
}

/// The fleet from the paired runners and what the hub says of each now.
pub fn fleet_of(
    devices: &[gov::Device],
    live: &std::collections::HashMap<String, RunnerState>,
) -> Fleet {
    let mut f = Fleet {
        working: 0,
        idle: 0,
        offline: 0,
        runners: vec![],
    };
    for d in devices.iter().filter(|d| super::runners::listed(d)) {
        let s = live.get(&d.id).filter(|s| s.online);
        let (state, busy_pct) = match s {
            None => {
                f.offline += 1;
                ("offline", None)
            }
            Some(s) if s.load > 0 => {
                f.working += 1;
                ("working", busy(s))
            }
            Some(s) => {
                f.idle += 1;
                ("idle", busy(s))
            }
        };
        f.runners.push(FleetRunner {
            name: d.name.clone(),
            state: state.to_owned(),
            busy_pct,
        });
    }
    f
}

fn busy(s: &RunnerState) -> Option<u32> {
    (s.capacity > 0).then(|| u32::try_from((s.load * 100 / s.capacity).min(100)).unwrap_or(100))
}

#[utoipa::path(get, path = "/api/v1/core/health", operation_id = "getCoreHealth",
    tag = "system",
    responses((status = 200, description = "The Core's version, uptime, certificate end and \
        newest backup, as of at most five seconds ago. Needs `read`", body = CoreHealth)))]
pub async fn get(State(app): State<App>) -> ApiResult<CoreHealth> {
    let host = app.health.host().await;
    let r = &host.readings;
    let now = app.clock.unix();
    let at = |t: i64| ts(&iso_of_unix(t));
    let devices = gov::list_devices(&app.pool).await?;
    let fleet = fleet_of(&devices, &app.hub.runners());
    let latest = app.health.history().latest();
    Ok(Json(CoreHealth {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_secs: app.health.uptime_secs(),
        cert_not_after: r.cert_not_after.map(at),
        cert_days_left: r.cert_days_left(now),
        last_backup_at: r.backup_at.map(at),
        last_backup_bytes: r.backup_bytes,
        memory_bytes: host.rss_bytes,
        disk_used_pct: r.disk_free_pct().map(|f| 100 - f),
        disk_total_bytes: r.disk_total_bytes,
        host_cpu_pct: latest.and_then(|s| s.host_cpu_pct),
        ram_used_bytes: host.ram.map(|m| m.0),
        ram_total_bytes: host.ram.map(|m| m.1),
        disk_used_bytes: r
            .disk_total_bytes
            .zip(r.disk_free_bytes)
            .map(|(t, f)| t.saturating_sub(f)),
        fleet: Some(fleet),
    }))
}
