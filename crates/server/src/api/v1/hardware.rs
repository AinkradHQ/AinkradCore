//! Hardware (E15 §3.4): every paired runner as a machine the Core places work on (the Core host,
//! This Mac, remote runners), the pool's load and the pause controls. Reading is `read`, pausing
//! `admin`. Events: `hardware.changed {id}` (debounced to 5 s).
//!
//! F0: the contract and stubs (an empty list, an idle pool, 501 for a pause) so the App lane has
//! fixtures. The E15-1 lane fills them from `Hub::hardware()` and `core_hardware_prefs`.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::Timestamp;
use super::{ApiError, ApiResult};

/// What a machine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HardwareKind {
    /// The Core host (its built-in runner).
    Core,
    /// This Mac (the bundled runner).
    Mac,
    /// A remote runner.
    Runner,
}

/// Whether a machine takes jobs now, by its own measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HardwareGate {
    Open,
    Busy,
    OnBattery,
    Paused,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HardwareBattery {
    pub on_battery: bool,
    /// 0 to 100.
    pub percent: u8,
}

/// A job running on a machine now.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HardwareJob {
    /// `j_…`.
    pub id: String,
    /// The project id, absent for a job of a session with no project.
    pub project: Option<i64>,
    /// What it runs, `cargo build`.
    pub label: String,
    pub started_at: Timestamp,
}

/// One machine.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Hardware {
    /// The runner device, `d_…`.
    pub id: String,
    pub name: String,
    pub kind: HardwareKind,
    pub online: bool,
    pub degraded: bool,
    /// Paused on the Core until then; absent: not paused.
    pub paused_until: Option<Timestamp>,
    pub gate: HardwareGate,
    /// `linux`, `macos`.
    pub os: Option<String>,
    /// `aarch64`, `x86_64`.
    pub arch: Option<String>,
    pub cores: u32,
    /// 0 to 100, over 60 s.
    pub cpu_pct: u8,
    pub mem_total_mb: u64,
    pub mem_free_mb: u64,
    pub battery: Option<HardwareBattery>,
    /// Ready toolchains, name to version.
    pub toolchains: BTreeMap<String, String>,
    /// AI sessions live on it.
    pub sessions: u32,
    pub jobs: Vec<HardwareJob>,
    pub job_slots: u32,
}

/// The pool as a whole, for the top bar's load ring.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HardwarePool {
    /// Running jobs over all online job slots, 0 to 100.
    pub load_pct: u8,
    pub jobs: u32,
    pub sessions: u32,
    /// A pause-all is in effect.
    pub paused: bool,
}

/// `PUT …/pause`: until when; `null` lifts the pause.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HardwarePause {
    pub until: Option<Timestamp>,
}

fn not_yet() -> ApiError {
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        "hardware pause arrives with E15-1",
    )
}

#[utoipa::path(get, path = "/api/v1/hardware", operation_id = "listHardware", tag = "hardware",
    responses((status = 200, description = "Every paired machine the Core places work on, with its \
        live capacity. Needs `read`", body = Vec<Hardware>)))]
pub async fn list() -> ApiResult<Vec<Hardware>> {
    Ok(Json(Vec::new()))
}

#[utoipa::path(get, path = "/api/v1/hardware/pool", operation_id = "getHardwarePool",
    tag = "hardware",
    responses((status = 200, description = "The pool's load, jobs and sessions. Needs `read`",
        body = HardwarePool)))]
pub async fn pool() -> ApiResult<HardwarePool> {
    Ok(Json(HardwarePool {
        load_pct: 0,
        jobs: 0,
        sessions: 0,
        paused: false,
    }))
}

#[utoipa::path(put, path = "/api/v1/hardware/{id}/pause", operation_id = "pauseHardware",
    tag = "hardware", request_body = HardwarePause,
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    responses((status = 200, description = "The machine takes no new jobs or overflow sessions until \
        `until` (`null` lifts it); running work finishes. Needs `admin`", body = Hardware)))]
pub async fn pause(Path(id): Path<String>, Json(_): Json<HardwarePause>) -> ApiResult<Hardware> {
    let _ = id;
    Err(not_yet())
}

#[utoipa::path(put, path = "/api/v1/hardware/pause", operation_id = "pauseAllHardware",
    tag = "hardware", request_body = HardwarePause,
    responses((status = 200, description = "Every machine but the Core takes no new work until \
        `until` (`null` lifts it). Needs `admin`", body = HardwarePool)))]
pub async fn pause_all(Json(_): Json<HardwarePause>) -> ApiResult<HardwarePool> {
    Err(not_yet())
}
