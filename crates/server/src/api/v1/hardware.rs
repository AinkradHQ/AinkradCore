//! Hardware (E15 §3.4): every paired runner as a machine the Core places work on (the Core host,
//! This Mac, remote runners), the pool's load and the pause controls. Reading is `read`, pausing
//! `admin`. Events: `hardware.changed {id}` (debounced to 5 s).
//!
//! Filled (E15-1) from `Hub::hardware()` joined with `core_hardware_prefs` (`hardware::view`).
//! Pause-all writes a pause for every paired machine but the Core host, and the same pause on the
//! Core host's own row, which is the pool's pause and so reaches a runner paired later (the Core is
//! never paused itself; its row has no other meaning). Pause and resume are audited.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_proto::v2::{Gate, HwKind, Os};

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::hardware::view::{self, Machine};
use crate::scheduler::{iso_of_unix, unix_secs};

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

/// `PUT …/pause`: until when; `null` lifts the pause, and any time in the year 2100 or later means
/// indefinitely.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HardwarePause {
    pub until: Option<Timestamp>,
}

fn os_name(os: Os) -> Option<String> {
    match os {
        Os::Linux => Some("linux".into()),
        Os::Macos => Some("macos".into()),
        Os::Unknown => None,
    }
}

fn shown(m: Machine) -> Hardware {
    let v = m.view;
    let c = v.capacity.clone().unwrap_or_default();
    Hardware {
        id: v.device,
        name: v.name,
        kind: match v.kind {
            HwKind::Core => HardwareKind::Core,
            HwKind::Mac => HardwareKind::Mac,
            _ => HardwareKind::Runner,
        },
        online: v.online,
        degraded: v.degraded,
        // The Core row's pause is the pool's, shown by `/hardware/pool`.
        paused_until: m
            .paused_until
            .as_deref()
            .filter(|_| v.kind != HwKind::Core)
            .map(ts),
        gate: match (v.online, c.gate) {
            (false, _) => HardwareGate::Off,
            (_, Gate::Open) => HardwareGate::Open,
            (_, Gate::Busy) => HardwareGate::Busy,
            (_, Gate::OnBattery) => HardwareGate::OnBattery,
            (_, Gate::Paused) => HardwareGate::Paused,
            _ => HardwareGate::Off,
        },
        os: v.os.and_then(os_name),
        arch: v
            .arch
            .map(|a| format!("{a:?}").to_lowercase())
            .filter(|a| a != "unknown"),
        cores: c.cores,
        cpu_pct: c.cpu_pct,
        mem_total_mb: c.mem_total_mb,
        mem_free_mb: c.mem_free_mb,
        battery: c.battery.map(|b| HardwareBattery {
            on_battery: b.on_battery,
            percent: b.percent,
        }),
        toolchains: c.toolchains,
        sessions: v.sessions,
        jobs: m
            .jobs
            .into_iter()
            .map(|j| HardwareJob {
                id: j.id,
                project: j.project,
                label: j.label,
                started_at: ts(&j.started_at),
            })
            .collect(),
        job_slots: v.job_slots,
    }
}

/// The pool over `machines`: running jobs over every online job slot.
fn pool_of(machines: &[Machine]) -> HardwarePool {
    let online = || machines.iter().filter(|m| m.view.online);
    let slots: u32 = online().map(|m| m.view.job_slots).sum();
    let jobs: u32 = machines.iter().map(|m| m.view.jobs).sum();
    let remote: Vec<_> = machines
        .iter()
        .filter(|m| m.view.kind != HwKind::Core)
        .collect();
    let global = machines
        .iter()
        .any(|m| m.view.kind == HwKind::Core && m.paused_until.is_some());
    HardwarePool {
        load_pct: if slots == 0 {
            0
        } else {
            u8::try_from((jobs * 100 / slots).min(100)).unwrap_or(100)
        },
        jobs,
        sessions: machines.iter().map(|m| m.view.sessions).sum(),
        paused: global || (!remote.is_empty() && remote.iter().all(|m| m.paused_until.is_some())),
    }
}

#[utoipa::path(get, path = "/api/v1/hardware", operation_id = "listHardware", tag = "hardware",
    responses((status = 200, description = "Every paired machine the Core places work on, with its \
        live capacity. Needs `read`", body = Vec<Hardware>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Hardware>> {
    Ok(Json(
        view::machines(&app).await?.into_iter().map(shown).collect(),
    ))
}

#[utoipa::path(get, path = "/api/v1/hardware/pool", operation_id = "getHardwarePool",
    tag = "hardware",
    responses((status = 200, description = "The pool's load, jobs and sessions. Needs `read`",
        body = HardwarePool)))]
pub async fn pool(State(app): State<App>) -> ApiResult<HardwarePool> {
    Ok(Json(pool_of(&view::machines(&app).await?)))
}

/// The stored `until` of a pause: `None` lifts it; a time in the past is refused.
fn until_of(app: &App, p: &HardwarePause) -> Result<Option<String>, ApiError> {
    let Some(t) = &p.until else { return Ok(None) };
    match unix_secs(t.as_str()) {
        Some(secs) if secs > app.clock.unix() => Ok(Some(iso_of_unix(secs))),
        Some(_) => Err(ApiError::bad_request("`until` must be in the future")),
        None => Err(ApiError::bad_request("`until` is not an ISO-8601 UTC time")),
    }
}

/// `hardware.paused` or `hardware.resumed`, for one device (`Some(id, seq)`) or the pool (`None`).
async fn audit_pause(
    app: &App,
    me: &Caller,
    device: Option<(&str, i64)>,
    until: Option<&str>,
) -> Result<(), ApiError> {
    let event = NewAuditEvent {
        actor: BY,
        action: if until.is_some() {
            "hardware.paused"
        } else {
            "hardware.resumed"
        }
        .to_owned(),
        entity: device.map(|(_, seq)| AuditEntity {
            kind: "device".to_owned(),
            id: seq,
        }),
        details: serde_json::json!({
            "device": device.map_or("all", |d| d.0),
            "until": until,
            "by_device": me.device.id,
        })
        .to_string(),
    };
    crate::store::audit::append_one(&app.pool, &event).await?;
    Ok(())
}

async fn set_pause(app: &App, ids: &[String], until: Option<&str>) -> Result<(), ApiError> {
    let mut tx = crate::store::begin_write(&app.pool).await?;
    for id in ids {
        sqlx::query(
            "INSERT INTO core_hardware_prefs (device_id, paused_until) VALUES (?, ?) \
             ON CONFLICT(device_id) DO UPDATE SET paused_until = excluded.paused_until",
        )
        .bind(id)
        .bind(until)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    for id in ids {
        app.hub.hw_touch(id);
    }
    Ok(())
}

#[utoipa::path(put, path = "/api/v1/hardware/{id}/pause", operation_id = "pauseHardware",
    tag = "hardware", request_body = HardwarePause,
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    responses((status = 200, description = "The machine takes no new jobs or overflow sessions until \
        `until` (`null` lifts it); running work finishes. 400 for the Core host or a past `until`, \
        404 for no such machine. Needs `admin`", body = Hardware)))]
pub async fn pause(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(p): Json<HardwarePause>,
) -> ApiResult<Hardware> {
    let until = until_of(&app, &p)?;
    let all = view::machines(&app).await?;
    match all.iter().find(|m| m.view.device == id) {
        None => return Err(ApiError::not_found("no such machine")),
        Some(m) if m.view.kind == HwKind::Core => {
            return Err(ApiError::bad_request("the Core host cannot be paused"));
        }
        Some(_) => {}
    }
    set_pause(&app, &[id.clone()], until.as_deref()).await?;
    let seq = crate::store::gov::get_device(&app.pool, &id)
        .await?
        .map_or(0, |d| d.seq);
    audit_pause(&app, &me, Some((&id, seq)), until.as_deref()).await?;
    let m = view::machines(&app)
        .await?
        .into_iter()
        .find(|m| m.view.device == id)
        .ok_or_else(|| ApiError::not_found("no such machine"))?;
    Ok(Json(shown(m)))
}

#[utoipa::path(put, path = "/api/v1/hardware/pause", operation_id = "pauseAllHardware",
    tag = "hardware", request_body = HardwarePause,
    responses((status = 200, description = "Every machine but the Core takes no new work until \
        `until` (`null` lifts it). Needs `admin`", body = HardwarePool)))]
pub async fn pause_all(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(p): Json<HardwarePause>,
) -> ApiResult<HardwarePool> {
    let until = until_of(&app, &p)?;
    let ids: Vec<String> = view::machines(&app)
        .await?
        .into_iter()
        .map(|m| m.view.device)
        .collect();
    // The Core host's row is the pool's pause: it reaches a runner paired later too.
    set_pause(&app, &ids, until.as_deref()).await?;
    audit_pause(&app, &me, None, until.as_deref()).await?;
    Ok(Json(pool_of(&view::machines(&app).await?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::place::HwView;
    use ainkrad_proto::v2::Capacity;

    fn m(kind: HwKind, jobs: u32, slots: u32, online: bool, paused: bool) -> Machine {
        Machine {
            view: HwView {
                device: "d".into(),
                name: "d".into(),
                kind,
                online,
                degraded: false,
                paused,
                os: None,
                arch: None,
                capacity: Some(Capacity::default()),
                sessions: 1,
                jobs,
                job_slots: slots,
                sustained_full: false,
            },
            paused_until: paused.then(|| "9999-12-31T00:00:00.000Z".to_owned()),
            jobs: Vec::new(),
        }
    }

    #[test]
    fn the_pool_is_jobs_over_online_slots_and_paused_when_every_remote_is() {
        let all = [
            m(HwKind::Core, 1, 2, true, false),
            m(HwKind::Runner, 1, 2, true, true),
            m(HwKind::Mac, 0, 4, false, true),
        ];
        let p = pool_of(&all);
        // 2 jobs over the 4 slots of the two online machines.
        assert_eq!((p.load_pct, p.jobs, p.sessions, p.paused), (50, 2, 3, true));
        let p = pool_of(&[
            m(HwKind::Core, 0, 1, true, false),
            m(HwKind::Runner, 0, 1, true, false),
        ]);
        assert!(!p.paused);
        assert!(
            !pool_of(&[m(HwKind::Core, 0, 1, true, false)]).paused,
            "no remote is not a pause"
        );
        assert_eq!(pool_of(&[]).load_pct, 0);
        // The pool's pause (the Core row) holds with no runner at all.
        assert!(pool_of(&[m(HwKind::Core, 0, 1, true, true)]).paused);
        assert_eq!(pool_of(&[m(HwKind::Core, 9, 2, true, false)]).load_pct, 100);
    }
}
