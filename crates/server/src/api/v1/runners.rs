//! Runners (E1-11.6): every paired runner with its live state from the hub (`crate::hub`), and
//! the no-op command end to end (`ainkradctl run noop`). A runner's presence also goes out as
//! the `runner.connected`, `runner.disconnected` and `runner.degraded` events.

use std::time::{Duration, Instant};

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_proto::v2::{ErrorCode, StreamError};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::auth::crypto::is_id;
use crate::hub::RunnerState;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::gov;

/// The audit action of a command sent through the API.
pub const COMMAND: &str = "runner.command";

/// How long `noop` waits for its answer (under the gateway's request deadline).
const NOOP_WAIT: Duration = Duration::from_secs(20);

/// A driver a runner offers, as it advertised it.
#[derive(Debug, Serialize, ToSchema)]
pub struct RunnerDriver {
    /// `exec` now; `pty`, `harness` later.
    pub name: Option<String>,
    /// The command ops it takes: `noop`, `exec.run`.
    pub commands: Option<Vec<String>>,
    /// How many of its commands run at once (`agent`: sessions).
    pub capacity: Option<u32>,
    /// `agent`: how many sessions each harness may run at once (E2-08.1); absent, no split.
    pub slots: Option<std::collections::BTreeMap<String, u32>>,
}

/// A paired runner and its live state.
#[derive(Debug, Serialize, ToSchema)]
pub struct Runner {
    /// The runner's device id, `d_…`.
    pub id: String,
    pub name: String,
    /// Connected to this Core now.
    pub online: Option<bool>,
    /// Connected but silent past two heartbeats.
    pub degraded: Option<bool>,
    /// Its last frame or request; null if never seen.
    pub last_seen: Option<Timestamp>,
    /// What it last advertised (empty until it first connected since the Core started).
    pub drivers: Option<Vec<RunnerDriver>>,
    /// Commands it takes at once.
    pub capacity: Option<u32>,
    /// Commands in flight.
    pub load: Option<u32>,
    /// Its `ainkrad-runner` version, once connected.
    pub version: Option<String>,
}

fn of(d: gov::Device, live: Option<&RunnerState>) -> Runner {
    let used = d.last_used_at.as_deref().and_then(unix_secs);
    let seen = live.map(|s| s.last_seen).into_iter().chain(used).max();
    let n = |v: usize| Some(u32::try_from(v).unwrap_or(u32::MAX));
    Runner {
        id: d.id,
        name: d.name,
        online: Some(live.is_some_and(|s| s.online)),
        degraded: Some(live.is_some_and(|s| s.degraded)),
        last_seen: seen.map(|t| ts(&iso_of_unix(t))),
        drivers: Some(
            live.map(|s| s.drivers.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|d| RunnerDriver {
                    name: Some(d.name),
                    commands: Some(d.commands),
                    capacity: Some(d.capacity),
                    slots: (!d.slots.is_empty()).then_some(d.slots),
                })
                .collect(),
        ),
        capacity: live.and_then(|s| n(s.capacity)),
        load: n(live.map_or(0, |s| s.load)),
        version: live.map(|s| s.version.clone()).filter(|v| !v.is_empty()),
    }
}

/// A runner device that may connect: approved and not revoked (a pending, rejected or expired
/// claimant is not a runner yet).
fn listed(d: &gov::Device) -> bool {
    d.kind == "runner" && d.usable()
}

#[utoipa::path(get, path = "/api/v1/runners", operation_id = "listRunners", tag = "runners",
    responses((status = 200, description = "Every paired runner that is active (approved, not \
        revoked), with its live state", body = Vec<Runner>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Runner>> {
    let live = app.hub.runners();
    let devices = gov::list_devices(&app.pool).await?;
    Ok(Json(
        devices
            .into_iter()
            .filter(listed)
            .map(|d| {
                let s = live.get(&d.id);
                of(d, s)
            })
            .collect(),
    ))
}

async fn one(app: &App, id: &str) -> Result<gov::Device, ApiError> {
    let found = match is_id(id, "d_") {
        true => gov::get_device(&app.pool, id).await?,
        false => None,
    };
    found
        .filter(listed)
        .ok_or_else(|| ApiError::not_found("no such runner"))
}

#[utoipa::path(get, path = "/api/v1/runners/{id}", operation_id = "getRunner", tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    responses((status = 200, description = "One runner and its live state", body = Runner)))]
pub async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Runner> {
    let d = one(&app, &id).await?;
    let live = app.hub.runners();
    Ok(Json(of(d, live.get(&id))))
}

/// The no-op's answer.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoopResult {
    /// The runner answered.
    pub ok: Option<bool>,
    /// From dispatch to answer.
    pub duration_ms: Option<u64>,
}

/// A failed command as an API error.
pub(super) fn failed(e: &StreamError) -> ApiError {
    let (status, code) = match e.code {
        ErrorCode::Offline => (StatusCode::CONFLICT, "runner_offline"),
        ErrorCode::UnsupportedCommand => (StatusCode::CONFLICT, "unsupported_command"),
        ErrorCode::Busy => (StatusCode::SERVICE_UNAVAILABLE, "runner_busy"),
        ErrorCode::Lost => (StatusCode::GATEWAY_TIMEOUT, "runner_lost"),
        _ => (StatusCode::BAD_GATEWAY, "runner_failed"),
    };
    ApiError::new(status, code, e.message.clone())
}

#[utoipa::path(post, path = "/api/v1/runners/{id}/noop", operation_id = "runNoop",
    tag = "runners",
    params(("id" = String, Path, description = "The runner's device id, `d_…`")),
    responses((status = 200, description = "The runner ran the no-op command (audited as \
        `runner.command`, once per caller, runner and outcome in a window). 409 `runner_offline` or `unsupported_command`, 503 `runner_busy`, \
        504 `runner_lost` or `runner_timeout`, 502 `runner_failed`", body = NoopResult)))]
pub async fn noop(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<NoopResult> {
    let d = one(&app, &id).await?;
    let started = Instant::now();
    let outcome = match tokio::time::timeout(NOOP_WAIT, app.hub.noop(&id)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(failed(&e)),
        Err(_) => Err(ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "runner_timeout",
            "the runner did not answer in time",
        )),
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    // The first call per caller, runner and outcome in a window is audited; the repeats are
    // counted in memory (`auth::refusals`, bounded), so a device that can call this at its
    // request rate cannot grow the permanent audit log (security review RH4).
    let key = format!("{COMMAND}:noop:{}:{id}:{}", me.device.id, outcome.is_ok());
    if !app.auth.refusals.note(&key, app.clock.unix()) {
        outcome?;
        return Ok(Json(NoopResult {
            ok: Some(true),
            duration_ms: Some(duration_ms),
        }));
    }
    let event = NewAuditEvent {
        actor: BY,
        action: COMMAND.to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: d.seq,
        }),
        details: json!({
            "runner": id,
            "op": "noop",
            "by_device": me.device.id,
            "ok": outcome.is_ok(),
            "duration_ms": duration_ms,
        })
        .to_string(),
    };
    crate::store::audit::append_one(&app.pool, &event).await?;
    outcome?;
    Ok(Json(NoopResult {
        ok: Some(true),
        duration_ms: Some(duration_ms),
    }))
}
