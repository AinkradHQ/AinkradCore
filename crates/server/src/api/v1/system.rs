//! The Core machine (host-helper plan §4): what is installed and running on the Core's host, a
//! restart of the Core or the local runner, and the service logs, all through the root host
//! helper (`crate::host`). Every route is `admin`; a restart and the runner and backup logs are
//! also destructive (a step-up), the Core and helper logs are not (D4).
//!
//! A restart writes its audit row **before** the helper is asked (`host.restart_requested`) and the
//! outcome after (`host.action_result`). The helper answers a Core restart before systemd takes the
//! Core down (`--no-block`), so the 202 is sent from this process while it still runs.
//!
//! Nothing the caller sends reaches the helper but a closed choice (`target`, the unit of the path)
//! and, for logs, a line count in 1..=500 and a journal cursor of `[A-Za-z0-9=;_]{1,256}` that
//! does not start with `-`; the helper checks the same again.

use std::time::Duration;

use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};

use super::{ApiError, BY, Caller, too_many};
use crate::api::App;
use crate::host::{Actor, Failure, request_id};

pub const RESTART_REQUESTED: &str = "host.restart_requested";
pub const ACTION_RESULT: &str = "host.action_result";
pub const LOGS_READ: &str = "host.logs_read";
pub const HELPER_REFUSED: &str = "host.helper_refused";

/// `s` cut to `max` characters, every control character (an escape sequence, a newline) but a tab
/// replaced by `?`: text from a log or a unit goes to terminals and UIs.
fn plain(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
        .collect()
}

/// A JSON string as short, plain text.
fn short(v: &Value) -> Option<String> {
    v.as_str().map(|s| plain(s, 128))
}

/// A program installed on the host, as the helper's manifest and checks say.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostBinary {
    pub name: String,
    pub version: Option<String>,
    /// The first 12 hex characters of the file's SHA-256.
    pub sha256_12: Option<String>,
    /// `ok`, `differs` (not the file the manifest lists) or `unsafe` (a link, or writable).
    pub state: Option<String>,
}

/// A systemd unit.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostUnit {
    /// systemd's `ActiveState`: `active`, `inactive`, `failed`, `activating`…
    pub state: Option<String>,
    /// systemd's `SubState`: `running`, `dead`…
    pub sub: Option<String>,
    /// When it entered its state, as systemd prints it.
    pub since: Option<String>,
    pub restarts: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HostUnits {
    pub core: Option<HostUnit>,
    /// Absent when no local runner is installed.
    pub runner: Option<HostUnit>,
    pub backup_timer: Option<HostUnit>,
}

/// The Core machine as the host helper reports it.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostStatus {
    /// `present` (it answered), `absent` (no socket: not installed) or `error` (it did not answer
    /// well: stopped, busy, too slow, refused).
    pub helper: String,
    pub helper_version: Option<String>,
    /// The host's random id, set at install; an app pins it at first sight.
    pub host_id: Option<String>,
    /// `ok`, `absent` or `invalid`: the state of the root-written manifest of installed programs.
    pub manifest: Option<String>,
    pub binaries: Option<Vec<HostBinary>>,
    /// `/usr/local/bin` is root-owned and not group or other writable.
    pub bin_dir_safe: Option<bool>,
    pub units: Option<HostUnits>,
}

fn unit(v: &Value) -> Option<HostUnit> {
    v.is_object().then(|| HostUnit {
        state: short(&v["active"]),
        sub: short(&v["sub"]),
        since: short(&v["since"]),
        restarts: v["restarts"].as_u64(),
    })
}

fn status_of(helper: &str, r: Option<&Value>) -> HostStatus {
    let Some(r) = r else {
        return HostStatus {
            helper: helper.to_owned(),
            helper_version: None,
            host_id: None,
            manifest: None,
            binaries: None,
            bin_dir_safe: None,
            units: None,
        };
    };
    HostStatus {
        helper: helper.to_owned(),
        helper_version: short(&r["helper_version"]),
        host_id: short(&r["host_id"]),
        manifest: short(&r["manifest"]),
        binaries: r["binaries"].as_array().map(|a| {
            a.iter()
                .take(16)
                .map(|b| HostBinary {
                    name: short(&b["name"]).unwrap_or_default(),
                    version: short(&b["version"]),
                    sha256_12: short(&b["sha256_12"]),
                    state: short(&b["state"]),
                })
                .collect()
        }),
        bin_dir_safe: r["bin_dir_safe"].as_bool(),
        units: Some(HostUnits {
            core: unit(&r["units"]["core"]),
            runner: unit(&r["units"]["runner"]),
            backup_timer: unit(&r["units"]["backup_timer"]),
        }),
    }
}

/// An error answer, boxed so the `Err` of a handler stays small.
pub struct Fail(Box<Response>);

impl From<Response> for Fail {
    fn from(r: Response) -> Self {
        Self(Box::new(r))
    }
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        *self.0
    }
}

/// A helper failure as an API answer.
fn fail(f: Failure) -> Fail {
    let e = |s, c, m: &str| ApiError::new(s, c, m).into_response();
    let unavailable = || {
        e(
            StatusCode::SERVICE_UNAVAILABLE,
            "host_helper_unavailable",
            "the host helper is not available on this machine",
        )
    };
    let busy = || {
        e(
            StatusCode::SERVICE_UNAVAILABLE,
            "host_helper_busy",
            "the host helper is busy; try again",
        )
    };
    Fail::from(match f {
        Failure::Absent | Failure::Unavailable => unavailable(),
        Failure::Busy => busy(),
        Failure::Timeout => e(
            StatusCode::GATEWAY_TIMEOUT,
            "host_helper_timeout",
            "the host helper did not answer in time",
        ),
        Failure::Garbled => e(
            StatusCode::BAD_GATEWAY,
            "host_helper_failed",
            "the host helper answered badly",
        ),
        Failure::Refused { code, retry_after } => match code.as_str() {
            "rate_limited" => too_many(Duration::from_secs(retry_after.unwrap_or(60).min(3600))),
            "not_installed" => e(
                StatusCode::CONFLICT,
                "not_installed",
                "that service is not installed on this machine",
            ),
            "busy" => busy(),
            "state_unavailable" => e(
                StatusCode::SERVICE_UNAVAILABLE,
                "host_state_unavailable",
                "the host helper cannot keep its state; see the Core machine's recovery notes",
            ),
            "forbidden_peer" => unavailable(),
            _ => e(
                StatusCode::BAD_GATEWAY,
                "host_helper_failed",
                "the host helper refused the request",
            ),
        },
    })
}

/// A short, fixed word for an outcome in the audit log (`accepted`, a helper code, or the kind of
/// failure); never text from the helper.
fn outcome(f: &Failure) -> String {
    match f {
        Failure::Absent => "absent".into(),
        Failure::Unavailable => "unavailable".into(),
        Failure::Busy => "busy".into(),
        Failure::Timeout => "timeout".into(),
        Failure::Garbled => "garbled".into(),
        Failure::Refused { code, .. } => code
            .chars()
            .filter(|c| c.is_ascii_lowercase() || *c == '_')
            .collect(),
    }
}

fn internal(e: sqlx::Error) -> Fail {
    ApiError::from(e).into_response().into()
}

async fn audit(
    app: &App,
    me: &Caller,
    action: &str,
    details: Value,
) -> Result<ainkrad_core::audit::AuditEvent, sqlx::Error> {
    let event = NewAuditEvent {
        actor: BY,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "device".to_owned(),
            id: me.device.seq,
        }),
        details: details.to_string(),
    };
    crate::store::audit::append_one(&app.pool, &event).await
}

#[utoipa::path(get, path = "/api/v1/system/host", operation_id = "getHostStatus", tag = "system",
    responses((status = 200, description = "The Core machine: the programs installed, their \
        state against the root-written manifest, and the Core, runner and backup units. \
        `helper` says whether the host helper answered (`absent`: not installed here; `error`: \
        it is stopped, busy or failing); the rest is then missing. Needs `admin`", body = HostStatus)))]
pub async fn host(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> Result<Json<HostStatus>, Fail> {
    let actor = Actor {
        device: me.device.id.clone(),
        audit_seq: 0,
    };
    match app
        .host_helper
        .call(&request_id(), "status", json!({}), &actor)
        .await
    {
        Ok(r) => Ok(Json(status_of("present", Some(&r)))),
        Err(Failure::Absent) => Ok(Json(status_of("absent", None))),
        Err(f) => {
            refused(&app, &me, "status", &f).await;
            Ok(Json(status_of("error", None)))
        }
    }
}

/// Audits a helper refusal once per caller, action and outcome in a window (a flood of the same
/// one is counted in memory, not in the permanent log).
async fn refused(app: &App, me: &Caller, action: &str, f: &Failure) {
    let word = outcome(f);
    let key = format!("{HELPER_REFUSED}:{}:{action}:{word}", me.device.id);
    if !app.auth.refusals.note(&key, app.clock.unix()) {
        return;
    }
    let details = json!({"action": action, "code": word, "by_device": me.device.id});
    if let Err(e) = audit(app, me, HELPER_REFUSED, details).await {
        tracing::error!(error = %e, "auditing a host helper refusal failed");
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RestartBody {
    /// `core` or `runner` (the local runner).
    pub target: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Restarted {
    /// The id the restart is audited under (`host.restart_requested`, `host.action_result`).
    pub request_id: String,
}

#[utoipa::path(post, path = "/api/v1/system/restart", operation_id = "restartHostService",
    tag = "system", request_body = RestartBody,
    responses((status = 202, description = "The restart is accepted (audited first as \
        `host.restart_requested`, then `host.action_result`). A Core restart answers before the \
        Core goes down; clients reconnect. A 429 or any failure holds the same restart back for a \
        while (`Retry-After` on a 429). Do not retry a 504 on your own: a retry is a new request \
        the helper cannot tell from the first. Needs `admin` and a step-up. 400 for a body other \
        than `{\"target\": \"core\" | \"runner\"}`; 409 `not_installed` (no local runner); 429 \
        with `Retry-After` (the helper's limits); 503 `host_helper_unavailable`, \
        `host_helper_busy` or `host_state_unavailable`; 504 `host_helper_timeout`; 502 \
        `host_helper_failed`", body = Restarted)))]
pub async fn restart(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> Result<(StatusCode, Json<Restarted>), Fail> {
    let action = match serde_json::from_slice::<RestartBody>(&body)
        .ok()
        .as_ref()
        .map(|b| b.target.as_str())
    {
        Some("core") => "restart_core",
        Some("runner") => "restart_runner",
        _ => {
            return Err(
                ApiError::bad_request("the body is {\"target\": \"core\" or \"runner\"}")
                    .into_response()
                    .into(),
            );
        }
    };
    // The helper refused this lately (or failed): answer from memory, with no new audit row per
    // call. The first refusal in a window is audited, the rest are counted (`refusals`).
    let now = u64::try_from(app.clock.unix()).unwrap_or(0);
    if let Some(f) = app.host_helper.blocked(action, now) {
        refused(&app, &me, action, &f).await;
        return Err(fail(f));
    }
    let id = request_id();
    // The row first: a helper that refuses, or a Core that goes down, leaves the request behind.
    let row = audit(
        &app,
        &me,
        RESTART_REQUESTED,
        json!({"target": &action[8..], "request_id": id, "by_device": me.device.id}),
    )
    .await
    .map_err(internal)?;
    let actor = Actor {
        device: me.device.id.clone(),
        audit_seq: u64::try_from(row.seq.0).unwrap_or(0),
    };
    let result = app.host_helper.call(&id, action, json!({}), &actor).await;
    let code = match &result {
        Ok(_) => "accepted".to_owned(),
        Err(f) => outcome(f),
    };
    // Hold the action back so a loop of requests cannot grow the audit log: the helper's wait, or
    // its 60 s minimum between two Core restarts, else a short back-off after any failure.
    match &result {
        Ok(_) if action == "restart_core" => {
            let why = Failure::Refused {
                code: "rate_limited".into(),
                retry_after: Some(60),
            };
            app.host_helper.block(action, now, 60, why);
        }
        Err(f) => {
            let secs = match f {
                Failure::Refused { code, retry_after } if code == "rate_limited" => {
                    retry_after.unwrap_or(60).clamp(1, 3600)
                }
                _ => 10,
            };
            app.host_helper.block(action, now, secs, f.clone());
        }
        Ok(_) => {}
    }
    let details = json!({"request_id": id, "action": action, "code": code});
    if let Err(e) = audit(&app, &me, ACTION_RESULT, details).await {
        tracing::error!(error = %e, request_id = id, "auditing a host action result failed");
    }
    match result {
        Ok(_) => Ok((StatusCode::ACCEPTED, Json(Restarted { request_id: id }))),
        Err(f) => Err(fail(f)),
    }
}

/// A page of a service's log, redacted by the helper, newest entries at the end.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LogLine {
    pub at: Option<String>,
    pub level: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LogPage {
    pub lines: Vec<LogLine>,
    /// Pass as `before` for the next older page; absent on the last.
    pub next_before: Option<String>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogQuery {
    /// 1 to 500, default 200.
    pub lines: Option<i64>,
    /// A cursor from `next_before`: `[A-Za-z0-9=;_]`, 1 to 256 characters, not starting with `-`.
    pub before: Option<String>,
}

/// The helper's own cursor rule (`wire::valid_cursor`).
fn valid_cursor(c: &str) -> bool {
    (1..=256).contains(&c.len())
        && !c.starts_with('-')
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b'_'))
}

async fn logs(
    app: App,
    me: Caller,
    unit: &'static str,
    q: LogQuery,
) -> Result<Json<LogPage>, Fail> {
    let lines = q.lines.unwrap_or(200);
    if !(1..=500).contains(&lines) {
        return Err(ApiError::bad_request("lines is 1 to 500")
            .into_response()
            .into());
    }
    if q.before.as_deref().is_some_and(|c| !valid_cursor(c)) {
        return Err(ApiError::bad_request("before is not a log cursor")
            .into_response()
            .into());
    }
    let mut params = json!({"unit": unit, "lines": lines});
    if let Some(c) = &q.before {
        params["before"] = json!(c);
    }
    let actor = Actor {
        device: me.device.id.clone(),
        audit_seq: 0,
    };
    let page = match app
        .host_helper
        .call(&request_id(), "logs", params, &actor)
        .await
    {
        Ok(r) => {
            let mut page =
                serde_json::from_value::<LogPage>(r).map_err(|_| fail(Failure::Garbled))?;
            // What the helper sends is plain, bounded text and a cursor the next request could send.
            for l in &mut page.lines {
                l.at = l.at.as_deref().map(|s| plain(s, 40));
                l.level = l.level.as_deref().map(|s| plain(s, 16));
                l.text = l.text.as_deref().map(|s| plain(s, 4096));
            }
            page.next_before = page.next_before.filter(|c| valid_cursor(c));
            page
        }
        Err(f) => {
            refused(&app, &me, "logs", &f).await;
            return Err(fail(f));
        }
    };
    // Fail closed: logs that cannot be audited are not handed out.
    let details = json!({"unit": unit, "lines": page.lines.len(), "by_device": me.device.id});
    audit(&app, &me, LOGS_READ, details)
        .await
        .map_err(internal)?;
    Ok(Json(page))
}

macro_rules! log_route {
    ($name:ident, $id:literal, $unit:literal, $gate:literal) => {
        #[utoipa::path(get, path = concat!("/api/v1/system/logs/", $unit), operation_id = $id,
            tag = "system", params(LogQuery),
            responses((status = 200, description = concat!("A page of the ", $unit, " log, \
                redacted by the host helper (audited as `host.logs_read`, the unit and the line \
                count only). ", $gate, " 400 for `lines` outside 1 to 500 or a bad cursor; \
                503 `host_helper_unavailable` or `host_helper_busy`; 429 with `Retry-After`"),
                body = LogPage)))]
        pub async fn $name(
            State(app): State<App>,
            Extension(me): Extension<Caller>,
            Query(q): Query<LogQuery>,
        ) -> Result<Json<LogPage>, Fail> {
            logs(app, me, $unit, q).await
        }
    };
}

log_route!(logs_core, "getCoreLogs", "core", "Needs `admin`.");
log_route!(logs_helper, "getHelperLogs", "helper", "Needs `admin`.");
log_route!(
    logs_runner,
    "getRunnerLogs",
    "runner",
    "Needs `admin` and a step-up: these logs can hold values no redactor can recognise."
);
log_route!(
    logs_backup,
    "getBackupLogs",
    "backup",
    "Needs `admin` and a step-up: these logs can hold values no redactor can recognise."
);
