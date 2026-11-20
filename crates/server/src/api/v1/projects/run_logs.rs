//! A running project's services and logs over the API (Core 0.9, P5-04; the runner's side is
//! `run.observe`, reached through `crate::runs::Link`).
//!
//! Security model. Logs are what a project's own code printed, so they may hold a secret. The
//! runner redacts every line before keeping it (the values of the leases it redeemed, key shapes,
//! PEM blocks); this Core redacts again before a line leaves it, with the values of the project's
//! current secrets (opened only here, only into a `Redactor`) and the shared key shapes, so a
//! runner restarted mid-run, or an older one, cannot leak what it forgot. Services (health, CPU,
//! memory, restarts) are `read`; logs and their WebSocket are `admin`. Nothing here starts or
//! stops anything: it only reads through the runner's read-only `run.observe`. Health checks
//! (`podman healthcheck run`) are the one thing a poll can cost the runner, so only the admin
//! routes ask for them (`health`); `services` reports what Podman last recorded. A device holds
//! at most [`MAX_LOGS_PER_DEVICE`] log sockets, and the upgrade is refused before it happens for
//! a bad request, a missing run or a full device.
//!
//! Limits of the masking: a secret under 8 bytes is not known to a `Redactor`; the values of the
//! secrets here are read once, when a socket opens, so one rotated while it is open is masked
//! only by the runner's pass (it is reopened on the next connect); a multi-line secret is masked
//! line by line, only where a line matches a key shape. The values live in the socket's
//! `Redactor`, which wipes them when it drops, and in `Zeroizing` strings while they are read.
//!
//! Field names for the app's Run page (`ProjectRunService`, ainkrad-core-app #156): its service
//! row is `name`, `state` (`up`/`down`/`exited` there; here Podman's `running`/`exited`/...),
//! `memory` (here `memory_bytes`), `cpu` (here `cpu_percent`), `restarts`, and a health badge
//! (here `health`: `none`/`starting`/`healthy`/`unhealthy`); a log line is `service` and `text`
//! (as here, plus `seq` and `at`).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{RunObserve, RunObserveReq, ServiceHealth};
use axum::Json;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use zeroize::Zeroizing;

use super::super::{ApiError, ApiResult, Caller};
use super::num;
use crate::api::App;
use crate::runs::{HubLink, Link, LinkError};
use crate::store::projects as projects_store;
use crate::store::runs::{self as store, Run};

/// A secret updated after this is never "newer than the caller": see `open_for_masking`.
const ANY_TIME: &str = "9999-12-31T23:59:59Z";
const TICK: Duration = Duration::from_millis(1500);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Log sockets one device may hold open at once: each polls the runner every tick.
const MAX_LOGS_PER_DEVICE: u32 = 4;

// ponytail: one process-wide table of open log sockets per device; move it into `App` if another
// feature needs the same kind of cap.
static OPEN: LazyLock<Mutex<HashMap<String, u32>>> = LazyLock::new(Mutex::default);

/// One open log socket of a device; released on drop (the socket ended, however it ended).
struct LogSlot(String);

impl LogSlot {
    /// A slot for `device`, or `None` at [`MAX_LOGS_PER_DEVICE`].
    fn reserve(device: &str) -> Option<Self> {
        let mut open = OPEN.lock().unwrap();
        let n = open.entry(device.to_owned()).or_default();
        if *n >= MAX_LOGS_PER_DEVICE {
            return None;
        }
        *n += 1;
        Some(Self(device.to_owned()))
    }
}

impl Drop for LogSlot {
    fn drop(&mut self) {
        let mut open = OPEN.lock().unwrap();
        if let Some(n) = open.get_mut(&self.0) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                open.remove(&self.0);
            }
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceInfo {
    pub name: String,
    /// Podman's state: `running`, `exited`, ...
    pub state: String,
    /// `none` (no health check), `starting`, `healthy` or `unhealthy`.
    pub health: String,
    /// Percent of one CPU; none while it is not running.
    pub cpu_percent: Option<f64>,
    pub memory_bytes: i64,
    /// The project's memory cap as Podman reports it; 0 when unknown.
    pub memory_limit_bytes: i64,
    pub restarts: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunServices {
    /// The live run these belong to; none (and no services) when the project is not running.
    pub run: Option<String>,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RunLogLine {
    /// Grows by one per line of the run; pass the last one as `after` to continue.
    pub seq: i64,
    pub service: String,
    /// When the container wrote it (RFC 3339).
    pub at: String,
    /// Redacted, at most 2048 bytes.
    pub text: String,
}

/// A page of lines; the WebSocket sends one per poll (only when it has lines or a gap).
#[derive(Debug, Serialize, ToSchema)]
pub struct RunLogs {
    pub run: Option<String>,
    pub lines: Vec<RunLogLine>,
    /// Ask again with `after` = this.
    pub next: i64,
    /// Lines before the first one that the runner had already dropped (a flood, or a slow reader).
    pub lost: i64,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogsQuery {
    /// Only this service's lines.
    pub service: Option<String>,
    /// Lines after this `seq`; default 0 (from the oldest the runner holds).
    pub after: Option<i64>,
    /// At most this many (default and most 500); the WebSocket ignores it.
    pub limit: Option<u32>,
    /// One of the project's live runs by id (a project can have one per configuration); default
    /// the newest live run.
    pub run: Option<String>,
}

/// Which live run `services` asks about.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ServicesQuery {
    /// One of the project's live runs by id; default the newest live run.
    pub run: Option<String>,
}

fn health(h: ServiceHealth) -> &'static str {
    match h {
        ServiceHealth::None => "none",
        ServiceHealth::Starting => "starting",
        ServiceHealth::Healthy => "healthy",
        ServiceHealth::Unhealthy => "unhealthy",
    }
}

fn big(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn link(app: &App) -> HubLink {
    HubLink(std::sync::Arc::clone(&app.hub))
}

async fn runner_error(app: &App, project: i64, e: LinkError) -> ApiError {
    let why = match e {
        LinkError::Offline => "the run's runner is offline".to_owned(),
        LinkError::Failed(m) => {
            let m = crate::runs::scrub(app, project, &m).await;
            m.chars().take(300).collect()
        }
    };
    ApiError::new(StatusCode::BAD_GATEWAY, "runner_error", why)
}

/// The project's live run; 404 when it has none.
async fn live_run(app: &App, project: i64, run: Option<&str>) -> Result<Option<Run>, ApiError> {
    projects_store::get(&mut *app.pool.acquire().await?, project)
        .await
        .map_err(ApiError::from)?;
    let Some(id) = run else {
        return Ok(store::live(&app.pool, project).await?);
    };
    Ok(store::live_list(&app.pool, project)
        .await?
        .into_iter()
        .find(|r| r.id == id))
}

/// What masks the project's secrets in a line: the values of its current secrets and the key
/// shapes. A secret that cannot be opened is skipped (the runner redacted its leases already).
pub(crate) async fn scrubber(app: &App, project: i64) -> Redactor {
    let mut red = Redactor::new();
    let (Some(sealer), Ok(mut conn)) = (&app.secrets, app.pool.acquire().await) else {
        return red;
    };
    let Ok(p) = projects_store::get(&mut conn, project).await else {
        return red;
    };
    let names = crate::store::project_secrets::names(&mut conn, &p)
        .await
        .unwrap_or_default();
    drop(conn);
    for name in names {
        let stored = format!("{}.{name}", p.slug);
        if let Ok(opened) = crate::store::secrets::open_for_masking(
            &app.pool,
            sealer,
            std::slice::from_ref(&stored),
            ANY_TIME,
        )
        .await
        {
            for (_, value) in opened {
                let value = Zeroizing::new(value);
                red.known(&name, &value);
            }
        }
    }
    red
}

fn page(run: &str, o: RunObserve, red: &Redactor) -> RunLogs {
    RunLogs {
        run: Some(run.to_owned()),
        lines: o
            .lines
            .into_iter()
            .map(|l| RunLogLine {
                seq: big(l.seq),
                service: l.service,
                at: l.at,
                text: red.text(&l.text),
            })
            .collect(),
        next: big(o.next),
        lost: big(o.lost),
    }
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run/services",
    operation_id = "getProjectRunServices", tag = "projects",
    params(("id" = String, Path, description = "The project's id"), ServicesQuery),
    responses((status = 200, description = "Health, CPU, memory and restarts of each service of \
        the live run, sampled every few seconds on its runner; none when the project is not \
        running. 404 for no such project; 502 `runner_error` when the runner cannot answer",
        body = RunServices)))]
pub async fn services(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<ServicesQuery>,
) -> ApiResult<RunServices> {
    let Some(run) = live_run(&app, num(&id, "project")?, q.run.as_deref()).await? else {
        return Ok(Json(RunServices {
            run: None,
            services: Vec::new(),
        }));
    };
    let req = RunObserveReq {
        run: run.id.clone(),
        after: 0,
        service: None,
        limit: Some(0),
        // Read scope: what Podman last recorded, never a health check run on this ask.
        health: false,
    };
    let o = match link(&app).observe(&run.runner, req).await {
        Ok(o) => o,
        Err(e) => return Err(runner_error(&app, run.project_id, e).await),
    };
    Ok(Json(RunServices {
        run: Some(run.id),
        services: o
            .services
            .into_iter()
            .map(|s| ServiceInfo {
                name: s.name,
                state: s.state,
                health: health(s.health).to_owned(),
                cpu_percent: s.cpu_percent,
                memory_bytes: big(s.memory_bytes),
                memory_limit_bytes: big(s.memory_limit_bytes),
                restarts: i64::from(s.restarts),
            })
            .collect(),
    }))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run/logs",
    operation_id = "getProjectRunLogs", tag = "projects",
    params(("id" = String, Path, description = "The project's id"), LogsQuery),
    responses((status = 200, description = "The newest log lines of the live run after `after`, \
        oldest first, redacted; empty when the project is not running. 404 for no such project; \
        502 `runner_error` when the runner cannot answer", body = RunLogs)))]
pub async fn logs(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> ApiResult<RunLogs> {
    let project = num(&id, "project")?;
    let Some(run) = live_run(&app, project, q.run.as_deref()).await? else {
        return Ok(Json(RunLogs {
            run: None,
            lines: Vec::new(),
            next: q.after.unwrap_or(0).max(0),
            lost: 0,
        }));
    };
    let req = RunObserveReq {
        run: run.id.clone(),
        after: u64::try_from(q.after.unwrap_or(0)).unwrap_or(0),
        service: q.service,
        limit: q.limit,
        health: true,
    };
    if let Some(why) = req.problem() {
        return Err(ApiError::bad_request(why));
    }
    let o = match link(&app).observe(&run.runner, req).await {
        Ok(o) => o,
        Err(e) => return Err(runner_error(&app, run.project_id, e).await),
    };
    Ok(Json(page(&run.id, o, &scrubber(&app, project).await)))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/run/logs/ws",
    operation_id = "streamProjectRunLogs", tag = "projects",
    params(("id" = String, Path, description = "The project's id"), LogsQuery),
    responses((status = 101, description = "Switching to a WebSocket: the live tail. Each text \
        frame is a `RunLogs` (only sent with lines or a gap), about every 1.5 s, from `after`. \
        Closed with 1000 `the run ended` when the run is no longer live, and 4001 when the \
        device was revoked. 404 for no such project or no live run. The upgrade is signed like \
        any request (no browser ticket)")))]
pub async fn logs_ws(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let project = match num(&id, "project") {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let run = match live_run(&app, project, q.run.as_deref()).await {
        Ok(Some(r)) => r,
        Ok(None) => return ApiError::not_found("the project has no live run").into_response(),
        Err(e) => return e.into_response(),
    };
    // Refused before the upgrade: a bad service name, and a device that has its sockets open.
    let probe = RunObserveReq {
        run: run.id.clone(),
        service: q.service.clone(),
        ..Default::default()
    };
    if let Some(why) = probe.problem() {
        return ApiError::bad_request(why).into_response();
    }
    let Some(slot) = LogSlot::reserve(&me.device.id) else {
        return ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_attaches",
            "this device already has its log streams open",
        )
        .into_response();
    };
    let after = u64::try_from(q.after.unwrap_or(0)).unwrap_or(0);
    let red = scrubber(&app, project).await;
    ws.on_upgrade(move |socket| tail(app, socket, project, run, q.service, after, red, me, slot))
}

#[allow(clippy::too_many_arguments)]
async fn tail(
    app: App,
    mut socket: WebSocket,
    project: i64,
    run: Run,
    service: Option<String>,
    mut after: u64,
    red: Redactor,
    me: Caller,
    _slot: LogSlot,
) {
    let link = link(&app);
    let mut tick = tokio::time::interval(TICK);
    let close = |code: u16, why: &'static str| {
        Message::Close(Some(CloseFrame {
            code,
            reason: why.into(),
        }))
    };
    loop {
        tokio::select! {
            _ = tick.tick() => {
                match crate::auth::device_now(&app.pool, &me.device.id, None).await {
                    crate::auth::DeviceNow::Usable => {}
                    _ => {
                        let _ = socket.send(close(4001, "the device was revoked")).await;
                        return;
                    }
                }
                // Still the same live run?
                match store::live(&app.pool, project).await {
                    Ok(Some(r)) if r.id == run.id => {}
                    Ok(_) => {
                        let _ = socket.send(close(1000, "the run ended")).await;
                        return;
                    }
                    Err(_) => continue,
                }
                let req = RunObserveReq {
                    run: run.id.clone(),
                    after,
                    service: service.clone(),
                    limit: None,
                    health: true,
                };
                // A runner that cannot answer this time is tried again at the next tick.
                let Ok(o) = link.observe(&run.runner, req).await else { continue };
                let moved = o.next;
                let batch = page(&run.id, o, &red);
                if batch.lines.is_empty() && batch.lost == 0 {
                    after = after.max(moved);
                    continue;
                }
                let text = serde_json::to_string(&batch).unwrap_or_default();
                match tokio::time::timeout(SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await {
                    Ok(Ok(())) => after = after.max(moved),
                    // Gone, or too slow to keep up: it reconnects with its last `seq`.
                    _ => return,
                }
            }
            msg = socket.recv() => match msg {
                None | Some(Err(_) | Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_redacted_again_before_it_leaves_the_core() {
        let mut red = Redactor::new();
        red.known("db", "hunter2-very-secret");
        let o = RunObserve {
            services: Vec::new(),
            lines: vec![ainkrad_proto::v2::LogLine {
                seq: 4,
                service: "web".into(),
                at: String::new(),
                text: "dsn=hunter2-very-secret key=sk-abcdefghijklmnopqrstuvwxyz0123".into(),
            }],
            next: 4,
            lost: 0,
        };
        let p = page("r1", o, &red);
        assert_eq!(
            p.lines[0].text,
            "dsn=[redacted:db] key=[redacted:openai_key]"
        );
        assert_eq!((p.next, p.lost), (4, 0));
    }

    #[test]
    fn a_device_holds_four_log_sockets_and_a_slot_frees_on_drop() {
        let slots: Vec<_> = (0..MAX_LOGS_PER_DEVICE)
            .map(|_| LogSlot::reserve("dev-cap-test").expect("under the cap"))
            .collect();
        assert!(LogSlot::reserve("dev-cap-test").is_none());
        // Another device is not affected.
        assert!(LogSlot::reserve("dev-cap-other").is_some());
        drop(slots);
        assert!(LogSlot::reserve("dev-cap-test").is_some());
        assert!(!OPEN.lock().unwrap().contains_key("dev-cap-other"));
    }

    #[test]
    fn a_request_with_a_bad_service_is_refused_before_the_upgrade() {
        let probe = RunObserveReq {
            run: "r1".into(),
            service: Some("a b".into()),
            ..Default::default()
        };
        assert!(probe.problem().is_some());
    }

    #[test]
    fn the_runner_is_asked_for_health_checks_only_by_the_admin_routes() {
        // The admin routes set `health: true`; `/run/services` leaves it off (see `services`).
        let read = RunObserveReq::default();
        assert!(!read.health);
        let json = serde_json::to_string(&read).unwrap();
        assert!(!json.contains("health"), "{json}");
    }
}
