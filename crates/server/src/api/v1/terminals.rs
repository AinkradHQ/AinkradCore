//! Terminal service. Content is transport-only; lifecycle metadata is the only persisted data.
use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::hub::Dispatched;
use crate::scheduler::iso_of_unix;
use crate::store::{self, gov};
use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::v2::{Body, Command, Control, Frame, PtyAttach, PtyClose, PtyOpen, SignalReq};
use ainkrad_proto::v2::{Reply, SIGNAL_HOST_LOST, TerminalInfo};
use axum::{
    Json,
    extract::ws::{CloseFrame, Message, WebSocket},
    extract::{Extension, Path, Query, State, WebSocketUpgrade},
    response::{IntoResponse, Response},
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::Instant;
use utoipa::ToSchema;

const MAX_INPUT: usize = 64 * 1024;
/// One WebSocket message: base64 of the largest input, with its frame around it.
const MAX_WS_MESSAGE: usize = 128 * 1024;
/// Typed bytes one socket may send per second; past it input is dropped, so one script cannot
/// fill the runner's shared queue.
const INPUT_PER_SEC: usize = 256 * 1024;
const OPEN_WAIT: Duration = Duration::from_secs(15);
const CLOSE_WAIT: Duration = Duration::from_secs(30);
/// How long an exited terminal stays listed before it is reaped.
const KEEP_EXITED: i64 = 3600;
/// How often the idle reaper looks (`sweep_loop`).
const SWEEP_EVERY: Duration = Duration::from_secs(30);

/// What the terminal service keeps in memory (never terminal content).
#[derive(Default)]
pub struct Rooms {
    /// One create at a time, so the caps are checked and used up under one lock.
    // ponytail: a global create lock; per-runner locks if create latency ever matters.
    create: tokio::sync::Mutex<()>,
    /// The stream that watches each running terminal for its exit.
    monitors: Mutex<HashMap<String, tokio::task::AbortHandle>>,
    /// Per terminal: the client that typed last, and how many clients are attached.
    rooms: Mutex<HashMap<String, (Option<u64>, u32)>>,
    next_client: AtomicU64,
}

impl Rooms {
    fn join(&self, terminal: &str) -> u64 {
        self.rooms
            .lock()
            .unwrap()
            .entry(terminal.to_owned())
            .or_default()
            .1 += 1;
        self.next_client.fetch_add(1, Ordering::Relaxed)
    }
    fn leave(&self, terminal: &str) {
        let mut all = self.rooms.lock().unwrap();
        if let Some(r) = all.get_mut(terminal) {
            r.1 = r.1.saturating_sub(1);
            if r.1 == 0 {
                all.remove(terminal);
            }
        }
    }
    fn attached(&self, terminal: &str) -> u32 {
        self.rooms.lock().unwrap().get(terminal).map_or(0, |r| r.1)
    }
    fn typed(&self, terminal: &str, client: u64) {
        if let Some(r) = self.rooms.lock().unwrap().get_mut(terminal) {
            r.0 = Some(client);
        }
    }
    /// Spec §4.4: the size follows the most recent typist; a lone client always resizes.
    fn may_resize(&self, terminal: &str, client: u64) -> bool {
        let all = self.rooms.lock().unwrap();
        all.get(terminal)
            .is_none_or(|r| r.1 <= 1 || r.0 == Some(client))
    }
    fn watched(&self, terminal: &str) -> bool {
        self.monitors
            .lock()
            .unwrap()
            .get(terminal)
            .is_some_and(|h| !h.is_finished())
    }
    /// Test hook: forget every exit watcher, as a restarted Core has none.
    #[cfg(any(test, feature = "test-support"))]
    pub fn forget_monitors(&self) {
        for (_, h) in self.monitors.lock().unwrap().drain() {
            h.abort();
        }
    }
}

/// Whether a client's frame may reach the runner: typed input within its limit, a valid
/// resize, a known signal. A client's `credit` is never forwarded: Core owns credit.
fn client_frame(b: &Body) -> bool {
    match b {
        Body::Output(o) => {
            o.data.len() <= MAX_INPUT / 3 * 4 + 4
                && base64::engine::general_purpose::STANDARD
                    .decode(&o.data)
                    .is_ok_and(|x| x.len() <= MAX_INPUT)
        }
        Body::Control(Control::Resize(s)) => s.valid(),
        Body::Control(Control::Signal(s)) => {
            ainkrad_proto::v2::SIGNALS.contains(&s.signal.as_str())
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStatus {
    Created,
    Running,
    Exited,
    Reaped,
}
impl TerminalStatus {
    fn parse(s: &str) -> Self {
        match s {
            "created" => Self::Created,
            "running" => Self::Running,
            "exited" => Self::Exited,
            _ => Self::Reaped,
        }
    }
}
#[derive(Debug, Serialize, ToSchema)]
pub struct Terminal {
    pub id: String,
    pub runner: String,
    pub status: TerminalStatus,
    pub size: Option<TerminalSize>,
    pub seq: Option<u64>,
    pub opened_by: Option<String>,
    pub created_at: Option<Timestamp>,
    pub exit_code: Option<i32>,
    pub exit_signal: Option<String>,
    pub attached: Option<u32>,
    /// Running with no client attached: it is closed once idle past `terminal.idle_secs`.
    pub orphaned: Option<bool>,
}
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewTerminal {
    pub runner: String,
    pub program: Option<String>,
    pub args: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub env: Option<BTreeMap<String, String>>,
    pub size: TerminalSize,
}
#[derive(Debug, Deserialize, ToSchema)]
pub struct TerminalSignal {
    pub signal: String,
}
#[derive(Debug, Deserialize)]
pub struct AttachQuery {
    pub after: Option<u64>,
}

fn failed(e: &ainkrad_proto::v2::StreamError) -> ApiError {
    let status = match e.code {
        ainkrad_proto::v2::ErrorCode::Offline
        | ainkrad_proto::v2::ErrorCode::UnsupportedCommand => axum::http::StatusCode::CONFLICT,
        ainkrad_proto::v2::ErrorCode::Busy => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        _ => axum::http::StatusCode::BAD_GATEWAY,
    };
    ApiError::new(
        status,
        "terminal_failed",
        "the runner could not serve the terminal",
    )
}
async fn row(app: &App, id: &str) -> Result<Terminal, ApiError> {
    let r = sqlx::query_as::<_, (String,String,String,i64,i64,i64,Option<String>,String,Option<i32>,Option<String>)>("SELECT id,runner,status,rows,cols,output_seq,opened_by,created_at,exit_code,exit_signal FROM core_terminals WHERE id=? AND status!='reaped'").bind(id).fetch_optional(&app.pool).await?.ok_or_else(|| ApiError::not_found("no such terminal"))?;
    let status = TerminalStatus::parse(&r.2);
    let attached = app.terminals.attached(id);
    Ok(Terminal {
        id: r.0,
        runner: r.1,
        status,
        size: Some(TerminalSize {
            rows: r.3 as u16,
            cols: r.4 as u16,
        }),
        seq: Some(r.5 as u64),
        opened_by: r.6,
        created_at: Some(ts(&r.7)),
        exit_code: r.8,
        exit_signal: r.9,
        attached: Some(attached),
        orphaned: Some(attached == 0 && status == TerminalStatus::Running),
    })
}

async fn owned_row(app: &App, id: &str, device: &str) -> Result<Terminal, ApiError> {
    let terminal = row(app, id).await?;
    if terminal.opened_by.as_deref() != Some(device) {
        return Err(ApiError::not_found("no such terminal"));
    }
    Ok(terminal)
}
/// A names-only audit row about terminal `id`; its entity is the terminal's row.
async fn audit(
    app: &App,
    action: &str,
    id: &str,
    by: &str,
    signal: Option<&str>,
) -> Result<(), ApiError> {
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM core_terminals WHERE id=?")
        .bind(id)
        .fetch_optional(&app.pool)
        .await?
        .unwrap_or(0);
    store::audit::append_one(
        &app.pool,
        &NewAuditEvent {
            actor: BY,
            action: action.to_owned(),
            entity: Some(AuditEntity {
                kind: "terminal".to_owned(),
                id: seq,
            }),
            details: json!({"terminal":id,"by_device":by,"signal":signal}).to_string(),
        },
    )
    .await?;
    Ok(())
}

/// The runner's `opened`, or why the stream failed; the runner is waited for `OPEN_WAIT`.
async fn opened(d: &mut Dispatched) -> Result<TerminalInfo, ApiError> {
    let wait = async {
        loop {
            match d.next().await {
                Some(Body::Control(Control::Opened(i))) => return Ok(i),
                Some(Body::Error(e)) => return Err(failed(&e)),
                Some(Body::Result(_)) | None => {
                    return Err(ApiError::new(
                        axum::http::StatusCode::BAD_GATEWAY,
                        "terminal_failed",
                        "runner ended before opening",
                    ));
                }
                _ => {}
            }
        }
    };
    tokio::time::timeout(OPEN_WAIT, wait)
        .await
        .unwrap_or_else(|_| {
            Err(ApiError::new(
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                "terminal_failed",
                "the runner did not open the terminal in time",
            ))
        })
}

/// Hangs up a host the Core will not keep a row for, so no shell is left unrecorded.
fn abandon(app: &App, runner: &str, terminal: &str) {
    let (hub, runner, terminal) = (app.hub.clone(), runner.to_owned(), terminal.to_owned());
    tokio::spawn(async move {
        let close = Command::PtyClose(PtyClose { terminal });
        if let Ok(d) = hub.dispatch_elevated(&runner, close, hub.continue_terminal_elevation()) {
            let _ = d.outcome().await;
        }
    });
}

/// Watches `terminal` on `d` until it exits, then records the exit.
fn monitor(app: &App, terminal: String, mut d: Dispatched) {
    let a = app.clone();
    let id = terminal.clone();
    let task = tokio::spawn(async move {
        while let Some(body) = d.next().await {
            match body {
                Body::Result(Reply::PtyOpen(exit) | Reply::PtyAttach(exit)) => {
                    ended(&a, &id, exit.exit_code, exit.signal).await;
                    break;
                }
                Body::Error(_) => break,
                _ => {}
            }
        }
    });
    app.terminals
        .monitors
        .lock()
        .unwrap()
        .insert(terminal, task.abort_handle());
}

/// Records the end of a running terminal (its slot is free from here) and tells the clients:
/// one `terminal.exited` event, whose `reason` is `host_lost` when the runner's host process
/// died without reporting how the child ended. A terminal already ended is left alone.
async fn ended(app: &App, id: &str, code: Option<i32>, signal: Option<String>) {
    let done = sqlx::query("UPDATE core_terminals SET status='exited',exit_code=?,exit_signal=?,last_activity=? WHERE id=? AND status IN ('created','running')")
        .bind(code)
        .bind(&signal)
        .bind(app.clock.unix())
        .bind(id)
        .execute(&app.pool)
        .await;
    if done.is_ok_and(|r| r.rows_affected() == 1) {
        let reason = (signal.as_deref() == Some(SIGNAL_HOST_LOST)).then_some(SIGNAL_HOST_LOST);
        let _ = event_with(app, "terminal.exited", id, "runner", reason).await;
    }
}

/// A runner connected (its `hello` lists the terminals it still holds): settle what the Core
/// kept while it was away, so a Core or runner restart does not leave rows `running` for
/// terminals that ended meanwhile. A row the runner no longer lists lost its host; a live one
/// is watched again and counts as just active, so its clients get a window to reattach.
/// Only rows older than `before` are looked at: a terminal opened since the hello was taken
/// is not in it.
pub async fn reconcile(app: &App, runner: &str, listed: &[TerminalInfo], before: i64) {
    let Ok(ids) = sqlx::query_scalar::<_, String>("SELECT id FROM core_terminals WHERE runner=? AND status IN ('created','running') AND last_activity<?")
        .bind(runner)
        .bind(before)
        .fetch_all(&app.pool)
        .await
    else {
        return;
    };
    for id in ids {
        match listed.iter().find(|i| i.terminal == id) {
            None => ended(app, &id, None, Some(SIGNAL_HOST_LOST.to_owned())).await,
            Some(TerminalInfo { exit: Some(x), .. }) => {
                ended(app, &id, x.exit_code, x.signal.clone()).await
            }
            Some(_) => {
                touch(app, &id).await;
                if let Ok(t) = row(app, &id).await {
                    ensure_monitor(app, &t);
                }
            }
        }
    }
}

async fn touch(app: &App, id: &str) {
    let _ = sqlx::query("UPDATE core_terminals SET last_activity=? WHERE id=?")
        .bind(app.clock.unix())
        .bind(id)
        .execute(&app.pool)
        .await;
}

/// Closes every running terminal nobody has been attached to for `terminal.idle_secs`
/// (0 turns it off). A runner that is offline is tried again at the next pass.
pub async fn sweep(app: &App) {
    let Ok(idle) =
        crate::store::settings::value(&app.pool, Key::TerminalIdleSecs, Scope::Server).await
    else {
        return;
    };
    if idle <= 0 {
        return;
    }
    let Ok(rows) = sqlx::query_as::<_, (String, String)>(
        "SELECT id,runner FROM core_terminals WHERE status='running' AND last_activity<?",
    )
    .bind(app.clock.unix() - idle)
    .fetch_all(&app.pool)
    .await
    else {
        return;
    };
    for (id, runner) in rows {
        if app.terminals.attached(&id) > 0 {
            continue;
        }
        let close = Command::PtyClose(PtyClose {
            terminal: id.clone(),
        });
        let Ok(d) =
            app.hub
                .dispatch_elevated(&runner, close, app.hub.continue_terminal_elevation())
        else {
            continue;
        };
        let Ok(Ok(Body::Result(Reply::PtyClose(x)))) =
            tokio::time::timeout(CLOSE_WAIT, d.outcome()).await
        else {
            continue;
        };
        let done = sqlx::query("UPDATE core_terminals SET status='reaped',exit_code=?,exit_signal=?,last_activity=? WHERE id=? AND status IN ('running','exited')")
            .bind(x.exit_code)
            .bind(x.signal)
            .bind(app.clock.unix())
            .bind(&id)
            .execute(&app.pool)
            .await;
        if done.is_ok_and(|r| r.rows_affected() == 1) {
            let _ = event_with(app, "terminal.closed", &id, "core", Some("idle")).await;
        }
    }
}

/// `sweep` every `SWEEP_EVERY` until the Core stops.
pub async fn sweep_loop(app: App) {
    let mut closing = app.closing.subscribe();
    let mut tick = tokio::time::interval(SWEEP_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = crate::api::stopping(&mut closing) => return,
            _ = tick.tick() => sweep(&app).await,
        }
    }
}

/// After a Core restart no stream watches a running terminal: attach one (the caller passed
/// the terminal gate; `pty.attach` reaches a running host only).
fn ensure_monitor(app: &App, t: &Terminal) {
    if !matches!(t.status, TerminalStatus::Running) || app.terminals.watched(&t.id) {
        return;
    }
    let attach = Command::PtyAttach(PtyAttach {
        terminal: t.id.clone(),
        seq: t.seq.unwrap_or(0),
    });
    if let Ok(d) =
        app.hub
            .dispatch_elevated(&t.runner, attach, app.hub.continue_terminal_elevation())
    {
        monitor(app, t.id.clone(), d);
    }
}

/// Exited terminals nobody closed are reaped after `KEEP_EXITED`.
async fn reap(app: &App) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE core_terminals SET status='reaped' WHERE status='exited' AND last_activity<?",
    )
    .bind(app.clock.unix() - KEEP_EXITED)
    .execute(&app.pool)
    .await?;
    Ok(())
}
async fn event(app: &App, kind: &str, id: &str, by: &str) -> Result<(), ApiError> {
    event_with(app, kind, id, by, None).await
}
async fn event_with(
    app: &App,
    kind: &str,
    id: &str,
    by: &str,
    reason: Option<&str>,
) -> Result<(), ApiError> {
    let mut tx = store::begin_write(&app.pool).await?;
    store::events::append(
        &mut tx,
        kind,
        &json!({"terminal":id,"by_device":by,"at":iso_of_unix(app.clock.unix()),"reason":reason}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[utoipa::path(post, path="/api/v1/terminals", operation_id="createTerminal", tag="terminals", request_body=NewTerminal, responses((status=201, description="The terminal was opened", body=Terminal)))]
pub async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(req): Json<NewTerminal>,
) -> Response {
    if !(1..=1000).contains(&req.size.rows) || !(1..=1000).contains(&req.size.cols) {
        return ApiError::bad_request("terminal size is out of range").into_response();
    }
    // The caps are counted and used up under one lock, so concurrent creates cannot overshoot.
    let _turn = app.terminals.create.lock().await;
    if let Err(e) = reap(&app).await {
        return e.into_response();
    }
    let mine = match sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM core_terminals WHERE opened_by=? AND status IN ('created','running')",
    )
    .bind(&me.device.id)
    .fetch_one(&app.pool)
    .await
    {
        Ok(n) => n,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let (per_device, per_runner) = match (
        store::settings::value(&app.pool, Key::TerminalMaxPerDevice, Scope::Server).await,
        store::settings::value(&app.pool, Key::TerminalMaxPerRunner, Scope::Server).await,
    ) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return ApiError::from(e).into_response(),
    };
    if mine >= per_device {
        return ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "terminal_limit",
            "device terminal limit reached",
        )
        .into_response();
    }
    let runner = match gov::get_device(&app.pool, &req.runner).await {
        Ok(Some(d)) if d.kind == "runner" && d.usable() => d,
        Ok(_) => return ApiError::not_found("no such runner").into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let count = match sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM core_terminals WHERE runner=? AND status IN ('created','running')",
    )
    .bind(&runner.id)
    .fetch_one(&app.pool)
    .await
    {
        Ok(n) => n,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if count >= per_runner {
        return ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "terminal_limit",
            "runner terminal limit reached",
        )
        .into_response();
    }
    // The gate passed scope and step-up for this route; only now is the token minted.
    let mut d = match app.hub.dispatch_elevated(
        &runner.id,
        Command::PtyOpen(PtyOpen {
            program: req.program,
            args: req.args.unwrap_or_default(),
            cwd: req.cwd,
            env: req.env.unwrap_or_default(),
            env_pass: Vec::new(),
            size: ainkrad_proto::v2::Size {
                rows: req.size.rows,
                cols: req.size.cols,
            },
        }),
        app.hub.terminal_elevation(&me),
    ) {
        Ok(d) => d,
        Err(e) => return failed(&e).into_response(),
    };
    let info = match opened(&mut d).await {
        Ok(i) => i,
        Err(e) => {
            // A host that opens after we gave up must not outlive the stream.
            let (app, runner) = (app.clone(), runner.id.clone());
            tokio::spawn(async move {
                if let Ok(Ok(i)) = tokio::time::timeout(CLOSE_WAIT, async {
                    loop {
                        match d.next().await {
                            Some(Body::Control(Control::Opened(i))) => return Ok(i),
                            Some(Body::Result(_) | Body::Error(_)) | None => return Err(()),
                            _ => {}
                        }
                    }
                })
                .await
                {
                    abandon(&app, &runner, &i.terminal);
                }
            });
            return e.into_response();
        }
    };
    if let Err(e) = register(&app, &me, &runner.id, &info).await {
        abandon(&app, &runner.id, &info.terminal);
        return e.into_response();
    }
    monitor(&app, info.terminal.clone(), d);
    match row(&app, &info.terminal).await {
        Ok(t) => (axum::http::StatusCode::CREATED, Json(t)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Records an opened terminal: its row, the audit row and the event, in one transaction.
async fn register(
    app: &App,
    me: &Caller,
    runner: &str,
    info: &TerminalInfo,
) -> Result<(), ApiError> {
    let t = &info.terminal;
    let named = t.len() <= 32
        && t.starts_with("t_")
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !named {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "terminal_failed",
            "the runner named the terminal badly",
        ));
    }
    let mut tx = store::begin_write(&app.pool).await?;
    let seq=sqlx::query_scalar::<_,i64>("INSERT INTO core_terminals(id,runner,status,rows,cols,output_seq,opened_by,created_at,last_activity) VALUES(?,?, 'running',?,?,?,?,?,?) RETURNING seq").bind(t).bind(runner).bind(info.size.rows.clamp(1,1000)).bind(info.size.cols.clamp(1,1000)).bind(info.seq as i64).bind(&me.device.id).bind(iso_of_unix(app.clock.unix())).bind(app.clock.unix()).fetch_one(&mut *tx).await?;
    let details = json!({"terminal":t,"runner":runner,"by_device":me.device.id});
    let ae = NewAuditEvent {
        actor: BY,
        action: "terminal.opened".to_owned(),
        entity: Some(AuditEntity {
            kind: "terminal".to_owned(),
            id: seq,
        }),
        details: details.to_string(),
    };
    store::audit::append(&mut tx, &ae).await?;
    store::events::append(&mut tx, "terminal.opened", &details).await?;
    tx.commit().await?;
    Ok(())
}
#[utoipa::path(get,path="/api/v1/terminals",operation_id="listTerminals",tag="terminals",responses((status=200,description="The caller's own terminals",body=Vec<Terminal>)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> ApiResult<Vec<Terminal>> {
    reap(&app).await?;
    // Like `get`: a terminal is listed only to the device that opened it.
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM core_terminals WHERE opened_by=? AND status!='reaped' ORDER BY seq",
    )
    .bind(&me.device.id)
    .fetch_all(&app.pool)
    .await?;
    let mut out = Vec::new();
    for id in ids {
        out.push(row(&app, &id).await?)
    }
    Ok(Json(out))
}
#[utoipa::path(get,path="/api/v1/terminals/{id}",operation_id="getTerminal",tag="terminals",params(("id"=String,Path)),responses((status=200,description="One terminal",body=Terminal)))]
pub async fn get(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Terminal> {
    // Terminal metadata is private to its opener.  Attach is deliberately separate: a second
    // elevated terminal device may attach for the multi-client case, but cannot enumerate a
    // different device's terminal by id.
    Ok(Json(owned_row(&app, &id, &me.device.id).await?))
}
#[utoipa::path(delete,path="/api/v1/terminals/{id}",operation_id="closeTerminal",tag="terminals",params(("id"=String,Path)),responses((status=200,description="The terminal was closed",body=Terminal)))]
pub async fn close(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Terminal> {
    let before = owned_row(&app, &id, &me.device.id).await?;
    let (mut code, mut signal) = (before.exit_code, before.exit_signal.clone());
    // An exited terminal has no host to hang up.
    if matches!(
        before.status,
        TerminalStatus::Running | TerminalStatus::Created
    ) {
        let mut d = app
            .hub
            .dispatch_elevated(
                &before.runner,
                Command::PtyClose(PtyClose {
                    terminal: id.clone(),
                }),
                app.hub.terminal_elevation(&me),
            )
            .map_err(|e| failed(&e))?;
        let r = tokio::time::timeout(CLOSE_WAIT, async {
            loop {
                match d.next().await {
                    Some(Body::Result(r)) => return Ok(r),
                    Some(Body::Error(e)) => return Err(failed(&e)),
                    Some(_) => {}
                    None => {
                        return Err(ApiError::new(
                            axum::http::StatusCode::BAD_GATEWAY,
                            "terminal_failed",
                            "runner disconnected",
                        ));
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                "terminal_failed",
                "the runner did not close the terminal in time",
            )
        })??;
        if let Reply::PtyClose(e) = r {
            (code, signal) = (e.exit_code, e.signal);
        }
    }
    sqlx::query("UPDATE core_terminals SET status='reaped',exit_code=?,exit_signal=?,last_activity=? WHERE id=?").bind(code).bind(signal).bind(app.clock.unix()).bind(&id).execute(&app.pool).await?;
    audit(&app, "terminal.closed", &id, &me.device.id, None).await?;
    event(&app, "terminal.closed", &id, &me.device.id).await?;
    Ok(Json(Terminal {
        status: TerminalStatus::Reaped,
        ..before
    }))
}
#[utoipa::path(post,path="/api/v1/terminals/{id}/signal",operation_id="signalTerminal",tag="terminals",request_body=TerminalSignal,params(("id"=String,Path)),responses((status=204,description="The signal was delivered")))]
pub async fn signal(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Json(req): Json<TerminalSignal>,
) -> Response {
    let t = match owned_row(&app, &id, &me.device.id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if !ainkrad_proto::v2::SIGNALS.contains(&req.signal.as_str()) {
        return ApiError::bad_request("unknown signal").into_response();
    }
    ensure_monitor(&app, &t);
    let mut d = match app.hub.dispatch_elevated(
        &t.runner,
        Command::PtyAttach(PtyAttach {
            terminal: id.clone(),
            seq: t.seq.unwrap_or(0),
        }),
        app.hub.terminal_elevation(&me),
    ) {
        Ok(d) => d,
        Err(e) => return failed(&e).into_response(),
    };
    let sent = match opened(&mut d).await {
        Ok(_) => app
            .hub
            .send_terminal(
                &t.runner,
                d.stream,
                Body::Control(Control::Signal(SignalReq {
                    signal: req.signal.clone(),
                })),
            )
            .map_err(|e| failed(&e)),
        Err(e) => Err(e),
    };
    // Always detach: this stream was only a way to reach the host.
    let _ = app
        .hub
        .send_terminal(&t.runner, d.stream, Body::Close(Default::default()));
    if let Err(e) = sent {
        return e.into_response();
    }
    if let Err(e) = audit(
        &app,
        "terminal.signalled",
        &id,
        &me.device.id,
        Some(&req.signal),
    )
    .await
    {
        return e.into_response();
    }
    axum::http::StatusCode::NO_CONTENT.into_response()
}
#[utoipa::path(get,path="/api/v1/terminals/{id}/ws",operation_id="attachTerminal",tag="terminals",params(("id"=String,Path),("after"=Option<u64>,Query)),responses((status=101,description="Terminal WebSocket")))]
pub async fn attach(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(q): Query<AttachQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let t = match row(&app, &id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    ensure_monitor(&app, &t);
    let d = match app.hub.dispatch_elevated(
        &t.runner,
        Command::PtyAttach(PtyAttach {
            terminal: id.clone(),
            // A fresh attach (no `after`) gets the terminal's history or a snapshot.
            seq: q.after.unwrap_or(0),
        }),
        app.hub.terminal_elevation(&me),
    ) {
        Ok(d) => d,
        Err(e) => return failed(&e).into_response(),
    };
    if let Err(e) = audit(&app, "terminal.attached", &id, &me.device.id, None).await {
        return e.into_response();
    }
    if let Err(e) = event(&app, "terminal.attached", &id, &me.device.id).await {
        return e.into_response();
    }
    let revoked = crate::auth::until_revoked(
        app.live.devices(&app.pool, app.stream.backstop),
        app.auth.subscribe(),
        me.device.id.clone(),
    );
    let rescoped = crate::auth::until_rescoped(
        app.live.devices(&app.pool, app.stream.backstop),
        app.auth.subscribe_rescoped(),
        me.device.id.clone(),
        me.device.scopes.clone(),
    );
    let elevation = app
        .auth
        .session(&me.session, &me.device.id, app.clock.unix())
        .and_then(|s| s.elevated_until)
        .unwrap_or(app.clock.unix());
    let terminal_id = id.clone();
    let by_device = me.device.id.clone();
    ws.protocols([super::ticket::PROTOCOL])
        .max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |s| {
            stream(
                app,
                s,
                d,
                t.runner,
                terminal_id,
                by_device,
                elevation,
                revoked,
                rescoped,
            )
        })
}
#[allow(clippy::too_many_arguments)]
async fn stream(
    app: App,
    mut socket: WebSocket,
    mut d: Dispatched,
    runner: String,
    terminal: String,
    by_device: String,
    elevation: i64,
    revoked: impl std::future::Future<Output = ()>,
    rescoped: impl std::future::Future<Output = ()>,
) {
    let client = app.terminals.join(&terminal);
    touch(&app, &terminal).await;
    tokio::pin!(revoked);
    tokio::pin!(rescoped);
    let expiry = tokio::time::sleep(Duration::from_secs(
        elevation.saturating_sub(app.clock.unix()).max(0) as u64,
    ));
    tokio::pin!(expiry);
    // A send to a client that stopped reading is bounded, so revoke, rescope and expiry are
    // always polled again within it (spec §4.7: 5 s).
    let cap = app.hub.config.send_timeout.min(Duration::from_secs(4));
    let mut seq = 0u64;
    let mut pending_resize = None;
    let (mut window, mut spent) = (Instant::now(), 0usize);
    loop {
        tokio::select! {
        ()=&mut revoked=>{close_socket(&mut socket,4001,"revoked",cap).await;break},
        ()=&mut rescoped=>{close_socket(&mut socket,4003,"scope changed",cap).await;break},
        ()=&mut expiry=>{close_socket(&mut socket,4003,"step-up expired",cap).await;break},
        next=d.next()=>match next{Some(body)=>{let f=Frame::new(0,seq,body);seq=seq.saturating_add(1);if send(&mut socket,f,cap).await.is_err(){break}},None=>break},
        msg=socket.recv()=>match msg{
            Some(Ok(Message::Text(t)))=>{
                let Ok(f)=serde_json::from_str::<Frame>(&t) else {continue};
                let Ok(Some(b))=f.body() else {continue};
                if !client_frame(&b) {continue}
                if let Body::Output(o)=&b {
                    if window.elapsed()>=Duration::from_secs(1){window=Instant::now();spent=0}
                    spent+=o.data.len();
                    if spent>INPUT_PER_SEC {continue}
                    app.terminals.typed(&terminal,client);
                    // This client is the typist now: its remembered size applies.
                    if let Some(s)=pending_resize.take()&&app.hub.send_terminal(&runner,d.stream,Body::Control(Control::Resize(s))).is_err(){break}
                }
                let b=match b{
                    Body::Control(Control::Resize(s))=>{
                        if !app.terminals.may_resize(&terminal,client){pending_resize=Some(s);continue}
                        Body::Control(Control::Resize(s))
                    }
                    Body::Control(Control::Signal(s))=>{
                        let _=audit(&app,"terminal.signalled",&terminal,&by_device,Some(&s.signal)).await;
                        Body::Control(Control::Signal(s))
                    }
                    other=>other,
                };
                if app.hub.send_terminal(&runner,d.stream,b).is_err(){break}
            }
            Some(Ok(Message::Close(_)))|Some(Err(_))|None=>break,
            _=>{}}}
    }
    // Stamped before the client is counted out, so a pass never sees "nobody attached" with a
    // stale stamp.
    touch(&app, &terminal).await;
    app.terminals.leave(&terminal);
    let _ = audit(&app, "terminal.detached", &terminal, &by_device, None).await;
    let _ = event(&app, "terminal.detached", &terminal, &by_device).await;
    let _ = app
        .hub
        .send_terminal(&runner, d.stream, Body::Close(Default::default()));
}
async fn send(s: &mut WebSocket, f: Frame, cap: Duration) -> Result<(), ()> {
    let text = serde_json::to_string(&f).map_err(|_| ())?;
    tokio::time::timeout(cap, s.send(Message::Text(text.into())))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}
async fn close_socket(s: &mut WebSocket, code: u16, reason: &str, cap: Duration) {
    let close = s.send(Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    })));
    let _ = tokio::time::timeout(cap, close).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainkrad_proto::v2::{Credit, Output, Size};

    fn typed(s: &str) -> Body {
        Body::Output(Output {
            data: base64::engine::general_purpose::STANDARD.encode(s),
        })
    }

    /// M5: a client's credit is never forwarded, and oversized or invalid frames are dropped.
    #[test]
    fn client_frames_are_filtered() {
        assert!(client_frame(&typed("ls\n")));
        assert!(!client_frame(&Body::Credit(Credit { bytes: 1 << 30 })));
        assert!(!client_frame(&typed(&"a".repeat(MAX_INPUT + 1))));
        assert!(!client_frame(&Body::Control(Control::Resize(Size {
            rows: 0,
            cols: 80
        }))));
        assert!(!client_frame(&Body::Control(Control::Signal(SignalReq {
            signal: "SEGV".to_owned()
        }))));
    }

    /// M4 (spec §4.4): the size follows the most recent typist; a lone client always resizes.
    #[test]
    fn size_follows_the_most_recent_typist() {
        let r = Rooms::default();
        let a = r.join("t_1");
        assert!(r.may_resize("t_1", a), "a lone client resizes");
        let b = r.join("t_1");
        assert!(
            !r.may_resize("t_1", a) && !r.may_resize("t_1", b),
            "nobody typed yet"
        );
        r.typed("t_1", b);
        assert!(r.may_resize("t_1", b));
        assert!(!r.may_resize("t_1", a), "a is remembered until it types");
        r.typed("t_1", a);
        assert!(r.may_resize("t_1", a) && !r.may_resize("t_1", b));
        r.leave("t_1");
        assert!(r.may_resize("t_1", b), "alone again");
        assert_eq!(r.attached("t_1"), 1);
    }
}
