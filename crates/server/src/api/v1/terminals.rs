//! Terminal service. Content is transport-only; lifecycle metadata is the only persisted data.
use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY, Caller};
use crate::api::App;
use crate::hub::Dispatched;
use crate::scheduler::iso_of_unix;
use crate::store::{self, gov};
use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
use ainkrad_proto::v2::{Body, Command, Control, Frame, PtyAttach, PtyClose, PtyOpen, SignalReq};
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
use std::time::Duration;
use utoipa::ToSchema;

const MAX_DEVICE_TERMINALS: i64 = 8;
const MAX_RUNNER_TERMINALS: i64 = 16;
const MAX_INPUT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
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
    Ok(Terminal {
        id: r.0,
        runner: r.1,
        status: TerminalStatus::parse(&r.2),
        size: Some(TerminalSize {
            rows: r.3 as u16,
            cols: r.4 as u16,
        }),
        seq: Some(r.5 as u64),
        opened_by: r.6,
        created_at: Some(ts(&r.7)),
        exit_code: r.8,
        exit_signal: r.9,
        attached: Some(0),
    })
}

async fn owned_row(app: &App, id: &str, device: &str) -> Result<Terminal, ApiError> {
    let terminal = row(app, id).await?;
    if terminal.opened_by.as_deref() != Some(device) {
        return Err(ApiError::not_found("no such terminal"));
    }
    Ok(terminal)
}
async fn audit(app: &App, action: &str, id: &str, by: &str, seq: i64) -> Result<(), ApiError> {
    store::audit::append_one(
        &app.pool,
        &NewAuditEvent {
            actor: BY,
            action: action.to_owned(),
            entity: Some(AuditEntity {
                kind: "terminal".to_owned(),
                id: seq,
            }),
            details: json!({"terminal":id,"by_device":by}).to_string(),
        },
    )
    .await?;
    Ok(())
}
async fn event(app: &App, kind: &str, id: &str, by: &str) -> Result<(), ApiError> {
    let mut tx = store::begin_write(&app.pool).await?;
    store::events::append(
        &mut tx,
        kind,
        &json!({"terminal":id,"by_device":by,"at":iso_of_unix(app.clock.unix())}),
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
    let mine=match sqlx::query_scalar::<_,i64>("SELECT count(*) FROM core_terminals WHERE opened_by=? AND status IN ('created','running','exited')").bind(&me.device.id).fetch_one(&app.pool).await {Ok(n)=>n,Err(e)=>return ApiError::from(e).into_response()};
    if mine >= MAX_DEVICE_TERMINALS {
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
    let count=match sqlx::query_scalar::<_,i64>("SELECT count(*) FROM core_terminals WHERE runner=? AND status IN ('created','running','exited')").bind(&runner.id).fetch_one(&app.pool).await {Ok(n)=>n,Err(e)=>return ApiError::from(e).into_response()};
    if count >= MAX_RUNNER_TERMINALS {
        return ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "terminal_limit",
            "runner terminal limit reached",
        )
        .into_response();
    }
    let mut d = match app.hub.dispatch(
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
    ) {
        Ok(d) => d,
        Err(e) => return failed(&e).into_response(),
    };
    let info = loop {
        match d.next().await {
            Some(Body::Control(Control::Opened(i))) => break i,
            Some(Body::Error(e)) => return failed(&e).into_response(),
            Some(Body::Result(_)) | None => {
                return ApiError::new(
                    axum::http::StatusCode::BAD_GATEWAY,
                    "terminal_failed",
                    "runner ended before opening",
                )
                .into_response();
            }
            _ => {}
        }
    };
    let mut tx = match store::begin_write(&app.pool).await {
        Ok(t) => t,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let seq=match sqlx::query_scalar::<_,i64>("INSERT INTO core_terminals(id,runner,status,rows,cols,output_seq,opened_by,created_at,last_activity) VALUES(?,?, 'running',?,?,?,?,?,?) RETURNING seq").bind(&info.terminal).bind(&runner.id).bind(info.size.rows).bind(info.size.cols).bind(info.seq as i64).bind(&me.device.id).bind(iso_of_unix(app.clock.unix())).bind(app.clock.unix()).fetch_one(&mut *tx).await{Ok(s)=>s,Err(e)=>return ApiError::from(e).into_response()};
    let ae = NewAuditEvent {
        actor: BY,
        action: "terminal.opened".to_owned(),
        entity: Some(AuditEntity {
            kind: "terminal".to_owned(),
            id: seq,
        }),
        details: json!({"terminal":info.terminal,"runner":runner.id,"by_device":me.device.id})
            .to_string(),
    };
    if let Err(e) = store::audit::append(&mut tx, &ae).await {
        return ApiError::from(e).into_response();
    }
    if let Err(e) = store::events::append(
        &mut tx,
        "terminal.opened",
        &json!({"terminal":info.terminal,"runner":runner.id,"by_device":me.device.id}),
    )
    .await
    {
        return ApiError::from(e).into_response();
    }
    if let Err(e) = tx.commit().await {
        return ApiError::from(e).into_response();
    };
    let monitor_app = app.clone();
    let monitor_id = info.terminal.clone();
    tokio::spawn(async move {
        while let Some(body) = d.next().await {
            if let Body::Result(ainkrad_proto::v2::Reply::PtyOpen(exit)) = body {
                let _ = sqlx::query("UPDATE core_terminals SET status='exited',exit_code=?,exit_signal=?,last_activity=? WHERE id=? AND status='running'")
                    .bind(exit.exit_code)
                    .bind(exit.signal)
                    .bind(monitor_app.clock.unix())
                    .bind(&monitor_id)
                    .execute(&monitor_app.pool)
                    .await;
                let _ = event(&monitor_app, "terminal.exited", &monitor_id, "runner").await;
                break;
            }
        }
    });
    match row(&app, &info.terminal).await {
        Ok(t) => (axum::http::StatusCode::CREATED, Json(t)).into_response(),
        Err(e) => e.into_response(),
    }
}
#[utoipa::path(get,path="/api/v1/terminals",operation_id="listTerminals",tag="terminals",responses((status=200,description="Known terminals",body=Vec<Terminal>)))]
pub async fn list(State(app): State<App>) -> ApiResult<Vec<Terminal>> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM core_terminals WHERE status!='reaped' ORDER BY seq")
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
    let before = row(&app, &id).await?;
    let mut d = app
        .hub
        .dispatch(
            &before.runner,
            Command::PtyClose(PtyClose {
                terminal: id.clone(),
            }),
        )
        .map_err(|e| failed(&e))?;
    let r = loop {
        match d.next().await {
            Some(Body::Result(r)) => break r,
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
    };
    let (code, signal) = match r {
        ainkrad_proto::v2::Reply::PtyClose(e) => (e.exit_code, e.signal),
        _ => (None, None),
    };
    sqlx::query("UPDATE core_terminals SET status='reaped',exit_code=?,exit_signal=?,last_activity=? WHERE id=?").bind(code).bind(signal).bind(app.clock.unix()).bind(&id).execute(&app.pool).await?;
    audit(&app, "terminal.closed", &id, &me.device.id, 0).await?;
    event(&app, "terminal.closed", &id, &me.device.id).await?;
    Ok(Json(Terminal {
        status: TerminalStatus::Reaped,
        ..before
    }))
}
#[utoipa::path(post,path="/api/v1/terminals/{id}/signal",operation_id="signalTerminal",tag="terminals",request_body=TerminalSignal,params(("id"=String,Path)),responses((status=204,description="The signal was delivered")))]
pub async fn signal(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(req): Json<TerminalSignal>,
) -> Response {
    let t = match row(&app, &id).await {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if !ainkrad_proto::v2::SIGNALS.contains(&req.signal.as_str()) {
        return ApiError::bad_request("unknown signal").into_response();
    }
    let mut d = match app.hub.dispatch(
        &t.runner,
        Command::PtyAttach(PtyAttach {
            terminal: id.clone(),
            seq: t.seq.unwrap_or(0),
        }),
    ) {
        Ok(d) => d,
        Err(e) => return failed(&e).into_response(),
    };
    while let Some(b) = d.next().await {
        if matches!(b, Body::Control(Control::Opened(_))) {
            break;
        }
    }
    if let Err(e) = app.hub.send_terminal(
        &t.runner,
        d.stream,
        Body::Control(Control::Signal(SignalReq { signal: req.signal })),
    ) {
        return failed(&e).into_response();
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
    let d = match app.hub.dispatch(
        &t.runner,
        Command::PtyAttach(PtyAttach {
            terminal: id.clone(),
            seq: q.after.unwrap_or(t.seq.unwrap_or(0)),
        }),
    ) {
        Ok(d) => d,
        Err(e) => return failed(&e).into_response(),
    };
    if let Err(e) = audit(&app, "terminal.attached", &id, &me.device.id, 0).await {
        return e.into_response();
    }
    if let Err(e) = event(&app, "terminal.attached", &id, &me.device.id).await {
        return e.into_response();
    }
    let revoked = crate::auth::until_revoked(
        app.pool.clone(),
        app.auth.subscribe(),
        me.device.id.clone(),
        app.stream.backstop,
    );
    let rescoped = crate::auth::until_rescoped(
        app.pool.clone(),
        app.auth.subscribe_rescoped(),
        me.device.id.clone(),
        me.device.scopes.clone(),
        app.stream.backstop,
    );
    let elevation = app
        .auth
        .session(&me.session, &me.device.id, app.clock.unix())
        .and_then(|s| s.elevated_until)
        .unwrap_or(app.clock.unix());
    let terminal_id = id.clone();
    let by_device = me.device.id.clone();
    ws.protocols([super::ticket::PROTOCOL])
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
    tokio::pin!(revoked);
    tokio::pin!(rescoped);
    let expiry = tokio::time::sleep(Duration::from_secs(
        elevation.saturating_sub(app.clock.unix()).max(0) as u64,
    ));
    tokio::pin!(expiry);
    let mut seq = 0u64;
    loop {
        tokio::select! {
        ()=&mut revoked=>{close_socket(&mut socket,4001,"revoked").await;break},
        ()=&mut rescoped=>{close_socket(&mut socket,4003,"scope changed").await;break},
        ()=&mut expiry=>{close_socket(&mut socket,4003,"step-up expired").await;break},
        next=d.next()=>match next{Some(body)=>{let f=Frame::new(0,seq,body);seq=seq.saturating_add(1);if send(&mut socket,f).await.is_err(){break}},None=>break},
        msg=socket.recv()=>match msg{Some(Ok(Message::Text(t)))=>{if let Ok(f)=serde_json::from_str::<Frame>(&t)&&let Ok(Some(b))=f.body(){let ok=match &b{Body::Output(o)=>base64::engine::general_purpose::STANDARD.decode(&o.data).is_ok_and(|x|x.len()<=MAX_INPUT),Body::Control(Control::Resize(s))=>s.valid(),Body::Control(Control::Signal(s))=>ainkrad_proto::v2::SIGNALS.contains(&s.signal.as_str()),Body::Credit(_)=>true,_=>false};if ok&&app.hub.send_terminal(&runner,d.stream,b).is_err(){break}}},Some(Ok(Message::Close(_)))|None=>break,_=>{}}}
    }
    let _ = audit(&app, "terminal.detached", &terminal, &by_device, 0).await;
    let _ = event(&app, "terminal.detached", &terminal, &by_device).await;
    let _ = app
        .hub
        .send_terminal(&runner, d.stream, Body::Close(Default::default()));
}
async fn send(s: &mut WebSocket, f: Frame) -> Result<(), ()> {
    s.send(Message::Text(
        serde_json::to_string(&f).map_err(|_| ())?.into(),
    ))
    .await
    .map_err(|_| ())
}
async fn close_socket(s: &mut WebSocket, code: u16, reason: &str) {
    let _ = s
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}
