//! Leyline as AI sessions see it through Code Mode (Y7-01, plan T11): the routes only a session
//! reaches (`/ai/...`, the Brain pattern), and what a session reads of a run.
//!
//! Security model.
//! - These routes answer only the Code Mode dispatcher's synthetic caller (`code_mode:<id>`); a
//!   person gets `session_only`. A person's routes and scopes are unchanged by this file.
//! - Who asks is `Principal::of(&Caller)`, so the session; the gate re-reads it through
//!   `session_principal` (live, creator usable, never `admin`) on every call. Nothing the session
//!   sends picks its principal, its rule or its runner.
//! - Every action reaching a host goes through `gate::authorize`: `read_only` hosts allow file
//!   list/read and read-only pre-set commands only, `ask` hosts park ONE Core-held `cm_` approval,
//!   `allowed` hosts run, audited. The routes are `Module::self_approved`, so the dispatcher does
//!   not park a second approval for a `risky` op: T10 decides.
//! - Dispatch takes the gate's `Authorized` and calls `gate::checked` before each runner op;
//!   every runner op carries one-use key leases only, never key material.
//! - What a host wrote (file text, directory entries, command output) leaves inside the
//!   `ainkrad_core::untrusted` envelope, redacted first. Labels name Core ids, never input.
//! - Errors are fixed sentences: no argument is ever echoed. Keys, trust, direct leases, host and
//!   command writes are not here, and never will be.

use ainkrad_core::untrusted::wrap;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::ops_catalog::SESSION_PREFIX;
use ainkrad_proto::v2::{
    Body, Close, Command, Reply, SFTP_MAX_PATH, SftpEntries, SftpKind, SftpList, SftpRead, SftpStat,
};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::commands::{RunRequest, RunStarted, RunView};
use crate::exec::{sftp, why};
use crate::gate::{Action, Authorized, Principal, authorize, finish, redact_text};
use crate::hosts::{In, find};

/// The most a file read returns (T11).
const MAX_READ: u64 = 1 << 20;
/// The longest ad-hoc command line.
const MAX_LINE: usize = 4096;

/// The session behind a Code Mode call, if this is one.
pub(crate) fn session_of(me: &Caller) -> Option<&str> {
    me.session
        .strip_prefix(SESSION_PREFIX)
        .filter(|s| !s.is_empty())
}

fn session_only(me: &Caller) -> Result<(), ApiError> {
    session_of(me).map(|_| ()).ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "session_only",
            "this route answers AI sessions; use the host routes",
        )
    })
}

fn host_err(why: String) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, "host_unavailable", why)
}

#[utoipa::path(get, path = "/ai/runs/{run}", operation_id = "leylineAiGetRun", tag = "leyline",
    params(("run" = String, Path, description = "The run's id")),
    responses((status = 200, description = "One of this session's runs and each host's result, every output as outside data; another principal's run is a 404", body = RunView)))]
pub(crate) async fn get_run(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<RunView> {
    session_only(&me)?;
    let Json(mut run) = crate::commands::get_run(State(app), Path(id)).await?;
    own_run(&me, &mut run)?;
    Ok(Json(run))
}

/// A session reads only its own runs, and every output there is outside data.
fn own_run(me: &Caller, run: &mut RunView) -> Result<(), ApiError> {
    let Some(s) = session_of(me) else {
        return Err(ApiError::not_found("no such run"));
    };
    if run.principal != format!("session:{s}") {
        return Err(ApiError::not_found("no such run"));
    }
    for h in &mut run.hosts {
        if let Some(o) = h.output.take() {
            h.output = Some(wrap(
                &format!("output of run {} on {}", run.id, h.host_id),
                &o,
            ));
        }
    }
    Ok(())
}

/// The host a session names, resolved (id, else unique label), then gated.
async fn gated(app: &App, me: &Caller, host: &str, action: Action) -> Result<Authorized, ApiError> {
    session_only(me)?;
    let host = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, host).await?
    };
    authorize(app, &Principal::of(me), &host, &action).await
}

#[derive(Deserialize, ToSchema)]
pub struct ExecRequest {
    /// One command line, run by the host's login shell.
    pub command: String,
}

#[utoipa::path(post, path = "/ai/hosts/{host}/exec", operation_id = "leylineExec", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = ExecRequest,
    responses((status = 200, description = "Past the gate: the command runs in the background; read the run (`leylineAiGetRun`) for its output, as outside data. 403 `gate_refused` when the host's AI rule says no, or the person did", body = RunStarted)))]
pub(crate) async fn exec(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<ExecRequest>,
) -> ApiResult<RunStarted> {
    let line = req.command.trim();
    if line.is_empty() || line.len() > MAX_LINE || line.contains('\0') {
        return Err(ApiError::bad_request("the command is not valid"));
    }
    let auth = gated(&app, &me, &host, Action::Exec(line.to_owned())).await?;
    let run = auth.run_id().to_owned();
    tokio::spawn(crate::exec::run(app.clone(), auth));
    Ok(Json(RunStarted {
        run,
        state: "running".to_owned(),
    }))
}

#[derive(Deserialize, ToSchema)]
pub struct AiRunRequest {
    /// Host id, else its unique label.
    pub host: String,
}

#[utoipa::path(post, path = "/ai/commands/{command}/run", operation_id = "leylineAiRunCommand", tag = "leyline",
    params(("command" = String, Path, description = "Command id, else its unique name")), request_body = AiRunRequest,
    responses((status = 200, description = "Past the gate: the pre-set command's steps run in the background; read the run for results. 403 `gate_refused` when the gate says no", body = RunStarted)))]
pub(crate) async fn run_command(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(command): Path<String>,
    In(req): In<AiRunRequest>,
) -> ApiResult<RunStarted> {
    session_only(&me)?;
    // The person's run path, as the session. `confirm` is the person's guard, not the session's:
    // the gate turns a `confirm` command run by a session into `ask` (a person approves it).
    let req = RunRequest {
        host: req.host,
        confirm: Some(true),
    };
    crate::commands::run(State(app), Extension(me), Path(command), In(req)).await
}

#[derive(Deserialize, IntoParams)]
pub struct PathQuery {
    /// An absolute or home-relative path on the host; data, never read by a shell.
    pub path: String,
}

fn path_of(q: Result<Query<PathQuery>, QueryRejection>) -> Result<String, ApiError> {
    let bad = || ApiError::bad_request("the path is not valid");
    let Query(q) = q.map_err(|_| bad())?;
    if q.path.is_empty() || q.path.len() > SFTP_MAX_PATH || q.path.contains('\0') {
        return Err(bad());
    }
    Ok(q.path)
}

fn other() -> String {
    "the runner answered something else".to_owned()
}

#[derive(Serialize, ToSchema)]
pub struct FileList {
    /// One line per entry, `kind size name` (the name JSON-quoted), inside the outside-data envelope.
    pub listing: String,
    pub count: usize,
    /// The directory has more entries than one listing carries.
    pub truncated: bool,
}

#[utoipa::path(get, path = "/ai/hosts/{host}/files", operation_id = "leylineListFiles", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label"), PathQuery),
    responses((status = 200, description = "A directory's entries on the host, as outside data. 403 `gate_refused` when the gate says no; 502 `host_unavailable` when the host could not be read", body = FileList)))]
pub(crate) async fn list_files(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    q: Result<Query<PathQuery>, QueryRejection>,
) -> ApiResult<FileList> {
    let path = path_of(q)?;
    let auth = gated(&app, &me, &host, Action::FileList(path.clone())).await?;
    let got = list(&app, &auth, path).await;
    let label = format!("directory listing on {}", auth.host_id());
    finish(&app, auth, got.is_ok()).await?;
    let e = got.map_err(host_err)?;
    let lines: Vec<String> = e
        .entries
        .iter()
        .map(|x| {
            let kind = match x.kind {
                SftpKind::File => "file",
                SftpKind::Dir => "dir",
                SftpKind::Symlink => "symlink",
                SftpKind::Other => "other",
            };
            let size = x.size.map_or_else(|| "-".to_owned(), |s| s.to_string());
            let name = serde_json::to_string(&x.name).unwrap_or_default();
            format!("{kind} {size} {name}")
        })
        .collect();
    Ok(Json(FileList {
        listing: wrap(&label, &redact_text(&lines.join("\n"))),
        count: e.entries.len(),
        truncated: e.truncated,
    }))
}

#[derive(Serialize, ToSchema)]
pub struct FileText {
    /// The file's bytes as text (invalid UTF-8 replaced), redacted, inside the outside-data envelope.
    pub text: String,
    pub bytes: u64,
}

#[utoipa::path(get, path = "/ai/hosts/{host}/file", operation_id = "leylineReadFile", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label"), PathQuery),
    responses((status = 200, description = "A regular file of at most 1 MB on the host, as outside data. 403 `gate_refused` when the gate says no; 502 `host_unavailable` when it could not be read, is no file or is larger", body = FileText)))]
pub(crate) async fn read_file(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    q: Result<Query<PathQuery>, QueryRejection>,
) -> ApiResult<FileText> {
    let path = path_of(q)?;
    let auth = gated(&app, &me, &host, Action::FileRead(path.clone())).await?;
    let got = read(&app, &auth, path).await;
    let label = format!("file on {}", auth.host_id());
    finish(&app, auth, got.is_ok()).await?;
    let buf = got.map_err(host_err)?;
    Ok(Json(FileText {
        text: wrap(&label, &redact_text(&String::from_utf8_lossy(&buf))),
        bytes: buf.len() as u64,
    }))
}

async fn list(app: &App, auth: &Authorized, path: String) -> Result<SftpEntries, String> {
    let (d, _) = sftp(app, auth, |route| {
        Command::SshSftpList(SftpList { route, path })
    })
    .await?;
    match d.outcome().await {
        Ok(Body::Result(Reply::SshSftpList(e))) => Ok(e),
        Ok(_) => Err(other()),
        Err(e) => Err(why(e.code)),
    }
}

/// Stat first (a symlink is followed: the gate allowed reading the path), then the bytes, cut off
/// and cancelled on the runner past the cap.
async fn read(app: &App, auth: &Authorized, path: String) -> Result<Vec<u8>, String> {
    let too_big = || "the file is larger than 1 MB".to_owned();
    let p = path.clone();
    let (d, _) = sftp(app, auth, |route| {
        Command::SshSftpStat(SftpStat {
            route,
            path: p,
            follow: true,
        })
    })
    .await?;
    match d.outcome().await {
        Ok(Body::Result(Reply::SshSftpStat(e))) if e.kind != SftpKind::File => {
            return Err("that is not a regular file".to_owned());
        }
        Ok(Body::Result(Reply::SshSftpStat(e))) if e.size.unwrap_or(0) > MAX_READ => {
            return Err(too_big());
        }
        Ok(Body::Result(Reply::SshSftpStat(_))) => {}
        Ok(_) => return Err(other()),
        Err(e) => return Err(why(e.code)),
    }
    let (mut d, runner) = sftp(app, auth, |route| {
        Command::SshSftpRead(SftpRead {
            route,
            path,
            offset: 0,
        })
    })
    .await?;
    let mut buf = Vec::new();
    while let Some(body) = d.next().await {
        match body {
            Body::Output(o) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(o.data.as_bytes())
                    .map_err(|_| other())?;
                buf.extend_from_slice(&bytes);
                if buf.len() as u64 > MAX_READ {
                    let close = Body::Close(Close {
                        reason: Some("over the read cap".to_owned()),
                    });
                    let _ = app.hub.send_terminal(&runner, d.stream, close);
                    return Err(too_big());
                }
            }
            Body::Result(Reply::SshSftpRead(_)) => return Ok(buf),
            Body::Error(e) => return Err(why(e.code)),
            Body::Control(_) => {}
            _ => return Err(other()),
        }
    }
    Err(why(ainkrad_proto::v2::ErrorCode::Lost))
}
