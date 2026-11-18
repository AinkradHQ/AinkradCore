//! Two small jobs a module does through a runner's SSH (Leyline Y8-01, "make a host a runner"):
//! move one tiny file to or from a host over SFTP, and type a line into a terminal the module
//! opened. Both are for [`open_ssh`](super::open_ssh)'s kind of caller.
//!
//! Security model.
//! - REQUIREMENT ON THE CALLER (as for `open_ssh`: the gate lives in another crate, so nothing here
//!   can check it): the module has passed its own gate for this host and action, holds the
//!   `Authorized` for the whole call, and built the route from leases it granted for this one job.
//!   Nothing else may call these. A new caller needs the same review as the gate.
//! - Both need the `terminal` scope, like the terminal routes, and are minted the terminal
//!   capability only after that check.
//! - File bytes travel as one `output` frame sent with `send_terminal`, which never keeps a frame
//!   for a resend: a secret in the file is in no buffer the hub holds, and the command that is
//!   resent after a reconnect (`SftpWrite`) carries only leases, a path and a size.
//! - Nothing here logs a path, a byte or the runner's own message: only the error code.
//! - `type_into` writes to the terminal of the caller's own device only (`owned_row`).

use std::time::Duration;

use ainkrad_proto::v2::{
    Body, Command, Control, Output, PtyAttach, STREAM_WINDOW, SftpMkdir, SftpRemove, SftpWrite,
    SshRoute, StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{
    ApiError, App, Caller, MAX_INPUT, ensure_monitor, failed, need_terminal_scope, opened,
    owned_row,
};

/// A file sent this way is at most this many bytes: it rides one frame inside the first window.
pub const MAX_SMALL_FILE: usize = 4096;
/// A file a person uploads (the host page) is at most this many bytes; it is sent in credited frames.
pub const MAX_UPLOAD: usize = 64 << 20;
/// One frame of an upload (the runner refuses a frame over the credit it granted).
const UPLOAD_FRAME: usize = 32 * 1024;
/// A whole job, dial included.
const JOB_WAIT: Duration = Duration::from_secs(60);

/// One small job on a host, reached by `route` through `runner`.
pub enum SftpJob<'a> {
    /// A directory (its parent must exist); the runner's `sftp_exists` etc. are the caller's to ignore.
    Mkdir(&'a str),
    /// One file, removed (never a directory, never recursive).
    Remove(&'a str),
    /// A file replaced whole: created with `mode` before the first byte, renamed into place.
    Put {
        path: &'a str,
        mode: u32,
        bytes: &'a [u8],
    },
    /// One file of at most [`MAX_UPLOAD`] bytes replaced whole (the host page), sent within the runner's credit.
    Upload { path: &'a str, bytes: &'a [u8] },
}

fn sftp_failed(e: &StreamError) -> ApiError {
    // The runner's text is its own; only the code is the Core's to log.
    tracing::warn!(code = ?e.code, "the runner failed an sftp job");
    let status = match e.code {
        ainkrad_proto::v2::ErrorCode::Offline
        | ainkrad_proto::v2::ErrorCode::UnsupportedCommand => axum::http::StatusCode::CONFLICT,
        ainkrad_proto::v2::ErrorCode::Busy => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        _ => axum::http::StatusCode::BAD_GATEWAY,
    };
    ApiError::new(
        status,
        "sftp_failed",
        "the runner could not do that on the host",
    )
}

/// Does `job` on the host `route` leads to, and answers when the runner has.
///
/// # Errors
///
/// 403 without the `terminal` scope; 400 for a file over [`MAX_SMALL_FILE`]; the runner's refusal
/// or loss, or a timeout, as a fixed `sftp_failed` answer.
pub async fn sftp_job(
    app: &App,
    me: &Caller,
    runner: &str,
    route: SshRoute,
    job: SftpJob<'_>,
) -> Result<(), ApiError> {
    need_terminal_scope(me)?;
    let (command, bytes) = match job {
        SftpJob::Upload { path, bytes } => {
            if bytes.len() > MAX_UPLOAD {
                return Err(ApiError::bad_request("the file is too big for this job"));
            }
            (
                Command::SshSftpWrite(SftpWrite {
                    route,
                    path: path.to_owned(),
                    overwrite: true,
                    size: Some(bytes.len() as u64),
                    mode: None,
                }),
                Some(bytes),
            )
        }
        SftpJob::Mkdir(p) => (
            Command::SshSftpMkdir(SftpMkdir {
                route,
                path: p.to_owned(),
            }),
            None,
        ),
        SftpJob::Remove(p) => (
            Command::SshSftpRemove(SftpRemove {
                route,
                path: p.to_owned(),
                dir: false,
            }),
            None,
        ),
        SftpJob::Put { path, mode, bytes } => {
            if bytes.len() > MAX_SMALL_FILE {
                return Err(ApiError::bad_request("the file is too big for this job"));
            }
            (
                Command::SshSftpWrite(SftpWrite {
                    route,
                    path: path.to_owned(),
                    overwrite: true,
                    size: Some(bytes.len() as u64),
                    mode: Some(mode),
                }),
                Some(bytes),
            )
        }
    };
    // A big upload gets time to move: a minute, plus a second per 256 KiB.
    let wait = JOB_WAIT + Duration::from_secs((bytes.map_or(0, <[u8]>::len) >> 18) as u64);
    let mut d = app
        .hub
        .dispatch_elevated(runner, command, app.hub.terminal_elevation(me))
        .map_err(|e| sftp_failed(&e))?;
    let stream = d.stream;
    let run = async {
        if let Some(b) = bytes {
            // The runner starts with one window and grants more as it writes: wait for credit
            // before a frame that would pass it (a small file never waits).
            let mut allowed = STREAM_WINDOW as usize;
            for part in b.chunks(UPLOAD_FRAME) {
                while allowed < part.len() {
                    match d.next().await {
                        Some(Body::Credit(c)) => {
                            allowed = allowed.saturating_add(usize::try_from(c.bytes).unwrap_or(0));
                        }
                        Some(Body::Error(e)) => return Err(sftp_failed(&e)),
                        Some(_) => {}
                        None => {
                            return Err(ApiError::new(
                                axum::http::StatusCode::BAD_GATEWAY,
                                "sftp_failed",
                                "the runner went away",
                            ));
                        }
                    }
                }
                let data = Body::Output(Output {
                    data: STANDARD.encode(part),
                });
                app.hub
                    .send_terminal(runner, stream, data)
                    .map_err(|e| sftp_failed(&e))?;
                allowed -= part.len();
            }
            app.hub
                .send_terminal(runner, stream, Body::Control(Control::Eof))
                .map_err(|e| sftp_failed(&e))?;
        }
        loop {
            match d.next().await {
                Some(Body::Result(_)) => return Ok(()),
                Some(Body::Error(e)) => return Err(sftp_failed(&e)),
                Some(_) => {}
                None => {
                    return Err(ApiError::new(
                        axum::http::StatusCode::BAD_GATEWAY,
                        "sftp_failed",
                        "the runner went away",
                    ));
                }
            }
        }
    };
    match tokio::time::timeout(wait, run).await {
        Ok(r) => r,
        Err(_) => {
            // A close cancels the job: a write leaves nothing behind on the host.
            let _ = app
                .hub
                .send_terminal(runner, stream, Body::Close(Default::default()));
            Err(ApiError::new(
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                "sftp_failed",
                "the runner did not answer in time",
            ))
        }
    }
}

/// Types `text` into `terminal`, which `me` opened, as if at the keyboard. The bytes are not kept
/// by the hub (typed input never is). The shell may not be up yet: the terminal holds what is
/// typed until it reads it.
///
/// # Errors
///
/// 403 without the `terminal` scope; 404 for a terminal that is not `me`'s; 400 for text over the
/// input limit; the runner's refusal.
pub async fn type_into(app: &App, me: &Caller, terminal: &str, text: &str) -> Result<(), ApiError> {
    need_terminal_scope(me)?;
    if text.len() > MAX_INPUT {
        return Err(ApiError::bad_request("too much to type at once"));
    }
    let t = owned_row(app, terminal, &me.device.id).await?;
    ensure_monitor(app, &t);
    let mut d = app
        .hub
        .dispatch_elevated(
            &t.runner,
            Command::PtyAttach(PtyAttach {
                terminal: terminal.to_owned(),
                seq: t.seq.unwrap_or(0),
                // A one-shot typist is not a client.
                watch: true,
            }),
            app.hub.terminal_elevation(me),
        )
        .map_err(|e| failed(&e))?;
    let sent = match opened(&mut d).await {
        Ok(_) => app
            .hub
            .send_terminal(
                &t.runner,
                d.stream,
                Body::Output(Output {
                    data: STANDARD.encode(text),
                }),
            )
            .map_err(|e| failed(&e)),
        Err(e) => Err(e),
    };
    // Always detach: this stream was only a way to reach the terminal.
    let _ = app
        .hub
        .send_terminal(&t.runner, d.stream, Body::Close(Default::default()));
    sent
}
