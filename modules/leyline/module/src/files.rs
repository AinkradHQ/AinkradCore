//! A person's files on a host (the host page, plan Y2-03 SFTP): list a folder, read a file in
//! chunks, write a file in chunks. Not the AI routes (`ai.rs`): those answer sessions as outside data.
//!
//! Security model.
//! - Every call is gated as the person behind the device (`Principal::of`): `authorize` makes the run
//!   row and the audit rows, and dispatch takes the `Authorized` (`exec::sftp` re-checks the host, the
//!   run and the principal right before each runner op). No key leaves the Core: one-use leases only.
//! - Paths are data for the runner's SFTP; nothing here reads them with a shell. A NUL is refused.
//! - Reading needs the `terminal` scope; writing also needs a live step-up (`DESTRUCTIVE`), like a
//!   terminal. A file is at most 64 MiB; a chunk at most 512 KiB.
//! - Upload chunks wait in Core memory (never on disk), keyed by device, host and path, in order, and
//!   are written to the host in ONE credited transfer when the last chunk says `done`. At most 4
//!   uploads wait per device (and 32 in all), so one device cannot starve the others; a stale one is
//!   dropped after 10 minutes.
//! - Every refusal is a fixed sentence: no path or byte is echoed.
// ponytail: each chunk is its own gated run and runner connection (the runner pools them); a
// per-transfer session would save the audit rows if 64 MB transfers become common.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller, MAX_UPLOAD};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_proto::v2::{Body, Close, Command, SftpKind, SftpRead};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::ai::{Open, PathQuery, host_err, list as sftp_list, path_of};
use crate::exec::{sftp, sftp_put, why};
use crate::gate::{Action, Principal, authorize};
use crate::hosts::{In, find};

/// The most one read chunk carries.
const CHUNK_MAX: u64 = 512 << 10;
/// Uploads waiting for their last chunk, and how long one may wait.
const PENDING_MAX: usize = 4;
const PENDING_ALL: usize = 32;
const PENDING_TTL: Duration = Duration::from_secs(600);

#[derive(Serialize, ToSchema)]
pub struct RemoteFile {
    /// The entry's full path on the host.
    pub path: String,
    pub name: String,
    /// `file`, `dir` or `link` (a symlink is never followed).
    pub kind: String,
    pub size: Option<u64>,
    pub modified: Option<String>,
    /// Where a link points; not reported by the runner yet.
    pub target: Option<String>,
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The host `ident` names, gated for `action` as the person behind `me`.
async fn gated(app: &App, me: &Caller, ident: &str, action: Action) -> Result<Open, ApiError> {
    let host = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, ident).await?
    };
    let auth = authorize(app, &Principal::of(me), &host, &action).await?;
    Ok(Open {
        app: app.clone(),
        auth: Some(auth),
    })
}

#[utoipa::path(get, path = "/hosts/{host}/files", operation_id = "leylineHostFiles", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label"), PathQuery),
    responses((status = 200, description = "A folder's entries on the host (at most 10000). Needs the terminal scope; 403 `gate_refused`, 502 `host_unavailable`", body = Vec<RemoteFile>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    q: Result<Query<PathQuery>, QueryRejection>,
) -> ApiResult<Vec<RemoteFile>> {
    let path = path_of(q)?;
    let open = gated(&app, &me, &host, Action::FileList(path.clone())).await?;
    let got = sftp_list(&app, open.auth(), path.clone()).await;
    open.end(got.is_ok()).await?;
    let e = got.map_err(host_err)?;
    Ok(Json(
        e.entries
            .into_iter()
            .map(|x| RemoteFile {
                path: join(&path, &x.name),
                kind: match x.kind {
                    SftpKind::Dir => "dir",
                    SftpKind::Symlink => "link",
                    SftpKind::File | SftpKind::Other => "file",
                }
                .to_owned(),
                size: x.size,
                modified: x.mtime.and_then(|t| i64::try_from(t).ok()).map(iso_of_unix),
                target: None,
                name: x.name,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(crate) struct ContentQuery {
    path: String,
    offset: Option<u64>,
    limit: Option<u64>,
}

fn content_of(q: Result<Query<ContentQuery>, QueryRejection>) -> Result<ContentQuery, ApiError> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the path is not valid"))?;
    path_of(Ok(Query(PathQuery {
        path: q.path.clone(),
    })))?;
    Ok(q)
}

#[derive(Serialize, ToSchema)]
pub struct Chunk {
    /// The bytes, standard base64.
    pub data: String,
    /// The file ended inside this chunk (the next read from here answers nothing).
    pub eof: bool,
}

#[utoipa::path(get, path = "/hosts/{host}/files/content", operation_id = "leylineReadHostFile", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label"),
           ("path" = String, Query, description = "The file's path on the host"),
           ("offset" = Option<u64>, Query, description = "Byte to start at"),
           ("limit" = Option<u64>, Query, description = "At most this many bytes (capped at 512 KiB)")),
    responses((status = 200, description = "One chunk of a file. Needs the terminal scope; 403 `gate_refused`, 502 `host_unavailable`", body = Chunk)))]
pub(crate) async fn read(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    q: Result<Query<ContentQuery>, QueryRejection>,
) -> ApiResult<Chunk> {
    let q = content_of(q)?;
    let limit = q.limit.unwrap_or(CHUNK_MAX).clamp(1, CHUNK_MAX);
    let open = gated(&app, &me, &host, Action::FileRead(q.path.clone())).await?;
    let got = part(&app, open.auth(), q.path, q.offset.unwrap_or(0), limit).await;
    open.end(got.is_ok()).await?;
    let (buf, eof) = got.map_err(host_err)?;
    Ok(Json(Chunk {
        data: STANDARD.encode(buf),
        eof,
    }))
}

/// Up to `limit` bytes from `offset`, and whether the file ended; the rest is cancelled on the runner.
async fn part(
    app: &App,
    auth: &crate::gate::Authorized,
    path: String,
    offset: u64,
    limit: u64,
) -> Result<(Vec<u8>, bool), String> {
    let (mut d, runner) = sftp(app, auth, |route| {
        Command::SshSftpRead(SftpRead {
            route,
            path,
            offset,
        })
    })
    .await?;
    let mut buf = Vec::new();
    let other = || "the runner answered something else".to_owned();
    while let Some(body) = d.next().await {
        match body {
            Body::Output(o) => {
                buf.extend(STANDARD.decode(o.data.as_bytes()).map_err(|_| other())?);
                if buf.len() as u64 >= limit {
                    buf.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                    let close = Body::Close(Close {
                        reason: Some("chunk done".to_owned()),
                    });
                    let _ = app.hub.send_terminal(&runner, d.stream, close);
                    return Ok((buf, false));
                }
            }
            Body::Result(_) => return Ok((buf, true)),
            Body::Error(e) => return Err(why(e.code)),
            Body::Control(_) => {}
            _ => return Err(other()),
        }
    }
    Err(why(ainkrad_proto::v2::ErrorCode::Lost))
}

#[derive(Deserialize, ToSchema)]
pub struct Put {
    /// Where this chunk starts; it must be where the last one ended (0 for the first).
    pub offset: u64,
    /// The chunk, standard base64, at most 512 KiB decoded.
    pub data: String,
    /// The last chunk: the file is now written to the host.
    pub done: bool,
}

type Key = (String, String, String);
type Waiting = HashMap<Key, (Vec<u8>, Instant)>;

fn waiting() -> &'static Mutex<Waiting> {
    static W: OnceLock<Mutex<Waiting>> = OnceLock::new();
    W.get_or_init(Mutex::default)
}

/// Adds a chunk; the whole file once `done`.
fn add(key: Key, req: &Put, bytes: Vec<u8>) -> Result<Option<Vec<u8>>, ApiError> {
    let mut w = waiting().lock().unwrap();
    w.retain(|_, (_, at)| at.elapsed() < PENDING_TTL);
    let mine = w.keys().filter(|k| k.0 == key.0).count();
    if !w.contains_key(&key) && (mine >= PENDING_MAX || w.len() >= PENDING_ALL) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "too_many_uploads",
            "too many uploads are waiting from this device; finish or retry them shortly",
        ));
    }
    let have = w.get(&key).map_or(0, |(v, _)| v.len() as u64);
    if req.offset != have {
        w.remove(&key);
        return Err(ApiError::conflict(
            "the upload is out of order; start again",
        ));
    }
    if have + bytes.len() as u64 > MAX_UPLOAD as u64 {
        w.remove(&key);
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_big",
            "the file is larger than 64 MB",
        ));
    }
    let (all, at) = w
        .entry(key.clone())
        .or_insert_with(|| (Vec::new(), Instant::now()));
    all.extend_from_slice(&bytes);
    *at = Instant::now();
    Ok(req
        .done
        .then(|| w.remove(&key).map(|(v, _)| v).unwrap_or_default()))
}

#[derive(Serialize, ToSchema)]
pub struct Stored {
    /// Bytes held or written so far.
    pub bytes: u64,
}

#[utoipa::path(put, path = "/hosts/{host}/files/content", operation_id = "leylineWriteHostFile", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label"),
           ("path" = String, Query, description = "The file's path on the host")),
    request_body = Put,
    responses((status = 200, description = "The chunk is held; on `done` the file replaced the target on the host (nothing is left behind on failure). Needs the terminal scope and a live step-up; 403 `gate_refused`, 409 out of order, 413 over 64 MB, 502 `host_unavailable`", body = Stored)))]
pub(crate) async fn write(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    q: Result<Query<PathQuery>, QueryRejection>,
    In(req): In<Put>,
) -> ApiResult<Stored> {
    let path = path_of(q)?;
    let bytes = (req.data.len() <= (CHUNK_MAX as usize / 3 + 1) * 4)
        .then(|| STANDARD.decode(req.data.as_bytes()).ok())
        .flatten()
        .ok_or_else(|| ApiError::bad_request("the chunk is not valid"))?;
    let id = {
        let mut conn = app.pool.acquire().await?;
        find(&mut conn, &host).await?
    };
    let key = (me.device.id.clone(), id, path.clone());
    let Some(all) = add(key, &req, bytes)? else {
        return Ok(Json(Stored { bytes: req.offset }));
    };
    let open = gated(&app, &me, &host, Action::FileWrite(path.clone())).await?;
    let put = sftp_put(&app, &me, open.auth(), &path, &all).await;
    open.end(put.is_ok()).await?;
    put?;
    Ok(Json(Stored {
        bytes: all.len() as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(offset: u64, done: bool) -> Put {
        Put {
            offset,
            data: String::new(),
            done,
        }
    }

    #[test]
    fn chunks_must_arrive_in_order_and_the_last_returns_the_file() {
        let k = ("d".to_owned(), "h".to_owned(), "/a".to_owned());
        assert!(
            add(k.clone(), &put(0, false), b"ab".to_vec())
                .unwrap()
                .is_none()
        );
        assert!(
            add(k.clone(), &put(5, false), b"x".to_vec()).is_err(),
            "a gap"
        );
        // the failed upload was dropped: it starts again from 0
        assert!(add(k.clone(), &put(2, true), b"x".to_vec()).is_err());
        assert!(
            add(k.clone(), &put(0, false), b"ab".to_vec())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            add(k, &put(2, true), b"cd".to_vec()).unwrap().unwrap(),
            b"abcd"
        );
    }

    #[test]
    fn one_device_cannot_fill_the_waiting_uploads_for_the_others() {
        let key = |d: &str, p: &str| (d.to_owned(), "h".to_owned(), p.to_owned());
        for i in 0..PENDING_MAX {
            assert!(
                add(
                    key("dev-a", &format!("/f{i}")),
                    &put(0, false),
                    b"x".to_vec()
                )
                .is_ok()
            );
        }
        assert!(add(key("dev-a", "/one-more"), &put(0, false), b"x".to_vec()).is_err());
        // a chunk of an upload already waiting still goes in, and another device is not blocked
        assert!(add(key("dev-a", "/f0"), &put(1, false), b"y".to_vec()).is_ok());
        assert!(add(key("dev-b", "/f0"), &put(0, false), b"x".to_vec()).is_ok());
    }

    #[test]
    fn paths_join_without_a_double_slash() {
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("/srv", "a"), "/srv/a");
    }
}
