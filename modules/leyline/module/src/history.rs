//! Session history, recording switch, replay and retention (Y3-02).
//!
//! Security model.
//! - Recording is opt-in per host and off by default. Turning it on needs a live step-up (a Code
//!   Mode caller never has one) and a loaded master key; turning it off needs the step-up too (the
//!   route is destructive). Both are audited (`leyline.recording.on` / `.off`).
//! - A recording is read only with the `terminal` scope and a live step-up, and every read is
//!   audited (`leyline.recording.replayed`, session and device, never content). The Core decrypts
//!   it; the client gets the plain cast over the signed, TLS API.
//! - Retention: 30 days and 2 GB in total, oldest first, by a daily job. A recording still being
//!   written is never removed for size; files with no row (a deleted host) are removed.
//! - A person (never an AI session) can pause a running recording (no step-up) and resume it
//!   (step-up); both are audited and the session's `recording` flag follows.
//! - Replay streams the blocks with a total cap; it never holds the whole cast in memory.
//! - Session lists name no recording content: only whether one exists and its size.

use std::path::Path as FsPath;
use std::sync::{Arc, OnceLock};

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller, step_up_required};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use utoipa::ToSchema;

use crate::cast::Blocks;
use crate::gate::Principal;
use crate::hosts::{In, elevated, find};
use crate::policy::Who;

/// How long a recording is kept, and how much all of them may take together.
pub const KEEP_SECS: i64 = 30 * 24 * 3600;
pub const CAP_BYTES: i64 = 2 * 1024 * 1024 * 1024;

/// The app the prune job runs on (`Module::attach`; the module value is a unit struct).
static APP: OnceLock<App> = OnceLock::new();

pub(crate) fn attach(app: &App) {
    let _ = APP.set(app.clone());
}

/// One host terminal session, as the history shows it.
#[derive(Serialize, ToSchema)]
pub struct SessionRow {
    /// `ls_` and 16 hex characters.
    pub id: String,
    pub host_id: String,
    pub terminal: String,
    pub runner: String,
    pub principal: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    /// `exited`, `runner_lost`, `host_key_unknown`, `host_key_changed`, `auth_failed` or `failed`.
    pub end_reason: Option<String>,
    pub exit_code: Option<i64>,
    /// A recording exists (and has not been pruned); replay it with `GET /sessions/{session}/recording`.
    pub recorded: bool,
    /// A recording is running now (not ended, not paused): the app shows a Recording indicator.
    pub recording: bool,
    /// The recording's size on disk.
    pub recording_bytes: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct Limit {
    limit: Option<i64>,
}

/// The session query with `$tail` appended: a compile-time string, never built at run time.
macro_rules! sessions_sql {
    ($tail:literal) => {
        concat!(
            "SELECT s.id, s.host_id, s.terminal, s.runner, s.principal, s.started_at, s.ended_at, \
             s.end_reason, s.exit_code, r.bytes AS rec_bytes, (r.ended_at IS NULL AND r.paused = 0) AS rec_live FROM leyline_sessions s \
             LEFT JOIN leyline_recordings r ON r.session = s.id ",
            $tail
        )
    };
}

fn rows(r: Vec<sqlx::sqlite::SqliteRow>) -> Result<Vec<SessionRow>, sqlx::Error> {
    use sqlx::Row;
    r.iter()
        .map(|r| {
            let bytes: Option<i64> = r.try_get("rec_bytes")?;
            Ok(SessionRow {
                id: r.try_get("id")?,
                host_id: r.try_get("host_id")?,
                terminal: r.try_get("terminal")?,
                runner: r.try_get("runner")?,
                principal: r.try_get("principal")?,
                started_at: r.try_get("started_at")?,
                ended_at: r.try_get("ended_at")?,
                end_reason: r.try_get("end_reason")?,
                exit_code: r.try_get("exit_code")?,
                recorded: bytes.is_some(),
                recording: bytes.is_some()
                    && r.try_get::<Option<i64>, _>("rec_live")?.unwrap_or(0) == 1,
                recording_bytes: bytes,
            })
        })
        .collect()
}

#[utoipa::path(get, path = "/hosts/{host}/sessions", operation_id = "leylineHostSessions", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label"), ("limit" = Option<i64>, Query, description = "1 to 200, default 50")),
    responses((status = 200, description = "The host's terminal sessions, newest first", body = Vec<SessionRow>)))]
pub(crate) async fn host_sessions(
    State(app): State<App>,
    Path(host): Path<String>,
    Query(q): Query<Limit>,
) -> ApiResult<Vec<SessionRow>> {
    let mut conn = app.pool.acquire().await?;
    let id = find(&mut conn, &host).await?;
    let found = sqlx::query(sessions_sql!(
        "WHERE s.host_id = ? ORDER BY s.started_at DESC, s.id DESC LIMIT ?"
    ))
    .bind(id)
    .bind(q.limit.unwrap_or(50).clamp(1, 200))
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(rows(found)?))
}

#[utoipa::path(get, path = "/projects/{project}/sessions", operation_id = "leylineProjectSessions", tag = "leyline",
    params(("project" = String, Path, description = "The Core project's id"), ("limit" = Option<i64>, Query, description = "1 to 200, default 50")),
    responses((status = 200, description = "Terminal sessions on the project's attached hosts, newest first", body = Vec<SessionRow>)))]
pub(crate) async fn project_sessions(
    State(app): State<App>,
    Path(project): Path<String>,
    Query(q): Query<Limit>,
) -> ApiResult<Vec<SessionRow>> {
    if !project.bytes().all(|b| b.is_ascii_digit()) || project.is_empty() || project.len() > 18 {
        return Err(ApiError::not_found("no such project"));
    }
    let found = sqlx::query(sessions_sql!(
        "WHERE s.host_id IN (SELECT host_id FROM leyline_project_hosts WHERE project = ?) \
         ORDER BY s.started_at DESC, s.id DESC LIMIT ?"
    ))
    .bind(project)
    .bind(q.limit.unwrap_or(50).clamp(1, 200))
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(rows(found)?))
}

#[derive(Deserialize, ToSchema)]
pub struct NewRecording {
    /// `on` or `off`.
    pub record: String,
}

#[derive(Serialize, ToSchema)]
pub struct HostRecording {
    pub host_id: String,
    /// `on` or `off`.
    pub record: String,
    /// What is kept: days, and total bytes for every recording.
    pub keep_days: i64,
    pub cap_bytes: i64,
}

#[utoipa::path(put, path = "/hosts/{host}/recording", operation_id = "leylineSetRecording", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")), request_body = NewRecording,
    responses((status = 200, description = "Recording for the host's future terminals is `on` (needs the master key: 409 `secrets_unavailable`) or `off`; both need a step-up (403 `step_up_required`); audited as `leyline.recording.on`/`off`. Output only, secrets redacted, kept 30 days and 2 GB in total", body = HostRecording)))]
pub(crate) async fn set_recording(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(host): Path<String>,
    In(req): In<NewRecording>,
) -> ApiResult<HostRecording> {
    let on = match req.record.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err(ApiError::bad_request("record is on or off")),
    };
    if on {
        if !elevated(&app, &me) {
            return Err(step_up_required());
        }
        // The key is made now, so a failure shows here and not on the first terminal.
        crate::record::recipient(&app).await.map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "secrets_unavailable",
                "recordings need the Core's master key",
            )
        })?;
    }
    let mut tx = begin_write(&app.pool).await?;
    let id = find(&mut tx, &host).await?;
    let word = if on { "on" } else { "off" };
    sqlx::query("UPDATE leyline_hosts SET record = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?")
        .bind(word)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.recording.{word}"),
        entity: None,
        details: json!({"host": id, "by_device": me.device.id}).to_string(),
    };
    audit::append(&mut tx, &row).await?;
    events::append(&mut tx, "leyline.host", &json!({"op": "changed", "id": id})).await?;
    tx.commit().await?;
    Ok(Json(HostRecording {
        host_id: id,
        record: word.to_owned(),
        keep_days: KEEP_SECS / 86400,
        cap_bytes: CAP_BYTES,
    }))
}

fn session_id(s: &str) -> bool {
    s.len() == 19 && s.starts_with("ls_") && s[3..].bytes().all(|b| b.is_ascii_hexdigit())
}

#[utoipa::path(get, path = "/sessions/{session}/recording", operation_id = "leylineReplay", tag = "leyline",
    params(("session" = String, Path, description = "Session id (`ls_...`)")),
    responses((status = 200, description = "The recording as an asciicast v2 file (`application/x-asciicast`: a header line, then `[seconds, \"o\", text]` lines), decrypted by the Core. Needs the terminal scope and a live step-up; audited as `leyline.recording.replayed`. The app plays it at 1x, 2x or 8x. 404 when none exists (off, pruned)", body = String, content_type = "application/x-asciicast")))]
pub(crate) async fn replay(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(session): Path<String>,
) -> Result<Response, ApiError> {
    let none = || ApiError::not_found("no such recording");
    if !session_id(&session) {
        return Err(none());
    }
    if !elevated(&app, &me) {
        return Err(step_up_required());
    }
    let (file, host): (String, String) =
        sqlx::query_as("SELECT file, host_id FROM leyline_recordings WHERE session = ?")
            .bind(&session)
            .fetch_optional(&app.pool)
            .await?
            .ok_or_else(none)?;
    let path = crate::record::dir(&app)
        .map_err(|_| ApiError::not_found("no such recording"))?
        .join(&file);
    let file = tokio::task::spawn_blocking(move || std::fs::File::open(path))
        .await
        .map_err(|_| none())?
        .map_err(|_| none())?;
    let id = crate::record::identity(&app).await.map_err(|_| {
        ApiError::new(
            StatusCode::CONFLICT,
            "secrets_unavailable",
            "the recording key is not available",
        )
    })?;
    // The first block is opened before anything is sent, so a key that does not open is a 409.
    let (mut blocks, id, first) = tokio::task::spawn_blocking(move || {
        let mut b = Blocks::new(std::io::BufReader::new(file));
        let first = b.next(&id);
        (b, id, first)
    })
    .await
    .map_err(|_| none())?;
    let unreadable = |_| {
        ApiError::new(
            StatusCode::CONFLICT,
            "recording_unreadable",
            "the recording did not decrypt",
        )
    };
    let first = first.map_err(unreadable)?;
    let mut tx = begin_write(&app.pool).await?;
    let row = NewAuditEvent {
        actor: BY,
        action: "leyline.recording.replayed".to_owned(),
        entity: None,
        details: json!({"session": session, "host": host, "by_device": me.device.id}).to_string(),
    };
    audit::append(&mut tx, &row).await?;
    tx.commit().await?;
    // Two blocks in flight at most: the reader waits for the client.
    let (send, recv) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    tokio::task::spawn_blocking(move || {
        let mut next = first;
        while let Some(b) = next {
            if send.blocking_send(Ok(Bytes::from(b))).is_err() {
                return;
            }
            next = match blocks.next(&id) {
                Ok(n) => n,
                Err(e) => {
                    let _ = send.blocking_send(Err(std::io::Error::other(e)));
                    return;
                }
            };
        }
    });
    let body = Body::from_stream(futures_util::stream::unfold(recv, |mut r| async {
        r.recv().await.map(|x| (x, r))
    }));
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-asciicast"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response())
}

#[derive(Serialize, ToSchema)]
pub struct Paused {
    pub session: String,
    /// The recording is paused (output is not written until it is resumed).
    pub paused: bool,
}

/// Pauses or resumes the recording of a running session. A person only (an AI session never
/// switches a recording); resuming needs the step-up (its route is destructive), pausing does not.
async fn pause_to(app: &App, me: &Caller, session: &str, on: bool) -> ApiResult<Paused> {
    if matches!(Principal::of(me).0, Who::Session(_)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "gate_refused",
            "only a person may pause or resume a recording",
        ));
    }
    if !session_id(session) {
        return Err(ApiError::not_found("no such recording"));
    }
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT host_id FROM leyline_recordings WHERE session = ? AND ended_at IS NULL",
    )
    .bind(session)
    .fetch_optional(&app.pool)
    .await?;
    let (host,) = row.ok_or_else(|| ApiError::not_found("no recording is running for it"))?;
    if !crate::record::pause(session, on).await {
        return Err(ApiError::not_found("no recording is running for it"));
    }
    let word = if on { "paused" } else { "resumed" };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("UPDATE leyline_recordings SET paused = ? WHERE session = ?")
        .bind(i64::from(on))
        .bind(session)
        .execute(&mut *tx)
        .await?;
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.recording.{word}"),
        entity: None,
        details: json!({"session": session, "host": host, "by_device": me.device.id}).to_string(),
    };
    audit::append(&mut tx, &row).await?;
    events::append(
        &mut tx,
        "leyline.session",
        &json!({"op": "recording", "id": session, "host": host, "recording": !on}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Paused {
        session: session.to_owned(),
        paused: on,
    }))
}

#[utoipa::path(post, path = "/sessions/{session}/recording/pause", operation_id = "leylinePauseRecording", tag = "leyline",
    params(("session" = String, Path, description = "Session id (`ls_...`)")),
    responses((status = 200, description = "The running recording stops writing output until resumed (a marker is written); a person only, no step-up; audited as `leyline.recording.paused`. 404 when none is running", body = Paused)))]
pub(crate) async fn pause(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(session): Path<String>,
) -> ApiResult<Paused> {
    pause_to(&app, &me, &session, true).await
}

#[utoipa::path(post, path = "/sessions/{session}/recording/resume", operation_id = "leylineResumeRecording", tag = "leyline",
    params(("session" = String, Path, description = "Session id (`ls_...`)")),
    responses((status = 200, description = "A paused recording writes again; a person only, needs a step-up; audited as `leyline.recording.resumed`", body = Paused)))]
pub(crate) async fn resume(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(session): Path<String>,
) -> ApiResult<Paused> {
    pause_to(&app, &me, &session, false).await
}

/// Removes recordings older than `keep` seconds, then the oldest until the rest fit in `cap`
/// bytes (a recording still being written is skipped), then files no row names. Returns how many
/// recordings went.
pub(crate) async fn prune(
    pool: &SqlitePool,
    dir: &FsPath,
    now: i64,
    keep: i64,
    cap: i64,
) -> Result<usize, sqlx::Error> {
    // Listed before the rows are read: a file seen here already has its row (the row is made first).
    let on_disk: Vec<String> = std::fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".cast.age"))
                .collect()
        })
        .unwrap_or_default();
    // (session, file, started_at, bytes, live)
    let all: Vec<(String, String, i64, i64, bool)> = sqlx::query_as(
        "SELECT r.session, r.file, r.started_at, r.bytes, (r.ended_at IS NULL AND s.ended_at IS NULL) \
         FROM leyline_recordings r JOIN leyline_sessions s ON s.id = r.session \
         ORDER BY r.started_at, r.session",
    )
    .fetch_all(pool)
    .await?;
    let mut total: i64 = all.iter().map(|r| r.3).sum();
    let mut gone = Vec::new();
    for (session, file, started, bytes, live) in &all {
        let old = now.saturating_sub(*started) > keep && !live;
        if old || (total > cap && !live) {
            gone.push((session.clone(), file.clone()));
            total -= bytes;
        }
    }
    for (session, file) in &gone {
        let _ = std::fs::remove_file(dir.join(file));
        sqlx::query("DELETE FROM leyline_recordings WHERE session = ?")
            .bind(session)
            .execute(pool)
            .await?;
    }
    for name in on_disk {
        if !all.iter().any(|r| r.1 == name) {
            let _ = std::fs::remove_file(dir.join(name));
        }
    }
    if !gone.is_empty() {
        let mut tx = begin_write(pool).await?;
        let row = NewAuditEvent {
            actor: BY,
            action: "leyline.recording.pruned".to_owned(),
            entity: None,
            details: json!({"removed": gone.len()}).to_string(),
        };
        audit::append(&mut tx, &row).await?;
        tx.commit().await?;
    }
    Ok(gone.len())
}

struct Prune;

impl JobHandler for Prune {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = APP.get().ok_or("the leyline module is not attached")?;
            let dir = crate::record::dir(app)?;
            let n = prune(&app.pool, &dir, app.clock.unix(), KEEP_SECS, CAP_BYTES)
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

pub(crate) fn jobs() -> Vec<Job> {
    let job = Job::new("prune_recordings", Schedule::Every(86400), Arc::new(Prune));
    vec![Job {
        missed: Missed::Skip,
        ..job
    }]
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ainkrad_core_server::module::Module;
    use ainkrad_core_server::store::{connect, migrate};

    use super::*;
    use crate::Leyline;

    const DAY: i64 = 86400;

    async fn store(tag: &str) -> (SqlitePool, PathBuf) {
        let dir = std::env::temp_dir().join(format!("leyline-prune-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rec")).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Leyline)];
        migrate::migrate_modules(&pool, &modules).await.unwrap();
        sqlx::query("INSERT INTO leyline_hosts (id, name, address, username) VALUES ('h_0000000000000001', 'a', 'a.example.com', 'u')")
            .execute(&pool)
            .await
            .unwrap();
        (pool, dir.join("rec"))
    }

    /// A recorded session `n` that started at `started` with a file of `bytes` (`live`: not over).
    async fn add(pool: &SqlitePool, dir: &FsPath, n: u32, started: i64, bytes: i64, live: bool) {
        let id = format!("ls_{n:016x}");
        sqlx::query(
            "INSERT INTO leyline_sessions (id, host_id, terminal, runner, principal, ended_at) \
             VALUES (?, 'h_0000000000000001', 't_1', 'd_1', 'p', ?)",
        )
        .bind(&id)
        .bind((!live).then_some("2026-01-01T00:00:00Z"))
        .execute(pool)
        .await
        .unwrap();
        let file = format!("{id}.cast.age");
        sqlx::query(
            "INSERT INTO leyline_recordings (session, host_id, file, started_at, ended_at, bytes) \
             VALUES (?, 'h_0000000000000001', ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&file)
        .bind(started)
        .bind((!live).then_some(started + 10))
        .bind(bytes)
        .execute(pool)
        .await
        .unwrap();
        std::fs::write(dir.join(file), b"x").unwrap();
    }

    async fn left(pool: &SqlitePool) -> Vec<String> {
        sqlx::query_scalar("SELECT session FROM leyline_recordings ORDER BY started_at")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn prune_drops_the_old_then_the_oldest_until_the_cap_holds() {
        let (pool, dir) = store("cap").await;
        let now = 100 * DAY;
        add(&pool, &dir, 1, now - 40 * DAY, 600, false).await; // past 30 days
        add(&pool, &dir, 2, now - 5 * DAY, 600, false).await; // oldest of the rest
        add(&pool, &dir, 3, now - 3 * DAY, 600, false).await;
        add(&pool, &dir, 4, now - DAY, 600, false).await;
        std::fs::write(dir.join("ls_00000000000000ff.cast.age"), b"x").unwrap(); // no row
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        let gone = prune(&pool, &dir, now, 30 * DAY, 1500).await.unwrap();
        assert_eq!(gone, 2);
        assert_eq!(
            left(&pool).await,
            ["ls_0000000000000003", "ls_0000000000000004"]
        );
        assert!(!dir.join("ls_0000000000000001.cast.age").exists());
        assert!(!dir.join("ls_0000000000000002.cast.age").exists());
        assert!(dir.join("ls_0000000000000003.cast.age").exists());
        assert!(
            !dir.join("ls_00000000000000ff.cast.age").exists(),
            "a file with no row"
        );
        assert!(
            dir.join("notes.txt").exists(),
            "only recordings are touched"
        );
        let kept: i64 = sqlx::query_scalar("SELECT sum(bytes) FROM leyline_recordings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(kept <= 1500);
        // The sessions stay in the history; only their recordings went.
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM leyline_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sessions, 4);
        // Nothing more to do, and a second pass at the same time changes nothing.
        assert_eq!(prune(&pool, &dir, now, 30 * DAY, 1500).await.unwrap(), 0);
        // Time moves on: 31 days later every one of them is past its keep.
        assert_eq!(
            prune(&pool, &dir, now + 31 * DAY, 30 * DAY, 1500)
                .await
                .unwrap(),
            2
        );
        assert!(left(&pool).await.is_empty());
    }

    #[tokio::test]
    async fn a_recording_still_being_written_is_not_pruned_for_size() {
        let (pool, dir) = store("live").await;
        let now = 100 * DAY;
        add(&pool, &dir, 1, now - 2 * DAY, 5000, true).await;
        add(&pool, &dir, 2, now - DAY, 100, false).await;
        let gone = prune(&pool, &dir, now, 30 * DAY, 1000).await.unwrap();
        assert_eq!(gone, 1, "the finished one went, the live one stayed");
        assert_eq!(left(&pool).await, ["ls_0000000000000001"]);
    }

    #[tokio::test]
    async fn a_live_recording_is_not_pruned_for_age_either() {
        let (pool, dir) = store("liveage").await;
        let now = 100 * DAY;
        add(&pool, &dir, 1, now - 40 * DAY, 100, true).await;
        assert_eq!(prune(&pool, &dir, now, 30 * DAY, 1 << 30).await.unwrap(), 0);
        assert_eq!(left(&pool).await, ["ls_0000000000000001"]);
    }
}
