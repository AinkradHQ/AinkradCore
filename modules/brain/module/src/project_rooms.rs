//! Project and room, strictly 1:1 (Projects plan D2, P1-03). The Core never depends on the Brain:
//! the link is a Brain table, `brain_project_rooms`, and this module reads the Core's
//! `project.created` events from the log. A new project gets a `product` room named after it
//! (unless a room was linked first); a project and a room can each be linked once, and archiving a
//! project leaves its room. No rule, overview or import logic is touched here.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::{begin_write, events};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use crate::files::{self, CANON};
use crate::review::room_id;
use crate::{Brain, code, record};

/// How often the `brain_project_rooms` job reads new `project.created` events.
const EVERY_SECS: u64 = 10;

#[derive(Serialize, ToSchema)]
pub struct ProjectRoomLink {
    pub project: String,
    pub room: String,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LinkRoom {
    /// An existing room that no other project is linked to.
    pub room: String,
}

fn project_id(p: &str) -> Result<i64, ApiError> {
    p.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such project"))
}

/// Links `project` to `room` in the caller's write transaction. 409 `project_linked` or
/// `room_linked` when either side already is (the table's two UNIQUE paths are the backstop).
pub(crate) async fn link(conn: &mut SqliteConnection, project: &str, room: &str) -> Result<(), ApiError> {
    let by_project: i64 =
        sqlx::query_scalar("SELECT count(*) FROM brain_project_rooms WHERE project = ?")
            .bind(project)
            .fetch_one(&mut *conn)
            .await?;
    if by_project > 0 {
        return Err(code(
            409,
            "project_linked",
            "that project is linked already",
        ));
    }
    let by_room: i64 =
        sqlx::query_scalar("SELECT count(*) FROM brain_project_rooms WHERE room = ?")
            .bind(room)
            .fetch_one(&mut *conn)
            .await?;
    if by_room > 0 {
        return Err(code(409, "room_linked", "that room is linked already"));
    }
    sqlx::query("INSERT INTO brain_project_rooms (project, room) VALUES (?, ?)")
        .bind(project)
        .bind(room)
        .execute(&mut *conn)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_unique_violation() => code(
                409,
                "already_linked",
                "the project or the room is linked already",
            ),
            _ => e.into(),
        })?;
    record(
        conn,
        "brain.room.linked",
        json!({"project": project, "room": room}),
        Some((
            "brain.room",
            json!({"op": "linked", "project": project, "room": room}),
        )),
    )
    .await?;
    Ok(())
}

/// A new AI session of `project` claims the project's room, if it has one (P3-02): the same
/// claim as `brainClaimRoom` (the room's model policy against the session's whole chain). A
/// project with no room claims nothing. `Err` is why the claim was refused; the Core then ends the
/// session unstarted.
pub(crate) async fn claim_for_session(
    app: &App,
    session: &str,
    project: i64,
    by: &str,
) -> Result<(), String> {
    let room: Option<String> =
        sqlx::query_scalar("SELECT room FROM brain_project_rooms WHERE project = ?")
            .bind(project.to_string())
            .fetch_optional(&app.pool)
            .await
            .map_err(|e| e.to_string())?;
    match room {
        None => Ok(()),
        Some(room) => crate::claim::claim(app, &room, session, by)
            .await
            .map(drop)
            .map_err(|e| e.message),
    }
}

/// A launch of a project session needs its claim when the project has a room: a session that
/// lost its claim (or never got one) would clone the project's repos without the room's policy.
pub(crate) async fn require_claim(app: &App, session: &str, project: i64) -> Result<(), String> {
    let missing: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM brain_project_rooms WHERE project = ?1) \
         AND NOT EXISTS (SELECT 1 FROM brain_session_rooms WHERE session = ?2)",
    )
    .bind(project.to_string())
    .bind(session)
    .fetch_one(&app.pool)
    .await
    .map_err(|e| e.to_string())?;
    if missing {
        return Err("the project has a room and this session holds no claim on it".to_owned());
    }
    Ok(())
}

/// How long the start bundle may take before the session starts without it.
const BUNDLE_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// What an AI session starts with (P3-03, B8-02): the approved instructions of the room it claimed,
/// then `brainAiContext(start)` of that room plus the me card (a session with no claim gets the
/// me card only).
///
/// SECURITY MODEL
/// - The bundle goes in the instruction text the runner writes to a private file (claude), sends as
///   `developerInstructions` (codex) or links as `GEMINI.md` (agy). It is never a user turn.
/// - It is the op's own output, so it is already wrapped once in the outside-data envelope (the
///   no-echo guard cuts that envelope before distil), its record ids are already in
///   `brain_session_loaded`, and the me-card provider gate and room policy already ran.
///   Nothing here reads memory or writes anything itself. No credential is involved.
/// - The approved instructions stay plain text, as before; they are left out of the bundle.
/// - Fail open: an op error or a slow op (3 s) gives the plain instructions, or `None`.
/// - Budget: the op's start cap, 1,500 tokens.
pub(crate) async fn instructions_for_session(
    app: &App,
    b: &Brain,
    session: &str,
) -> Option<String> {
    let room: Option<String> =
        sqlx::query_scalar("SELECT room FROM brain_session_rooms WHERE session = ?")
            .bind(session)
            .fetch_optional(&app.pool)
            .await
            .ok()
            .flatten();
    // The approved instructions go only to a session that may see the room now (the same gate as
    // the op), so a link made while it could, or one the policy chain no longer allows, sends none.
    let visible = match &room {
        Some(r) => matches!(
            crate::access::visible_room(app, session, r).await,
            Ok(Some(_))
        ),
        None => false,
    };
    let plain = match &room {
        Some(room) if visible => match crate::distil::canon(app, b, room).await {
            Ok(pool) => {
                let text = approved_instructions(&pool).await;
                pool.close().await;
                // GEMINI-style CLIs expand `@path` imports: break them in the person's text too.
                text.map(|t| ainkrad_core::untrusted::defang(&t))
            }
            Err(_) => None,
        },
        _ => None,
    };
    let bundle = start_bundle(app, b, session, room.as_deref()).await;
    join(plain, bundle)
}

/// The wrapped start bundle, or `None` when there is nothing to add or the op failed.
async fn start_bundle(app: &App, b: &Brain, session: &str, room: Option<&str>) -> Option<String> {
    // The op's own scope, checked as `ainkrad_call` would: the creator's current `read` scope.
    let scopes = ainkrad_core_server::ops_catalog::session_scopes(&app.pool, session)
        .await
        .ok()?;
    if !scopes.iter().any(|s| s == "read") {
        return None;
    }
    let q = crate::context::AiContextQuery {
        mode: "start".to_owned(),
        room: room.map(str::to_owned),
        prompt: None,
        budget: None,
    };
    let opts = crate::context::Opts {
        me_only: room.is_none(),
        no_instructions: true,
    };
    let got = tokio::time::timeout(BUNDLE_WAIT, crate::context::build(app, b, session, q, opts))
        .await
        .ok()?
        .ok()?;
    Some(got.text).filter(|t| !t.is_empty())
}

/// Plain instructions first, the bundle after a blank line.
fn join(plain: Option<String>, bundle: Option<String>) -> Option<String> {
    match (plain, bundle) {
        (Some(p), Some(b)) => Some(format!("{p}\n\n{b}")),
        (p, b) => p.or(b),
    }
}

/// The approved, non-blank instructions in a room's `room_overview` row.
async fn approved_instructions(pool: &sqlx::SqlitePool) -> Option<String> {
    let text: Option<String> = sqlx::query_scalar(
        "SELECT instructions FROM room_overview \
         WHERE id = 1 AND instructions_approved_at IS NOT NULL",
    )
    .fetch_optional(pool)
    .await
    .ok()??;
    text.filter(|t| !t.trim().is_empty())
}

#[cfg(test)]
mod instructions_tests {
    use super::{approved_instructions, join};

    #[test]
    fn the_bundle_follows_the_plain_text_and_either_alone_passes() {
        let (p, b) = (Some("Use tabs.".to_owned()), Some("<<<B>>>".to_owned()));
        assert_eq!(
            join(p.clone(), b.clone()).as_deref(),
            Some("Use tabs.\n\n<<<B>>>")
        );
        assert_eq!(join(p.clone(), None), p);
        assert_eq!(join(None, b.clone()), b);
        assert_eq!(join(None, None), None);
    }

    /// The no-echo guard cuts the bundle out of a transcript that repeats the instructions, and
    /// leaves the approved plain text (which is the person's own).
    #[test]
    fn the_echo_guard_strips_the_bundle() {
        let bundle = ainkrad_core::untrusted::wrap(
            "Brain memory | start",
            "- [r1] Deploys go out on Friday.",
        );
        let text = join(Some("Use tabs.".to_owned()), Some(bundle)).unwrap();
        let out = crate::echo::strip(&format!("Assistant: {text}"), &[]);
        assert!(!out.contains("Friday") && !out.contains("[r1]"), "{out}");
        assert!(out.contains("Use tabs."), "{out}");
    }

    async fn room(text: Option<&str>, approved: Option<&str>) -> sqlx::SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE room_overview (id INTEGER PRIMARY KEY, instructions TEXT, \
             instructions_approved_at TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO room_overview (id, instructions, instructions_approved_at) VALUES (1, ?, ?)")
            .bind(text)
            .bind(approved)
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    #[tokio::test]
    async fn only_approved_text_is_returned() {
        let t = Some("Use tabs.");
        let a = Some("2026-11-18T10:00:00.000Z");
        assert_eq!(approved_instructions(&room(t, a).await).await.as_deref(), t);
        assert_eq!(approved_instructions(&room(t, None).await).await, None);
        assert_eq!(approved_instructions(&room(None, a).await).await, None);
        assert_eq!(
            approved_instructions(&room(Some(" \n"), a).await).await,
            None
        );
    }
}

#[utoipa::path(put, path = "/projects/{project}/room", operation_id = "brainLinkProjectRoom", tag = "brain",
    params(("project" = String, Path, description = "The Core project's id")),
    request_body = LinkRoom,
    responses((status = 200, description = "Links the project to an existing room (audited as `brain.room.linked`). 404 for no such project or room; 409 `project_linked` or `room_linked` when either already has its one partner", body = ProjectRoomLink)))]
pub(crate) async fn link_route(
    State(app): State<App>,
    Extension(_b): Extension<Brain>,
    Path(project): Path<String>,
    Json(req): Json<LinkRoom>,
) -> ApiResult<ProjectRoomLink> {
    let id = project_id(&project)?;
    let mut tx = begin_write(&app.pool).await?;
    let known: i64 = sqlx::query_scalar("SELECT count(*) FROM core_projects WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM brain_rooms WHERE id = ?")
        .bind(&req.room)
        .fetch_optional(&mut *tx)
        .await?;
    let (true, Some(name)) = (known > 0, name) else {
        return Err(ApiError::not_found("no such project or room"));
    };
    link(&mut tx, &id.to_string(), &req.room).await?;
    tx.commit().await?;
    Ok(Json(ProjectRoomLink {
        project: id.to_string(),
        room: req.room,
        name,
    }))
}

#[utoipa::path(delete, path = "/projects/{project}/room", operation_id = "brainUnlinkProjectRoom", tag = "brain",
    params(("project" = String, Path, description = "The Core project's id")),
    responses((status = 200, description = "Unlinks the project; the room stays and can be linked to another project, unless the Brain made it for the project and it holds nothing (no records, no session claims): then it is archived (audited as `brain.room.unlinked`). 404 when the project has no room", body = ProjectRoomLink)))]
pub(crate) async fn unlink_route(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(project): Path<String>,
) -> ApiResult<ProjectRoomLink> {
    let id = project_id(&project)?.to_string();
    // The Brain's own room, with nothing in it, is archived with the link; any other stays.
    let linked: Option<String> =
        sqlx::query_scalar("SELECT room FROM brain_project_rooms WHERE project = ?")
            .bind(&id)
            .fetch_optional(&app.pool)
            .await?;
    let archive = match &linked {
        Some(room) => crate::project_deleted::made_for_and_empty(&app, &b, &id, room).await?,
        None => false,
    };
    let mut tx = begin_write(&app.pool).await?;
    let room: String =
        sqlx::query_scalar("DELETE FROM brain_project_rooms WHERE project = ? RETURNING room")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| ApiError::not_found("the project has no room"))?;
    let name: String = sqlx::query_scalar("SELECT name FROM brain_rooms WHERE id = ?")
        .bind(&room)
        .fetch_one(&mut *tx)
        .await?;
    record(
        &mut tx,
        "brain.room.unlinked",
        json!({"project": id, "room": room, "archived": archive}),
        Some((
            "brain.room",
            json!({"op": "unlinked", "project": id, "room": room}),
        )),
    )
    .await?;
    if archive {
        sqlx::query("UPDATE brain_rooms SET state = 'archived' WHERE id = ? AND state = 'active'")
            .bind(&room)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(ProjectRoomLink {
        project: id,
        room,
        name,
    }))
}

/// Gives a new project its room: a `product` room named after it. Does nothing when the project
/// is gone or already linked (a room was linked first, or this event is read twice).
async fn make(app: &App, b: &Brain, id: i64, name: &str) -> Result<(), ApiError> {
    let project = id.to_string();
    let mut tx = begin_write(&app.pool).await?;
    let live: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_projects WHERE id = ?) \
         - (SELECT count(*) FROM brain_project_rooms WHERE project = ?)",
    )
    .bind(id)
    .bind(&project)
    .fetch_one(&mut *tx)
    .await?;
    if live != 1 {
        return Ok(());
    }
    // A room of that name exists already (another kind, another project's): make this one apart.
    let mut room = room_id(name);
    let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms WHERE id = ?")
        .bind(&room)
        .fetch_one(&mut *tx)
        .await?;
    if taken > 0 {
        room = room_id(&format!("{name} project {id}"));
    }
    sqlx::query("INSERT INTO brain_rooms (id, name, kind) VALUES (?, ?, 'product')")
        .bind(&room)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO brain_room_policy (room, auto_accept) VALUES (?, ?)")
        .bind(&room)
        .bind(crate::policy::AUTO_ACCEPT_ALL)
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        "brain.room.created",
        json!({"room": room, "kind": "product", "project": project}),
        Some((
            "brain.room",
            json!({"op": "created", "room": room, "name": name, "kind": "product"}),
        )),
    )
    .await?;
    link(&mut tx, &project, &room).await?;
    tx.commit().await?;
    // The room's own file, when the brain key is there; an import makes the key otherwise.
    // No key yet means no file here; `rooms::open` makes it on first open.
    if let Ok(key) = b.key(app).await {
        files::open_migrated(
            &files::room_path(&files::root(app), &room),
            &key,
            true,
            CANON,
        )
        .await
        .map_err(|e| code(500, "room_unavailable", e.to_string()))?
        .close()
        .await;
    }
    Ok(())
}

/// Reads the `project.created` and `project.deleted` events after the cursor: a new project gets
/// its room, a deleted one loses its link.
pub(crate) async fn step(app: &App, b: &Brain) -> Result<(), ApiError> {
    let from: i64 = sqlx::query_scalar("SELECT seq FROM brain_project_cursor")
        .fetch_optional(&app.pool)
        .await?
        .unwrap_or(0);
    let batch = events::list_events(&app.pool, from, 200).await?;
    let Some(last) = batch.last().map(|e| e.seq) else {
        return Ok(());
    };
    for e in &batch {
        match e.kind.as_str() {
            "project.created" => {
                let (Some(id), Some(name)) =
                    (e.payload["id"].as_i64(), e.payload["name"].as_str())
                else {
                    continue;
                };
                match e.payload["room"].as_str() {
                    Some(room) if crate::project_deleted::adopt(app, id, room).await? => {}
                    _ => make(app, b, id, name).await?,
                }
            }
            "project.deleted" => {
                if let Some(id) = e.payload["id"].as_i64() {
                    crate::project_deleted::forget(app, b, id).await?;
                }
            }
            _ => {}
        }
    }
    sqlx::query(
        "INSERT INTO brain_project_cursor (id, seq) VALUES (1, ?) \
         ON CONFLICT (id) DO UPDATE SET seq = excluded.seq",
    )
    .bind(last)
    .execute(&app.pool)
    .await?;
    Ok(())
}

struct RoomsJob(Brain);

impl JobHandler for RoomsJob {
    fn run<'a>(&'a self, _run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            step(app, &self.0)
                .await
                .map_err(|e| format!("{}: {}", e.code, e.message))
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_project_rooms",
        Schedule::Every(EVERY_SECS),
        Arc::new(RoomsJob(b.clone())),
    )
}

impl Brain {
    /// Reads the new `project.created` events now (the `brain_project_rooms` job does this every
    /// few seconds).
    pub async fn project_rooms_step(&self) -> Result<(), ApiError> {
        match self.inner.app.get() {
            Some(app) => step(app, self).await,
            None => Ok(()),
        }
    }
}
