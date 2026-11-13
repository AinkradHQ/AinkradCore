//! Rooms (E0-5): the registry of opened rooms, the `RoomAccess` handle and the routes that list and
//! open them. A room's file is reachable only through a handle, and a handle is made only here, for
//! a room whose lease is live: opening needs a step-up (the route is destructive) and the lease is
//! enforced in code, not left to the app (A-3: `test-support` builds set leases in seconds).

use std::collections::HashMap;
use std::sync::Mutex;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::files::{self, CANON, FileError};
use crate::{Brain, code, record};

/// A room's open file. Not constructible outside this module: a handle that exists means the room
/// was opened with a live lease and its file migrated.
///
/// ```compile_fail
/// let pool: sqlx::SqlitePool = todo!();
/// let _forged = brain_module::rooms::RoomAccess { room: "r".to_owned(), pool };
/// ```
pub struct RoomAccess {
    room: String,
    pool: SqlitePool,
}

impl RoomAccess {
    pub fn room(&self) -> &str {
        &self.room
    }

    /// The room's `canon.db`. It holds only this room's data.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessError {
    /// Never opened, or the lease ended.
    Closed,
    Unknown,
    /// The file was written by a newer binary: the room stays unmounted.
    Newer,
    Unavailable,
}

#[derive(Default)]
pub struct Rooms {
    /// Room id to the unix second its lease ends.
    open: Mutex<HashMap<String, i64>>,
    #[cfg(feature = "test-support")]
    lease_override: Mutex<Option<i64>>,
}

impl Rooms {
    #[cfg(feature = "test-support")]
    pub(crate) fn set_lease_override(&self, secs: i64) {
        *self
            .lease_override
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(secs);
    }

    fn lease_secs(&self, hours: i64) -> i64 {
        #[cfg(feature = "test-support")]
        if let Some(s) = *self
            .lease_override
            .lock()
            .unwrap_or_else(|e| e.into_inner())
        {
            return s;
        }
        hours * 3600
    }

    pub(crate) fn is_open(&self, room: &str, now: i64) -> bool {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(room)
            .is_some_and(|until| *until > now)
    }

    /// The handle for `room`, if its lease is live.
    pub async fn access(
        &self,
        app: &App,
        key: &[u8; 32],
        room: &str,
    ) -> Result<RoomAccess, AccessError> {
        if !files::safe_id(room) {
            return Err(AccessError::Unknown);
        }
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms WHERE id = ?")
            .bind(room)
            .fetch_one(&app.pool)
            .await
            .map_err(|_| AccessError::Unavailable)?;
        if known == 0 {
            return Err(AccessError::Unknown);
        }
        if !self.is_open(room, app.clock.unix()) {
            return Err(AccessError::Closed);
        }
        let pool = files::open_migrated(
            &files::room_path(&files::root(app), room),
            key,
            false,
            CANON,
        )
        .await
        .map_err(|e| match e {
            FileError::Newer { .. } => AccessError::Newer,
            _ => AccessError::Unavailable,
        })?;
        Ok(RoomAccess {
            room: room.to_owned(),
            pool,
        })
    }
}

#[derive(Serialize, ToSchema)]
pub struct RoomView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub state: String,
    pub review_days: i64,
    /// Sources stored, counted from hashes in the control plane (no need to open the room).
    pub sources: i64,
    /// Whether the room's lease is live.
    pub open: bool,
}

#[utoipa::path(get, path = "/rooms", operation_id = "brainRooms", tag = "brain",
    responses((status = 200, description = "Every room: names, kinds and counts", body = Vec<RoomView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
) -> ApiResult<Vec<RoomView>> {
    let rows = sqlx::query(
        "SELECT r.id, r.name, r.kind, r.state, r.review_days, \
         (SELECT count(*) FROM brain_seen s WHERE s.room = r.id) AS sources FROM brain_rooms r ORDER BY lower(r.name)",
    )
    .fetch_all(&app.pool)
    .await?;
    let now = app.clock.unix();
    let mut out = Vec::new();
    for r in rows {
        let id: String = r.try_get("id")?;
        out.push(RoomView {
            open: b.rooms().is_open(&id, now),
            name: r.try_get("name")?,
            kind: r.try_get("kind")?,
            state: r.try_get("state")?,
            review_days: r.try_get("review_days")?,
            sources: r.try_get("sources")?,
            id,
        });
    }
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct Opened {
    pub room: String,
    /// When the lease ends (RFC 3339).
    pub open_until: String,
}

#[utoipa::path(post, path = "/rooms/{room}/open", operation_id = "brainOpenRoom", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "The room is open for its lease (step-up; audited as `brain.room.opened`)", body = Opened)))]
pub(crate) async fn open(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(room): Path<String>,
) -> ApiResult<Opened> {
    let hours: i64 = sqlx::query_scalar("SELECT lease_hours FROM brain_room_policy WHERE room = ?")
        .bind(&room)
        .fetch_optional(&app.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("no such room"))?;
    let key = b.key(&app).await?;
    let now = app.clock.unix();
    // Opening the file now proves it is readable by this binary before the lease starts.
    match files::open_migrated(
        &files::room_path(&files::root(&app), &room),
        &key,
        false,
        CANON,
    )
    .await
    {
        Ok(p) => p.close().await,
        Err(FileError::Newer { found, known }) => {
            let mut tx = begin_write(&app.pool).await?;
            record(
                &mut tx,
                "brain.room.refused",
                json!({"room": room, "found": found, "known": known}),
                Some((
                    "brain.alarm",
                    json!({"room": room, "why": "room_file_newer"}),
                )),
            )
            .await?;
            tx.commit().await?;
            return Err(code(
                409,
                "room_file_newer",
                "the room file was written by a newer version; it stays closed",
            ));
        }
        Err(e) => return Err(code(500, "room_unavailable", e.to_string())),
    }
    let until = now + b.rooms().lease_secs(hours);
    b.rooms()
        .open
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(room.clone(), until);
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.room.opened",
        json!({"room": room, "until": until}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Opened {
        room,
        open_until: iso_of_unix(until),
    }))
}
