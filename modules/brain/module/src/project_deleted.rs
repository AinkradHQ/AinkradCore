//! Project events the Brain reads besides `project.created` (API 112). A project made with a chosen
//! room (`adopt`) links that room. A deleted project (`project.deleted`) drops its Brain link. The room stays,
//! unless this module made it for the project (the `brain.room.created` audit row names the
//! project) and it holds no records: then it is archived. Read by the same job as
//! `project.created` ([`crate::project_rooms::step`]).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use ainkrad_core_server::store::begin_write;
use serde_json::json;

use crate::{Brain, record};

/// Whether the room was made for project `id` by [`crate::project_rooms`] and has no records or
/// session claims.
/// A room whose file cannot be opened (no key yet) counts as not empty: nothing is lost then.
pub(crate) async fn made_for_and_empty(app: &App, b: &Brain, id: &str, room: &str) -> Result<bool, ApiError> {
    let made: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'brain.room.created' \
         AND details LIKE ? AND details LIKE ?",
    )
    .bind(format!("%\"project\":\"{id}\"%"))
    .bind(format!("%\"room\":\"{room}\"%"))
    .fetch_one(&app.pool)
    .await?;
    let claims: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_session_rooms WHERE room = ?")
        .bind(room)
        .fetch_one(&app.pool)
        .await?;
    if made == 0 || claims > 0 {
        return Ok(false);
    }
    let Ok(pool) = crate::distil::canon(app, b, room).await else {
        return Ok(false);
    };
    let records: Result<i64, _> = sqlx::query_scalar("SELECT count(*) FROM records")
        .fetch_one(&pool)
        .await;
    pool.close().await;
    Ok(matches!(records, Ok(0)))
}

/// Removes the project's link (audited as `brain.room.unlinked`), and archives its room when it
/// was made for it and is empty. Does nothing for a project with no link.
pub(crate) async fn forget(app: &App, b: &Brain, project: i64) -> Result<(), ApiError> {
    let id = project.to_string();
    let room: Option<String> =
        sqlx::query_scalar("SELECT room FROM brain_project_rooms WHERE project = ?")
            .bind(&id)
            .fetch_optional(&app.pool)
            .await?;
    let Some(room) = room else { return Ok(()) };
    let archive = made_for_and_empty(app, b, &id, &room).await?;
    let mut tx = begin_write(&app.pool).await?;
    let gone = sqlx::query("DELETE FROM brain_project_rooms WHERE project = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 0 {
        return Ok(());
    }
    record(
        &mut tx,
        "brain.room.unlinked",
        json!({"project": id, "room": room, "why": "project_deleted", "archived": archive}),
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
    Ok(())
}

/// A project made with a chosen room (`project.created` carries `room`): links it, if it is still
/// there and free; false when it is not, and the project then gets a room of its own.
pub(crate) async fn adopt(app: &App, id: i64, room: &str) -> Result<bool, ApiError> {
    let project = id.to_string();
    let mut tx = begin_write(&app.pool).await?;
    let ok: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_projects WHERE id = ?1) \
              + (SELECT count(*) FROM brain_rooms WHERE id = ?2) \
              - (SELECT count(*) FROM brain_project_rooms WHERE project = ?3 OR room = ?2)",
    )
    .bind(id)
    .bind(room)
    .bind(&project)
    .fetch_one(&mut *tx)
    .await?;
    if ok != 2 {
        return Ok(false);
    }
    crate::project_rooms::link(&mut tx, &project, room).await?;
    tx.commit().await?;
    Ok(true)
}
