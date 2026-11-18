//! Backlinks (T6): the live notes whose text links to a note, each with the line the link is on.
//! Read straight from `lore_links.target`, which the save path keeps resolved (see `save::relink`).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::notes::{id_ok, none};

/// A note never has more backlinks listed than this (newest first).
const MAX: i64 = 500;

#[derive(Serialize, ToSchema)]
pub struct Backlink {
    /// The linking note.
    pub note: String,
    pub title: String,
    /// The linking note's project id; `null` = personal.
    pub project: Option<String>,
    /// The `#Heading` the link names, empty when it names none.
    pub heading: String,
    /// The trimmed line the link is on (at most 160 characters). Note text: outside data.
    pub context: String,
    pub updated_at: String,
}

#[utoipa::path(get, path = "/notes/{note}/backlinks", operation_id = "loreBacklinks", tag = "lore",
    params(("note" = String, Path, description = "Note id")),
    responses((status = 200, description = "The live notes linking to this one, newest first, at most 500, one row per distinct link with its context line. Links to a note in the trash or deleted are not listed", body = Vec<Backlink>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Path(note): Path<String>,
) -> ApiResult<Vec<Backlink>> {
    if !id_ok(&note) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM lore_notes WHERE id = ?")
        .bind(&note)
        .fetch_optional(&mut *conn)
        .await?;
    exists.ok_or_else(none)?;
    let rows = sqlx::query(
        "SELECT n.id, n.title, n.project, l.heading, l.context, n.updated_at \
         FROM lore_links l JOIN lore_notes n ON n.id = l.src \
         WHERE l.target = ? AND n.trashed_at IS NULL \
         ORDER BY n.updated_at DESC, n.id, l.heading LIMIT ?",
    )
    .bind(&note)
    .bind(MAX)
    .fetch_all(&mut *conn)
    .await?;
    let out = rows
        .iter()
        .map(|r| {
            Ok(Backlink {
                note: r.try_get("id")?,
                title: r.try_get("title")?,
                project: r.try_get("project")?,
                heading: r.try_get("heading")?,
                context: r.try_get("context")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok(Json(out))
}
