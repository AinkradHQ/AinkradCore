//! Versions (T4): full-text snapshots of a note. `auto` (the first save after 10 idle minutes, before a
//! restore, before a system rewrite), `named` (a person's), `conflict` (a head a merge could not keep).
//! At most 200 per note, `auto` pruned first, then `conflict`, then `named`. Restore is a normal save at
//! the head, so it is undone by restoring the auto version it made first.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::notes::{In, bad, id_has, id_ok, none, rand_id, view};
use crate::save::{Head, SaveOut, Snap, audit_only, commit_text, load};

const VERSIONS_MAX: i64 = 200;
const NAME_MAX: usize = 100;

/// Keeps `h`'s current text as a version of `kind`; an identical one for the same revision is reused.
pub(crate) async fn snapshot(
    conn: &mut SqliteConnection,
    h: &Head,
    kind: &str,
    name: Option<&str>,
    origin: &str,
) -> Result<String, ApiError> {
    if kind != "named" {
        let same: Option<String> = sqlx::query_scalar(
            "SELECT id FROM lore_versions WHERE note = ? AND rev = ? AND kind = ? AND text = ? LIMIT 1",
        )
        .bind(&h.id)
        .bind(h.rev)
        .bind(kind)
        .bind(&h.text)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = same {
            return Ok(id);
        }
    }
    let id = rand_id("lv_");
    sqlx::query(
        "INSERT INTO lore_versions (id, note, kind, name, rev, text, origin, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
    )
    .bind(&id)
    .bind(&h.id)
    .bind(kind)
    .bind(name)
    .bind(h.rev)
    .bind(&h.text)
    .bind(origin)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM lore_versions WHERE rowid IN (SELECT rowid FROM lore_versions WHERE note = ?1 AND id != ?2 \
         ORDER BY CASE kind WHEN 'auto' THEN 0 WHEN 'conflict' THEN 1 ELSE 2 END, created_at, rowid \
         LIMIT MAX((SELECT count(*) FROM lore_versions WHERE note = ?1) - ?3, 0))",
    )
    .bind(&h.id)
    .bind(&id)
    .bind(VERSIONS_MAX)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

#[derive(Serialize, ToSchema)]
pub struct VersionSummary {
    /// `lv_` and 12 base32 characters.
    pub id: String,
    /// `auto`, `named` or `conflict`.
    pub kind: String,
    pub name: Option<String>,
    /// The note revision this text was the head of.
    pub rev: i64,
    /// Who wrote the text: `person:d_…`, `session:as_…` or `system`.
    pub origin: String,
    pub created_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct VersionView {
    #[serde(flatten)]
    pub version: VersionSummary,
    pub text: String,
}

fn summary(r: &sqlx::sqlite::SqliteRow) -> Result<VersionSummary, sqlx::Error> {
    Ok(VersionSummary {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        name: r.try_get("name")?,
        rev: r.try_get("rev")?,
        origin: r.try_get("origin")?,
        created_at: r.try_get("created_at")?,
    })
}

#[utoipa::path(get, path = "/notes/{note}/versions", operation_id = "loreListVersions", tag = "lore",
    params(("note" = String, Path, description = "Note id")),
    responses((status = 200, description = "The note's versions, newest first, without text (at most 200)", body = Vec<VersionSummary>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Path(note): Path<String>,
) -> ApiResult<Vec<VersionSummary>> {
    if !id_ok(&note) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    load(&mut conn, &note).await?;
    let rows = sqlx::query(
        "SELECT id, kind, name, rev, origin, created_at FROM lore_versions WHERE note = ? \
         ORDER BY created_at DESC, rowid DESC LIMIT ?",
    )
    .bind(&note)
    .bind(VERSIONS_MAX)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(rows.iter().map(summary).collect::<Result<_, _>>()?))
}

async fn version_text(
    conn: &mut SqliteConnection,
    note: &str,
    v: &str,
) -> Result<VersionView, ApiError> {
    if !id_has("lv_", v) {
        return Err(ApiError::not_found("no such version"));
    }
    let r = sqlx::query("SELECT id, kind, name, rev, origin, created_at, text FROM lore_versions WHERE id = ? AND note = ?")
        .bind(v)
        .bind(note)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| ApiError::not_found("no such version"))?;
    Ok(VersionView {
        version: summary(&r)?,
        text: r.try_get("text")?,
    })
}

#[utoipa::path(get, path = "/notes/{note}/versions/{version}", operation_id = "loreGetVersion", tag = "lore",
    params(("note" = String, Path, description = "Note id"), ("version" = String, Path, description = "Version id")),
    responses((status = 200, description = "One version with its text", body = VersionView)))]
pub(crate) async fn get(
    State(app): State<App>,
    Path((note, v)): Path<(String, String)>,
) -> ApiResult<VersionView> {
    if !id_ok(&note) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(version_text(&mut conn, &note, &v).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct NewVersion {
    /// 1 to 100 characters, no control characters.
    pub name: String,
}

#[utoipa::path(post, path = "/notes/{note}/versions", operation_id = "loreNameVersion", tag = "lore",
    params(("note" = String, Path, description = "Note id")), request_body = NewVersion,
    responses((status = 200, description = "A `named` version of the head text (audited as `lore.note.version`). A trashed note refuses", body = VersionSummary)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
    In(req): In<NewVersion>,
) -> ApiResult<VersionSummary> {
    if !id_ok(&note) {
        return Err(none());
    }
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > NAME_MAX || name.chars().any(char::is_control) {
        return Err(bad());
    }
    let who = format!("person:{}", me.device.id);
    let mut tx = begin_write(&app.pool).await?;
    let h = load(&mut tx, &note).await?;
    if h.trashed {
        return Err(ApiError::conflict("the note is in the trash"));
    }
    let id = snapshot(&mut tx, &h, "named", Some(name), &who).await?;
    audit_only(&mut tx, "lore.note.version", &note, json!({"version": id})).await?;
    let out = version_text(&mut tx, &note, &id).await?.version;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct RestoreReq {
    /// The version id to bring back.
    pub version: String,
}

#[utoipa::path(post, path = "/notes/{note}/restore", operation_id = "loreRestoreVersion", tag = "lore",
    params(("note" = String, Path, description = "Note id")), request_body = RestoreReq,
    responses((status = 200, description = "The head is now exactly the version's text (a normal save at rev+1, audited as `lore.note.reverted`). `version` is an auto version of the text it replaced: restoring that one undoes this. Restoring the head's own text changes nothing. A trashed note refuses", body = SaveOut)))]
pub(crate) async fn restore(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
    In(req): In<RestoreReq>,
) -> ApiResult<SaveOut> {
    if !id_ok(&note) {
        return Err(none());
    }
    let who = format!("person:{}", me.device.id);
    let mut tx = begin_write(&app.pool).await?;
    let h = load(&mut tx, &note).await?;
    if h.trashed {
        return Err(ApiError::conflict("the note is in the trash"));
    }
    let v = version_text(&mut tx, &note, &req.version).await?;
    let mut undo = None;
    if v.text != h.text {
        undo = Some(snapshot(&mut tx, &h, "auto", None, &who).await?);
        commit_text(&mut tx, &h, &v.text, &who, "person", Snap::Never).await?;
        audit_only(
            &mut tx,
            "lore.note.reverted",
            &note,
            json!({"version": v.version.id}),
        )
        .await?;
    }
    let out = SaveOut {
        missing_attachments: crate::attachments::missing(&mut tx, &v.text).await?,
        note: view(&mut tx, &note).await?,
        outcome: "restored".to_owned(),
        version: undo,
    };
    tx.commit().await?;
    Ok(Json(out))
}
