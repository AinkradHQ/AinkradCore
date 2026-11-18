//! The save path (T2): `PUT /notes/{id}/text {base_rev, text}`. A save from the head writes `rev+1`; a stale
//! one is merged against the head with the base from the `lore_saves` ring (see `merge.rs`); nothing a person
//! typed is dropped in any branch. One write transaction per save: text, title, ring row, links, tags, event.
//! Renaming a note (its derived title changes) rewrites `[[Old]]` in the notes that link to it (T6), as
//! `system` saves in the same transaction, each with an auto version of what it replaced.
//!
//! Index (R1-04): links, tags and the FTS row are written in the same transaction, and links are resolved
//! (T6: same project, then personal, then any; newest wins) by `relink`. A note that appears, is renamed,
//! moved, trashed or restored re-resolves every link that names or pointed at it.
//!
//! ponytail: a rewritten linker whose own title changes does not cascade a second rename.
//! ponytail: `lore_fts` is keyed by the note's rowid, which VACUUM may renumber; `rebuild_fts` repairs it.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::merge::resolve;
use crate::notes::{In, NoteView, bad, id_ok, none, parsed, store_err, view};
use crate::versions;

const TEXT_MAX: usize = 2_000_000;
/// The ring keeps this many saved texts per note, and none older than a day (T2).
const RING: i64 = 20;
const LINKERS_MAX: i64 = 500;

/// The head of a note: what a save is resolved against.
pub(crate) struct Head {
    pub id: String,
    pub kind: String,
    pub text: String,
    pub rev: i64,
    pub title_norm: String,
    pub updated_by: String,
    pub trashed: bool,
}

pub(crate) async fn load(conn: &mut SqliteConnection, id: &str) -> Result<Head, ApiError> {
    let r = sqlx::query(
        "SELECT id, kind, text, rev, title_norm, updated_by, trashed_at IS NOT NULL AS trashed \
         FROM lore_notes WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?
    .ok_or_else(none)?;
    Ok(Head {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        text: r.try_get("text")?,
        rev: r.try_get("rev")?,
        title_norm: r.try_get("title_norm")?,
        updated_by: r.try_get("updated_by")?,
        trashed: r.try_get("trashed")?,
    })
}

/// The ring row and index of a note's first text (create, today): later saves can name rev 1 as their base.
pub(crate) async fn seed(
    conn: &mut SqliteConnection,
    id: &str,
    text: &str,
    p: &lore_model::Parsed,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO lore_saves (note, rev, text, at) VALUES (?, 1, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")
        .bind(id)
        .bind(text)
        .execute(&mut *conn)
        .await?;
    index(conn, id, p).await?;
    fts(conn, id).await?;
    Ok(relink(conn, id, None).await?)
}

/// The note's FTS row (title, body = the whole Markdown) in step with the note.
pub(crate) async fn fts(conn: &mut SqliteConnection, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM lore_fts WHERE rowid = (SELECT rowid FROM lore_notes WHERE id = ?)")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO lore_fts (rowid, title, body) SELECT rowid, title, text FROM lore_notes WHERE id = ?",
    )
    .bind(id)
    .execute(conn)
    .await
    .map(|_| ())
}

/// Rebuilds every FTS row from the notes (repair, and the proof that the incremental rows are right).
pub async fn rebuild_fts(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    let mut tx = begin_write(pool)
        .await
        .map_err(|_| sqlx::Error::PoolClosed)?;
    sqlx::query("DELETE FROM lore_fts")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO lore_fts (rowid, title, body) SELECT rowid, title, text FROM lore_notes",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// T6 resolution. Re-resolves every link that is `id`'s own, points at `id`, or names `id`'s current title
/// (or `old_norm`, the title it just left). A link's target is the live note with the title it names,
/// preferring the linking note's project, then personal, then any; ties go to the newest. No match = NULL.
pub(crate) async fn relink(
    conn: &mut SqliteConnection,
    id: &str,
    old_norm: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE lore_links SET target = ( \
             SELECT n.id FROM lore_notes n, lore_notes s \
             WHERE s.id = lore_links.src AND n.title_norm = lore_links.target_title_norm \
               AND n.trashed_at IS NULL AND n.id != s.id \
             ORDER BY CASE WHEN n.project IS s.project THEN 0 WHEN n.project IS NULL THEN 1 ELSE 2 END, \
                      n.updated_at DESC, n.id LIMIT 1) \
         WHERE src = ?1 OR target = ?1 OR target_title_norm = ?2 \
            OR target_title_norm = (SELECT title_norm FROM lore_notes WHERE id = ?1)",
    )
    .bind(id)
    .bind(old_norm)
    .execute(conn)
    .await
    .map(|_| ())
}

/// Links and tags of the note's current text, replacing the old rows.
async fn index(
    conn: &mut SqliteConnection,
    id: &str,
    p: &lore_model::Parsed,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM lore_links WHERE src = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM lore_tags WHERE note = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    for w in &p.wikilinks {
        sqlx::query("INSERT OR IGNORE INTO lore_links (src, target_title_norm, heading, context) VALUES (?, ?, ?, ?)")
            .bind(id)
            .bind(&w.title_norm)
            .bind(w.heading.as_deref().unwrap_or(""))
            .bind(&w.context)
            .execute(&mut *conn)
            .await?;
    }
    for t in &p.tags {
        sqlx::query("INSERT OR IGNORE INTO lore_tags (note, tag) VALUES (?, ?)")
            .bind(id)
            .bind(t)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

pub(crate) async fn audit_only(
    conn: &mut SqliteConnection,
    action: &str,
    id: &str,
    extra: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let mut d = json!({"note": id});
    if let (Some(o), Some(e)) = (d.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    let row = NewAuditEvent {
        actor: BY,
        action: action.to_owned(),
        entity: None,
        details: d.to_string(),
    };
    audit::append(conn, &row).await.map(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Snap {
    /// An auto version of the old text when the note was idle for 10 minutes (T4).
    IfIdle,
    Always,
    Never,
}

pub(crate) struct Wrote {
    pub rev: i64,
    /// The note's title (normalised) before this write, when the write renamed it.
    pub renamed_from: Option<String>,
}

/// Writes `text` as the head at `rev+1`. The caller has decided what the text is; this keeps the ring, the
/// index, the versions and the event in step. A daily note keeps its date title.
pub(crate) async fn write_text(
    conn: &mut SqliteConnection,
    h: &Head,
    text: &str,
    who: &str,
    origin: &str,
    snap: Snap,
) -> Result<Wrote, ApiError> {
    let p = parsed(text)?;
    let snapshot = match snap {
        Snap::Always => true,
        Snap::Never => false,
        Snap::IfIdle => {
            sqlx::query_scalar(
                "SELECT updated_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-10 minutes') FROM lore_notes WHERE id = ?",
            )
            .bind(&h.id)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    if snapshot && h.text != text {
        versions::snapshot(conn, h, "auto", None, who).await?;
    }
    let daily = h.kind == "daily";
    let rev: i64 = sqlx::query_scalar(
        "UPDATE lore_notes SET text = ?1, title = IIF(?2, title, ?3), title_norm = IIF(?2, title_norm, ?4), \
         rev = rev + 1, updated_by = ?5, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE id = ?6 RETURNING rev",
    )
    .bind(text)
    .bind(daily)
    .bind(&p.title)
    .bind(&p.title_norm)
    .bind(who)
    .bind(&h.id)
    .fetch_one(&mut *conn)
    .await
    .map_err(store_err)?;
    sqlx::query("INSERT INTO lore_saves (note, rev, text, at) VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))")
        .bind(&h.id)
        .bind(rev)
        .bind(text)
        .execute(&mut *conn)
        .await?;
    // The head row is never pruned, so a base from a later non-text revision still finds its text.
    sqlx::query(
        "DELETE FROM lore_saves WHERE note = ?1 AND rev < ?2 \
         AND (rev <= ?2 - ?3 OR at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day'))",
    )
    .bind(&h.id)
    .bind(rev)
    .bind(RING)
    .execute(&mut *conn)
    .await?;
    index(conn, &h.id, &p).await?;
    fts(conn, &h.id).await?;
    let renamed_from = (!daily && p.title_norm != h.title_norm).then(|| h.title_norm.clone());
    relink(conn, &h.id, renamed_from.as_deref()).await?;
    events::append(
        conn,
        "lore.note.changed",
        &json!({"id": h.id, "rev": rev, "origin": origin}),
    )
    .await?;
    Ok(Wrote { rev, renamed_from })
}

/// `write_text`, then the rename rewrite when the title moved.
pub(crate) async fn commit_text(
    conn: &mut SqliteConnection,
    h: &Head,
    text: &str,
    who: &str,
    origin: &str,
    snap: Snap,
) -> Result<i64, ApiError> {
    let w = write_text(conn, h, text, who, origin, snap).await?;
    if let Some(old) = w.renamed_from {
        let new_title = parsed(text)?.title;
        rename_linkers(conn, &h.id, &old, &new_title).await?;
    }
    Ok(w.rev)
}

/// T6: `[[old]]` in the notes linking to the renamed note now says the new title. Skipped when another live
/// note still carries the old title (the links may mean that one).
async fn rename_linkers(
    conn: &mut SqliteConnection,
    id: &str,
    old_norm: &str,
    new_title: &str,
) -> Result<(), ApiError> {
    let other: Option<String> = sqlx::query_scalar(
        "SELECT id FROM lore_notes WHERE title_norm = ? AND id != ? AND trashed_at IS NULL LIMIT 1",
    )
    .bind(old_norm)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    if other.is_some() {
        return Ok(());
    }
    let srcs: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT l.src FROM lore_links l JOIN lore_notes n ON n.id = l.src \
         WHERE l.target_title_norm = ? AND l.src != ? AND n.trashed_at IS NULL ORDER BY l.src LIMIT ?",
    )
    .bind(old_norm)
    .bind(id)
    .bind(LINKERS_MAX)
    .fetch_all(&mut *conn)
    .await?;
    for src in srcs {
        let h = load(conn, &src).await?;
        if let Some(text) = lore_model::rename_wikilinks(&h.text, old_norm, new_title) {
            write_text(conn, &h, &text, "system", "system", Snap::Always).await?;
            audit_only(conn, "lore.note.relinked", &src, json!({"target": id})).await?;
        }
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct SaveReq {
    /// The revision the client's text was edited from (the `rev` it last received).
    pub base_rev: i64,
    /// The whole Markdown document. At most 2 000 000 bytes.
    pub text: String,
}

#[derive(Serialize, ToSchema)]
pub struct SaveOut {
    #[serde(flatten)]
    pub note: NoteView,
    /// `saved`, `merged` (both sides kept; `text` is the merge), `conflict` (the client's lines won, the old head is
    /// the version named in `version`), `base_lost` (the base had left the ring; same keep) or `restored`.
    pub outcome: String,
    /// A version made by this call that holds text the head no longer has: the kept head (`conflict`,
    /// `base_lost`) or the undo point of a restore.
    pub version: Option<String>,
    /// Attachments the returned `text` names (`lore-attachment:<sha>`) that the Core does not hold (never
    /// uploaded, or swept): re-upload them from the local copy. Ascending, no repeats.
    pub missing_attachments: Vec<String>,
}

#[utoipa::path(put, path = "/notes/{note}/text", operation_id = "loreSaveText", tag = "lore",
    params(("note" = String, Path, description = "Note id")), request_body = SaveReq,
    responses((status = 200, description = "The head after the save. Edited from the head: written at rev+1. Stale: 3-way merged against the head (clean = both sides kept; conflicting = the client's lines win and the old head is kept as a `conflict` version; base gone from the ring = same). The returned `text` is what the client must show. A save that changes nothing does not move `rev`. A trashed note refuses", body = SaveOut)))]
pub(crate) async fn put_text(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(note): Path<String>,
    In(req): In<SaveReq>,
) -> ApiResult<SaveOut> {
    if !id_ok(&note) {
        return Err(none());
    }
    if req.text.len() > TEXT_MAX || req.base_rev < 1 {
        return Err(bad());
    }
    let who = format!("person:{}", me.device.id);
    let mut tx = begin_write(&app.pool).await?;
    let h = load(&mut tx, &note).await?;
    if h.trashed {
        return Err(ApiError::conflict("the note is in the trash"));
    }
    if req.base_rev > h.rev {
        return Err(ApiError::conflict("the revision is ahead of the note"));
    }
    let fresh = req.base_rev == h.rev;
    let base: Option<String> = if fresh {
        None
    } else {
        // The text at base_rev is the newest ring row at or below it: a revision that changed no text has no row.
        sqlx::query_scalar(
            "SELECT text FROM lore_saves WHERE note = ? AND rev <= ? ORDER BY rev DESC LIMIT 1",
        )
        .bind(&note)
        .bind(req.base_rev)
        .fetch_optional(&mut *tx)
        .await?
    };
    let r = resolve(fresh, base.as_deref(), &h.text, &req.text);
    let mut kept = None;
    if r.keep_head {
        kept = Some(versions::snapshot(&mut tx, &h, "conflict", None, &h.updated_by).await?);
        audit_only(
            &mut tx,
            "lore.note.conflict",
            &note,
            json!({"outcome": r.outcome.name()}),
        )
        .await?;
    }
    if r.text != h.text {
        commit_text(&mut tx, &h, &r.text, &who, "person", Snap::IfIdle).await?;
    }
    let missing_attachments = crate::attachments::missing(&mut tx, &r.text).await?;
    let out = SaveOut {
        missing_attachments,
        note: view(&mut tx, &note).await?,
        outcome: r.outcome.name().to_owned(),
        version: kept,
    };
    tx.commit().await?;
    Ok(Json(out))
}
