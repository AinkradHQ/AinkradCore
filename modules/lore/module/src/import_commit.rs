//! Commit and undo of an import run (R4-01, T12). Security model: only items the review left included act, only
//! on notes in the Lore tables, and every overwrite is reversible: an update keeps the old text as an `auto`
//! version first (T4) and remembers it; an edited note is never overwritten (its incoming text is kept as a
//! `conflict` version); undo puts back exactly what the run replaced, and trashes (never deletes) what it made.
//! Both walk the run in transactions of 200 items and store progress per item, so a stopped commit or undo
//! resumes when called again. No step-up is needed: nothing here is irreversible, except that undo leaves a note
//! alone when it was edited after the import (counted as `kept`).
//!
//! ponytail: undoing an update that renamed a note does not rewrite the links the rename rewrote.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use axum::Json;
use axum::extract::{Extension, Path, State};
use serde_json::json;
use sqlx::{Row, SqliteConnection, SqlitePool};

use crate::import::{RunView, record, run_view, set_state, sha_hex, state_of};
use crate::notes::{self, project_id, rand_id};
use crate::save::{self, Snap};
use crate::versions;

const CHUNK: i64 = 200;
/// Staged text is kept this long after a run ends.
const KEEP_DAYS: i64 = 30;

struct Item {
    seq: i64,
    origin: String,
    text: String,
    hash: String,
    project: Option<String>,
    match_note: Option<String>,
    flag: Option<String>,
    mark: String,
}

#[derive(Default)]
struct Done<'a> {
    result: &'a str,
    note: Option<String>,
    version: Option<String>,
    rev: Option<i64>,
    prev_hash: Option<String>,
    prev_run: Option<String>,
}

async fn done(conn: &mut SqliteConnection, run: &str, seq: i64, d: Done<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE lore_import_items SET result = ?, note = ?, version = ?, rev_after = ?, prev_hash = ?, prev_run = ? \
         WHERE run = ? AND seq = ?",
    )
    .bind(d.result)
    .bind(d.note)
    .bind(d.version)
    .bind(d.rev)
    .bind(d.prev_hash)
    .bind(d.prev_run)
    .bind(run)
    .bind(seq)
    .execute(conn)
    .await
    .map(|_| ())
}

/// One item. The note is looked at again here: the review may have been open for days.
async fn apply(conn: &mut SqliteConnection, run: &str, who: &str, it: Item) -> Result<(), ApiError> {
    let seq = it.seq;
    if it.mark != "include" || matches!(it.flag.as_deref(), Some("too_large" | "skipped")) {
        return Ok(done(conn, run, seq, Done { result: "skipped", ..Done::default() }).await?);
    }
    if let Some(nid) = &it.match_note {
        let live = sqlx::query("SELECT import_hash, import_run FROM lore_notes WHERE id = ? AND trashed_at IS NULL")
            .bind(nid)
            .fetch_optional(&mut *conn)
            .await?;
        if let Some(n) = live {
            let (imported, prev_run): (Option<String>, Option<String>) = (n.try_get("import_hash")?, n.try_get("import_run")?);
            let h = save::load(conn, nid).await?;
            let now = sha_hex(&h.text);
            if now == it.hash {
                return Ok(done(conn, run, seq, Done { result: "unchanged", note: Some(nid.clone()), ..Done::default() }).await?);
            }
            if imported.as_deref() != Some(now.as_str()) {
                // Edited since the import: keep the note, keep what the file says now as a version.
                let same: Option<String> = sqlx::query_scalar(
                    "SELECT id FROM lore_versions WHERE note = ? AND kind = 'conflict' AND text = ? LIMIT 1",
                )
                .bind(nid)
                .bind(&it.text)
                .fetch_optional(&mut *conn)
                .await?;
                let v = match same {
                    Some(v) => v,
                    None => versions::keep(conn, nid, h.rev, &it.text, "conflict", Some("import"), "system").await?,
                };
                save::audit_only(conn, "lore.note.conflict", nid, json!({"outcome": "import"})).await?;
                let d = Done { result: "conflict", note: Some(nid.clone()), version: Some(v), ..Done::default() };
                return Ok(done(conn, run, seq, d).await?);
            }
            let v = versions::snapshot(conn, &h, "auto", None, "system").await?;
            let rev = save::commit_text(conn, &h, &it.text, "system", "system", Snap::Never).await?;
            sqlx::query("UPDATE lore_notes SET import_run = ?, import_hash = ? WHERE id = ?")
                .bind(run)
                .bind(&it.hash)
                .bind(nid)
                .execute(&mut *conn)
                .await?;
            let d = Done {
                result: "updated",
                note: Some(nid.clone()),
                version: Some(v),
                rev: Some(rev),
                prev_hash: imported,
                prev_run,
            };
            return Ok(done(conn, run, seq, d).await?);
        }
    }
    // A new note. A project deleted since the review makes this item skipped, not the run fail.
    let project = match it.project.as_deref() {
        Some(p) => match project_id(conn, p).await {
            Ok(p) => Some(p),
            Err(_) => return Ok(done(conn, run, seq, Done { result: "skipped", ..Done::default() }).await?),
        },
        None => None,
    };
    // A trashed note of this origin gives it up, so the new note is the one a later import finds.
    sqlx::query("UPDATE lore_notes SET import_origin = NULL WHERE import_origin = ? AND trashed_at IS NOT NULL")
        .bind(&it.origin)
        .execute(&mut *conn)
        .await?;
    let id = rand_id("ln_");
    let parse = notes::parsed(&it.text)?;
    sqlx::query(
        "INSERT INTO lore_notes (id, project, title, title_norm, text, import_run, import_hash, import_origin, created_by, updated_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&project)
    .bind(&parse.title)
    .bind(lore_model::normalize_title(&parse.title))
    .bind(&it.text)
    .bind(run)
    .bind(&it.hash)
    .bind(&it.origin)
    .bind(who)
    .bind(who)
    .execute(&mut *conn)
    .await
    .map_err(notes::store_err)?;
    save::seed(conn, &id, &it.text, &parse).await?;
    notes::record(conn, "created", "changed", &id, 1, "import", project.as_deref()).await?;
    let d = Done { result: "created", note: Some(id), rev: Some(1), ..Done::default() };
    Ok(done(conn, run, seq, d).await?)
}

#[utoipa::path(post, path = "/imports/{run}/commit", operation_id = "loreCommitImport", tag = "lore",
    params(("run" = String, Path, description = "Import run id")),
    responses((status = 200, description = "The included items become notes: new ones are created, an unedited note of the same origin is updated (its old text kept as a version), an edited one is kept and the incoming text saved as a `conflict` version. Done in transactions of 200 items; calling it again on a `committing` run resumes it. Links between the new notes are resolved as each one lands. Reversible with `undo`", body = RunView)))]
pub(crate) async fn commit(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(run): Path<String>,
) -> ApiResult<RunView> {
    let who = format!("person:{}", me.device.id);
    loop {
        let mut tx = begin_write(&app.pool).await?;
        if state_of(&mut tx, &run, &["review", "committing"]).await? == "review" {
            set_state(&mut tx, &run, "committing", None).await?;
        }
        let rows = sqlx::query(
            "SELECT seq, origin, text, hash, project, match_note, flag, mark FROM lore_import_items \
             WHERE run = ? AND result IS NULL ORDER BY seq LIMIT ?",
        )
        .bind(&run)
        .bind(CHUNK)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            set_state(&mut tx, &run, "committed", None).await?;
            record(&mut tx, "committed", &run, "committed").await?;
            let out = run_view(&mut tx, &run).await?;
            tx.commit().await?;
            return Ok(Json(out));
        }
        for r in &rows {
            let it = Item {
                seq: r.try_get("seq")?,
                origin: r.try_get("origin")?,
                text: r.try_get("text")?,
                hash: r.try_get("hash")?,
                project: r.try_get("project")?,
                match_note: r.try_get("match_note")?,
                flag: r.try_get("flag")?,
                mark: r.try_get("mark")?,
            };
            apply(&mut tx, &run, &who, it).await?;
        }
        set_state(&mut tx, &run, "committing", None).await?;
        tx.commit().await?;
    }
}

/// `undone`: 1 = put back, 2 = left because the note changed after the import.
async fn undo_item(conn: &mut SqliteConnection, r: &sqlx::sqlite::SqliteRow) -> Result<i64, ApiError> {
    let result: String = r.try_get("result")?;
    let note: Option<String> = r.try_get("note")?;
    let version: Option<String> = r.try_get("version")?;
    let Some(note) = note else { return Ok(2) };
    match result.as_str() {
        "created" => {
            let rev: Option<i64> = sqlx::query_scalar(
                "UPDATE lore_notes SET trashed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), rev = rev + 1 \
                 WHERE id = ? AND trashed_at IS NULL RETURNING rev",
            )
            .bind(&note)
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(rev) = rev {
                notes::record(conn, "trashed", "trashed", &note, rev, "import", None).await?;
                save::relink(conn, &note, None).await?;
            }
            Ok(1)
        }
        "updated" => {
            let (Ok(h), Some(version)) = (save::load(conn, &note).await, version) else { return Ok(2) };
            let rev_after: Option<i64> = r.try_get("rev_after")?;
            let old: Option<String> = sqlx::query_scalar("SELECT text FROM lore_versions WHERE id = ?")
                .bind(&version)
                .fetch_optional(&mut *conn)
                .await?;
            let Some(old) = old.filter(|_| !h.trashed && rev_after == Some(h.rev)) else { return Ok(2) };
            save::commit_text(conn, &h, &old, "system", "system", Snap::Never).await?;
            sqlx::query("UPDATE lore_notes SET import_hash = ?, import_run = ? WHERE id = ?")
                .bind(r.try_get::<Option<String>, _>("prev_hash")?)
                .bind(r.try_get::<Option<String>, _>("prev_run")?)
                .bind(&note)
                .execute(&mut *conn)
                .await?;
            Ok(1)
        }
        "conflict" => {
            if let Some(v) = version {
                sqlx::query("DELETE FROM lore_versions WHERE id = ?").bind(v).execute(&mut *conn).await?;
            }
            Ok(1)
        }
        _ => Ok(1),
    }
}

#[utoipa::path(post, path = "/imports/{run}/undo", operation_id = "loreUndoImport", tag = "lore",
    params(("run" = String, Path, description = "Import run id")),
    responses((status = 200, description = "What the run created is trashed, what it updated gets its old text back (and old import hash), the conflict versions it kept are removed. A note edited after the import is left alone and counted in `kept`. Not possible once the run's staged text was cleaned up (30 days). Calling it again on an `undoing` run resumes it", body = RunView)))]
pub(crate) async fn undo(State(app): State<App>, Path(run): Path<String>) -> ApiResult<RunView> {
    loop {
        let mut tx = begin_write(&app.pool).await?;
        if state_of(&mut tx, &run, &["committed", "undoing"]).await? == "committed" {
            let held: i64 = sqlx::query_scalar("SELECT count(*) FROM lore_import_items WHERE run = ? AND result IS NOT NULL")
                .bind(&run)
                .fetch_one(&mut *tx)
                .await?;
            if held == 0 {
                return Err(ApiError::conflict("the import's details were cleaned up"));
            }
            set_state(&mut tx, &run, "undoing", None).await?;
        }
        let rows = sqlx::query(
            "SELECT seq, result, note, version, rev_after, prev_hash, prev_run FROM lore_import_items \
             WHERE run = ? AND undone = 0 AND result IN ('created', 'updated', 'conflict') ORDER BY seq LIMIT ?",
        )
        .bind(&run)
        .bind(CHUNK)
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            set_state(&mut tx, &run, "undone", None).await?;
            record(&mut tx, "undone", &run, "undone").await?;
            let out = run_view(&mut tx, &run).await?;
            tx.commit().await?;
            return Ok(Json(out));
        }
        for r in &rows {
            let how = undo_item(&mut tx, r).await?;
            sqlx::query("UPDATE lore_import_items SET undone = ? WHERE run = ? AND seq = ?")
                .bind(how)
                .bind(&run)
                .bind(r.try_get::<i64, _>("seq")?)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
}

/// The 30-day cleanup: a run still staging or in review after 30 days is abandoned, and the staged items of every
/// run that ended more than 30 days ago are deleted (the run row stays as the history). Returns rows touched.
pub async fn sweep(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let mut tx = begin_write(pool).await?;
    let cutoff = format!("-{KEEP_DAYS} days");
    let a = sqlx::query(
        "UPDATE lore_imports SET state = 'abandoned', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE state IN ('staging', 'review') AND updated_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
    )
    .bind(&cutoff)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let d = sqlx::query(
        "DELETE FROM lore_import_items WHERE run IN (SELECT id FROM lore_imports \
         WHERE state IN ('committed', 'undone', 'abandoned') AND updated_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?))",
    )
    .bind(&cutoff)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(a + d)
}
