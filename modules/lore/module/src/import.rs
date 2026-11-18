//! Import runs (R4-01, T12): bring Markdown files into Lore as notes, reviewed first, undoable after.
//! Security model: see `import_read.rs` (all input is hostile: path rules, zip and git reading, caps). Here:
//! - A run stages *items*, never notes; nothing becomes a note before `commit`, and nothing is written outside
//!   the Lore tables. Items hold the text only (no path outside what `classify_path` accepted).
//! - Identity is the origin (`mirror:<repo>:<path>` / `upload:<project>:<path>`): importing it again updates the
//!   note it made, and only while the note is unedited (its text still hashes to `import_hash`). An edited note is
//!   never overwritten: it is flagged `conflict`, kept as it is, and the incoming text is kept as a `conflict`
//!   version. An update first keeps the old text as an `auto` version (T4); undo puts it back exactly.
//! - Runs are persisted at every step (`staging` -> `review` -> `committing` -> `committed`, `undoing` ->
//!   `undone`, or `abandoned`), committed in transactions of 200 items, so a stopped commit resumes by calling
//!   commit again. Staged text is dropped 30 days after the run ends (`import_commit::sweep`).
//! - Refusals are fixed sentences; audit and events carry ids and counts only.
//!
//! ponytail: an upload batch sent twice counts its refused/ignored entries twice; the numbers are informational.
//! ponytail: a matched note keeps its project; a project chosen in review applies to notes this run creates.

use std::path::PathBuf;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::{begin_write, projects};
use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::Lore;
use crate::import_read::{
    MirrorRef, PathClass, Scan, classify_path, clean_text, read_mirror, read_zip,
};
pub(crate) use crate::import_run::*;
use crate::import_stage::{classify, stage};
use crate::notes::{In, project_id, rand_id, some};

/// A zip upload's body ceiling at the gate.
pub(crate) const ZIP_BODY_MAX: usize = 16 << 20;
const BATCH_MAX: usize = 200;
const OPEN_RUNS_MAX: i64 = 20;
const SEQS_MAX: usize = 500;

fn too_large(what: &'static str) -> ApiError {
    ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", what)
}

#[derive(Deserialize, ToSchema)]
pub struct NewRun {
    /// `mirror` (the project's repo copy in the Core) or `upload` (items or a zip sent to this run).
    pub source: String,
    /// The project the notes go to; absent = personal (an upload only).
    pub project: Option<String>,
    /// A mirror run: the project's repo id; absent = its primary repo.
    pub repo: Option<String>,
}

#[utoipa::path(post, path = "/imports", operation_id = "loreCreateImport", tag = "lore", request_body = NewRun,
    responses((status = 200, description = "A new run. `upload`: state `staging`, send items or a zip, then `finish`. `mirror`: the repo copy's `Docs/` (or `docs/`) is read now, `.md` regular files only, and the run comes back in `review` (or `abandoned` with `error` when it could not be read). Needs an active project with a copy", body = RunView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(lore): Extension<Lore>,
    In(req): In<NewRun>,
) -> ApiResult<RunView> {
    let mirror = match req.source.as_str() {
        "mirror" => true,
        "upload" => false,
        _ => return Err(ApiError::bad_request("the import source is not valid")),
    };
    let mut tx = begin_write(&app.pool).await?;
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM lore_imports WHERE state IN ('staging', 'review', 'committing', 'undoing')",
    )
    .fetch_one(&mut *tx)
    .await?;
    if open >= OPEN_RUNS_MAX {
        return Err(ApiError::conflict("too many imports are open"));
    }
    let project = match req.project.as_deref() {
        Some(p) => Some(project_id(&mut tx, p).await?),
        None => None,
    };
    let mut target = None;
    let mut repo_id = None;
    if mirror {
        let pid: i64 = project
            .as_deref()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| ApiError::bad_request("a repo import needs a project"))?;
        let p = projects::get(&mut tx, pid)
            .await
            .map_err(|_| ApiError::bad_request("no such project"))?;
        if p.state != "active" {
            return Err(ApiError::conflict("the project is archived"));
        }
        let repos = projects::repos(&mut tx, pid).await?;
        let repo = match req.repo.as_deref() {
            Some(r) => repos.iter().find(|x| x.id.to_string() == r),
            None => repos.first(),
        }
        .ok_or_else(|| ApiError::bad_request("no such repo in the project"))?;
        let root = lore.mirror_root.clone().unwrap_or_else(|| {
            let db = app.pool.connect_options().get_filename().to_owned();
            db.parent()
                .map(|d| d.to_path_buf())
                .unwrap_or_default()
                .join("mirrors")
        });
        repo_id = Some(repo.id.to_string());
        target = Some(MirrorRef {
            dir: PathBuf::from(root).join(format!("{}.git", repo.id)),
            project: pid,
            remote: repo.remote_url.clone(),
            branch: repo.default_branch.clone(),
        });
    }
    let id = rand_id("li_");
    sqlx::query(
        "INSERT INTO lore_imports (id, source, project, repo, state, created_by) VALUES (?, ?, ?, ?, 'staging', ?)",
    )
    .bind(&id)
    .bind(&req.source)
    .bind(&project)
    .bind(&repo_id)
    .bind(format!("person:{}", me.device.id))
    .execute(&mut *tx)
    .await?;
    record(&mut tx, "created", &id, "staging").await?;
    tx.commit().await?;
    // The read runs outside the write gate: git is slow and the repo copy is not the database.
    if let Some(t) = target {
        let read = read_mirror(&t).await;
        let mut tx = begin_write(&app.pool).await?;
        match read {
            Ok(scan) => {
                let origin = format!("mirror:{}:", repo_id.as_deref().unwrap_or_default());
                match stage(&mut tx, &id, &origin, 1, project.as_deref(), scan).await {
                    Ok(()) => {
                        classify(&mut tx, &id, None).await?;
                        set_state(&mut tx, &id, "review", None).await?;
                    }
                    Err(_) => {
                        set_state(
                            &mut tx,
                            &id,
                            "abandoned",
                            Some("the repo has too many documents or too much text"),
                        )
                        .await?
                    }
                }
            }
            Err(why) => set_state(&mut tx, &id, "abandoned", Some(why)).await?,
        }
        let out = run_view(&mut tx, &id).await?;
        tx.commit().await?;
        return Ok(Json(out));
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(run_view(&mut conn, &id).await?))
}

#[utoipa::path(get, path = "/imports", operation_id = "loreListImports", tag = "lore",
    responses((status = 200, description = "The runs, newest first (at most 50), with their state and counts: what is staged, committing, done or undone", body = Vec<RunView>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<RunView>> {
    let mut conn = app.pool.acquire().await?;
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM lore_imports ORDER BY created_at DESC, id LIMIT 50")
            .fetch_all(&mut *conn)
            .await?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(run_view(&mut conn, &id).await?);
    }
    Ok(Json(out))
}

#[utoipa::path(get, path = "/imports/{run}", operation_id = "loreGetImport", tag = "lore",
    params(("run" = String, Path, description = "Import run id")),
    responses((status = 200, description = "The run and its counts", body = RunView)))]
pub(crate) async fn get(State(app): State<App>, Path(run): Path<String>) -> ApiResult<RunView> {
    if !run_ok(&run) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    Ok(Json(run_view(&mut conn, &run).await?))
}

#[derive(Deserialize, ToSchema)]
pub struct UploadItem {
    /// The path relative to the folder or zip root, `/`-separated.
    pub path: String,
    pub text: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UploadBatch {
    /// At most 200 per call, and the whole call under the 1 MiB signed-body cap.
    pub items: Vec<UploadItem>,
}

/// Where an upload run's origins live: its project, or `-` for personal.
async fn upload_scope(
    conn: &mut SqliteConnection,
    run: &str,
) -> Result<(String, Option<String>), ApiError> {
    let r = sqlx::query("SELECT project FROM lore_imports WHERE id = ? AND source = 'upload'")
        .bind(run)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| ApiError::conflict("the import does not take uploads"))?;
    let p: Option<String> = r.try_get("project")?;
    Ok((format!("upload:{}:", p.as_deref().unwrap_or("-")), p))
}

#[utoipa::path(post, path = "/imports/{run}/items", operation_id = "loreAddImportItems", tag = "lore",
    params(("run" = String, Path, description = "Import run id")), request_body = UploadBatch,
    responses((status = 200, description = "The run after the batch is staged. Unsafe paths and unreadable text are refused and counted, unwanted files ignored; a path sent twice replaces the earlier one. Only while `staging`", body = RunView)))]
pub(crate) async fn add_items(
    State(app): State<App>,
    Path(run): Path<String>,
    In(req): In<UploadBatch>,
) -> ApiResult<RunView> {
    if req.items.len() > BATCH_MAX {
        return Err(too_large("too many items in one call"));
    }
    let mut scan = Scan::default();
    for it in req.items {
        match classify_path(&it.path) {
            PathClass::Refused => scan.refused += 1,
            PathClass::Ignored => scan.ignored += 1,
            PathClass::Ok(p) if it.text.len() > crate::import_read::FILE_MAX => {
                scan.too_large.push(p)
            }
            PathClass::Ok(p) => match clean_text(it.text.as_bytes()) {
                Some(t) => scan.files.push((p, t)),
                None => scan.refused += 1,
            },
        }
    }
    let mut tx = begin_write(&app.pool).await?;
    state_of(&mut tx, &run, &["staging"]).await?;
    let (origin, project) = upload_scope(&mut tx, &run).await?;
    stage(&mut tx, &run, &origin, 0, project.as_deref(), scan).await?;
    let out = run_view(&mut tx, &run).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/imports/{run}/zip", operation_id = "loreAddImportZip", tag = "lore",
    params(("run" = String, Path, description = "Import run id")),
    request_body(content = Vec<u8>, content_type = "application/zip", description = "A zip of `.md` files, at most 16 MiB"),
    responses((status = 200, description = "The run after the zip's Markdown files are staged. Symlinks, `..` or absolute names, NUL and binary files are refused and counted; over 5 000 entries, 2 000 files or 64 MiB of text is 413. Only while `staging`", body = RunView)))]
pub(crate) async fn add_zip(
    State(app): State<App>,
    Path(run): Path<String>,
    body: Bytes,
) -> ApiResult<RunView> {
    if body.is_empty() {
        return Err(ApiError::bad_request("the zip is not valid"));
    }
    {
        let mut conn = app.pool.acquire().await?;
        state_of(&mut conn, &run, &["staging"]).await?;
    }
    let scan = tokio::task::spawn_blocking(move || read_zip(&body))
        .await
        .map_err(|_| ApiError::bad_request("the zip is not valid"))?
        .map_err(|why| match why {
            "the zip is not valid" => ApiError::bad_request(why),
            _ => too_large(why),
        })?;
    let mut tx = begin_write(&app.pool).await?;
    state_of(&mut tx, &run, &["staging"]).await?;
    let (origin, project) = upload_scope(&mut tx, &run).await?;
    stage(&mut tx, &run, &origin, 0, project.as_deref(), scan).await?;
    let out = run_view(&mut tx, &run).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/imports/{run}/finish", operation_id = "loreFinishImport", tag = "lore",
    params(("run" = String, Path, description = "Import run id")),
    responses((status = 200, description = "Staging is over: the items are flagged (duplicate, changed, conflict) and the run is in `review`. Calling it again on a run in review is harmless", body = RunView)))]
pub(crate) async fn finish(State(app): State<App>, Path(run): Path<String>) -> ApiResult<RunView> {
    let mut tx = begin_write(&app.pool).await?;
    if state_of(&mut tx, &run, &["staging", "review"]).await? == "staging" {
        classify(&mut tx, &run, None).await?;
        set_state(&mut tx, &run, "review", None).await?;
    }
    let out = run_view(&mut tx, &run).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[derive(Serialize, ToSchema)]
pub struct ItemSummary {
    pub seq: i64,
    pub path: String,
    pub title: String,
    pub tags: Vec<String>,
    /// The project a new note goes to; `null` = personal.
    pub project: Option<String>,
    /// `duplicate`, `changed`, `conflict`, `too_large` or `skipped`.
    pub flag: Option<String>,
    /// `include` or `skip`.
    pub mark: String,
    /// The note this item would update (or, for `conflict`, keep).
    pub match_note: Option<String>,
    /// What commit did with it.
    pub result: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ItemsQuery {
    flag: Option<String>,
    after: Option<i64>,
    limit: Option<i64>,
}

#[utoipa::path(get, path = "/imports/{run}/items", operation_id = "loreListImportItems", tag = "lore",
    params(("run" = String, Path, description = "Import run id"),
           ("flag" = Option<String>, Query, description = "Only items with this flag"),
           ("after" = Option<i64>, Query, description = "Only items after this seq"),
           ("limit" = Option<i64>, Query, description = "At most this many (default 200, at most 500)")),
    responses((status = 200, description = "Staged items by seq, without their text", body = Vec<ItemSummary>)))]
pub(crate) async fn items(
    State(app): State<App>,
    Path(run): Path<String>,
    q: Result<Query<ItemsQuery>, QueryRejection>,
) -> ApiResult<Vec<ItemSummary>> {
    let Query(q) = q.map_err(|_| ApiError::bad_request("the query is not valid"))?;
    if !run_ok(&run) {
        return Err(none());
    }
    let mut conn = app.pool.acquire().await?;
    let found: i64 = sqlx::query_scalar("SELECT count(*) FROM lore_imports WHERE id = ?")
        .bind(&run)
        .fetch_one(&mut *conn)
        .await?;
    if found == 0 {
        return Err(none());
    }
    let rows = sqlx::query(
        "SELECT seq, path, title, tags, project, flag, mark, match_note, result FROM lore_import_items \
         WHERE run = ?1 AND seq > ?2 AND (?3 IS NULL OR flag = ?3) ORDER BY seq LIMIT ?4",
    )
    .bind(&run)
    .bind(q.after.unwrap_or(0))
    .bind(q.flag)
    .bind(q.limit.unwrap_or(200).clamp(1, SEQS_MAX as i64))
    .fetch_all(&mut *conn)
    .await?;
    let out = rows
        .iter()
        .map(|r| {
            let tags: String = r.try_get("tags")?;
            Ok(ItemSummary {
                seq: r.try_get("seq")?,
                path: r.try_get("path")?,
                title: r.try_get("title")?,
                tags: serde_json::from_str(&tags).unwrap_or_default(),
                project: r.try_get("project")?,
                flag: r.try_get("flag")?,
                mark: r.try_get("mark")?,
                match_note: r.try_get("match_note")?,
                result: r.try_get("result")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct ItemsPatch {
    /// Up to 500 item numbers; empty = every item of the run.
    pub seqs: Vec<i64>,
    /// `include` or `skip`. Items that are too large or skipped stay skipped.
    pub mark: Option<String>,
    /// The project new notes go to; `null` = personal. Items are re-flagged against it.
    #[serde(default, deserialize_with = "some")]
    #[schema(value_type = Option<String>)]
    pub project: Option<Option<String>>,
}

#[utoipa::path(patch, path = "/imports/{run}/items", operation_id = "lorePatchImportItems", tag = "lore",
    params(("run" = String, Path, description = "Import run id")), request_body = ItemsPatch,
    responses((status = 200, description = "The run after the review edit. Only while `review`", body = RunView)))]
pub(crate) async fn patch_items(
    State(app): State<App>,
    Path(run): Path<String>,
    In(req): In<ItemsPatch>,
) -> ApiResult<RunView> {
    if req.seqs.len() > SEQS_MAX
        || req
            .mark
            .as_deref()
            .is_some_and(|m| !["include", "skip"].contains(&m))
    {
        return Err(ApiError::bad_request("the request is not valid"));
    }
    let mut tx = begin_write(&app.pool).await?;
    state_of(&mut tx, &run, &["review"]).await?;
    let seqs: Vec<i64> = if req.seqs.is_empty() {
        sqlx::query_scalar("SELECT seq FROM lore_import_items WHERE run = ? ORDER BY seq")
            .bind(&run)
            .fetch_all(&mut *tx)
            .await?
    } else {
        req.seqs
    };
    if let Some(p) = &req.project {
        let new = match p.as_deref() {
            Some(p) => Some(project_id(&mut tx, p).await?),
            None => None,
        };
        for s in &seqs {
            sqlx::query("UPDATE lore_import_items SET project = ? WHERE run = ? AND seq = ?")
                .bind(&new)
                .bind(&run)
                .bind(s)
                .execute(&mut *tx)
                .await?;
        }
        classify(&mut tx, &run, Some(&seqs)).await?;
    }
    if let Some(m) = &req.mark {
        for s in &seqs {
            sqlx::query(
                "UPDATE lore_import_items SET mark = ? WHERE run = ? AND seq = ? \
                 AND (flag IS NULL OR flag NOT IN ('too_large', 'skipped'))",
            )
            .bind(m)
            .bind(&run)
            .bind(s)
            .execute(&mut *tx)
            .await?;
        }
    }
    let out = run_view(&mut tx, &run).await?;
    tx.commit().await?;
    Ok(Json(out))
}

#[utoipa::path(post, path = "/imports/{run}/abandon", operation_id = "loreAbandonImport", tag = "lore",
    params(("run" = String, Path, description = "Import run id")),
    responses((status = 200, description = "The run is dropped before anything was committed; its staged text goes with the 30-day cleanup", body = RunView)))]
pub(crate) async fn abandon(State(app): State<App>, Path(run): Path<String>) -> ApiResult<RunView> {
    let mut tx = begin_write(&app.pool).await?;
    state_of(&mut tx, &run, &["staging", "review"]).await?;
    set_state(&mut tx, &run, "abandoned", None).await?;
    record(&mut tx, "abandoned", &run, "abandoned").await?;
    let out = run_view(&mut tx, &run).await?;
    tx.commit().await?;
    Ok(Json(out))
}
