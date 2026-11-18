//! A room's search index (E7-1): FTS5 in `index.db`, built from `canon.db` by the `brain_index` job
//! and, when behind, by the search itself. Deleting the file loses nothing: the next build gives
//! the same results, because rows go in by item id and results come out by rank then item id.

use std::path::Path;
use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use axum::extract::{Path as UrlPath, Query, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use utoipa::{IntoParams, ToSchema};

use crate::files::{self, CANON, INDEX};
use crate::{Brain, code};

/// How often the `brain_index` job looks for a room whose index is behind.
pub const INDEX_EVERY_SECS: u64 = 600;
const PAGE: i64 = 500;
const DEFAULT_LIMIT: u32 = 20;
const MAX_LIMIT: u32 = 100;
const MAX_WORDS: usize = 20;

/// Brings `index.db` in line with `canon`; true when anything was rebuilt. Sources are only ever
/// added, so their count and the newest op-log row say whether `fts` is behind; `rec_fts` (the
/// facts in force, the `memory` view) is behind when its own stamp moved: a record was added,
/// archived, superseded or reinforced.
/// ponytail: a full rebuild, not an incremental add; per-room volumes are small, add `seq > ?` if not.
/// ponytail: the record stamp is count + body sizes + newest touch + op-log head; an edit that keeps
/// the length and logs no op is missed. AI reads re-check every hit against `memory`, so a stale row
/// can mis-rank but never return a record that left memory.
pub(crate) async fn ensure(
    canon: &SqlitePool,
    index_file: &Path,
    key: &[u8; 32],
) -> Result<bool, ApiError> {
    let stamp: String = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM sources) || ':' || coalesce((SELECT max(seq) FROM op_log), 0)",
    )
    .fetch_one(canon)
    .await?;
    let rec_stamp: String = sqlx::query_scalar(
        "SELECT (SELECT count(*) || ':' || coalesce(sum(length(body) + coalesce(length(tags), 0) + support), 0) \
                || ':' || coalesce(max(coalesce(last_seen_at, created_at)), '') || ':' || coalesce(max(id), '') FROM memory) \
                || ':' || coalesce((SELECT max(seq) FROM op_log), 0)",
    )
    .fetch_one(canon)
    .await?;
    let index = files::open_migrated(index_file, key, true, INDEX)
        .await
        .map_err(|e| code(500, "index_unavailable", e.to_string()))?;
    let behind = |k: &'static str, want: &str| {
        let index = index.clone();
        let want = want.to_owned();
        async move {
            let had: Option<String> = sqlx::query_scalar("SELECT v FROM meta WHERE k = ?")
                .bind(k)
                .fetch_optional(&index)
                .await?;
            Ok::<_, sqlx::Error>(had.as_deref() != Some(want.as_str()))
        }
    };
    let (src_behind, rec_behind) = (
        behind("stamp", &stamp).await?,
        behind("rec_stamp", &rec_stamp).await?,
    );
    if !src_behind && !rec_behind {
        index.close().await;
        return Ok(false);
    }
    let mut tx = index.begin().await?;
    if src_behind {
        sqlx::query("DELETE FROM fts").execute(&mut *tx).await?;
        let mut after = String::new();
        loop {
            let rows = sqlx::query(
                "SELECT item_id, source_kind, started_at, title, text FROM sources WHERE compacted_at IS NULL AND item_id > ? ORDER BY item_id LIMIT ?",
            )
            .bind(&after)
            .bind(PAGE)
            .fetch_all(canon)
            .await?;
            let Some(last) = rows.last() else { break };
            after = last.try_get("item_id")?;
            for r in &rows {
                sqlx::query("INSERT INTO fts (item_id, source_kind, started_at, title, text) VALUES (?, ?, ?, ?, ?)")
                    .bind(r.try_get::<String, _>("item_id")?)
                    .bind(r.try_get::<String, _>("source_kind")?)
                    .bind(r.try_get::<String, _>("started_at")?)
                    .bind(r.try_get::<String, _>("title")?)
                    .bind(r.try_get::<String, _>("text")?)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    if rec_behind {
        sqlx::query("DELETE FROM rec_fts").execute(&mut *tx).await?;
        let mut after = String::new();
        loop {
            let rows =
                sqlx::query("SELECT id, type, body, tags FROM memory WHERE id > ? ORDER BY id LIMIT ?")
                    .bind(&after)
                    .bind(PAGE)
                    .fetch_all(canon)
                    .await?;
            let Some(last) = rows.last() else { break };
            after = last.try_get("id")?;
            for r in &rows {
                sqlx::query("INSERT INTO rec_fts (record, type, body, tags) VALUES (?, ?, ?, ?)")
                    .bind(r.try_get::<String, _>("id")?)
                    .bind(r.try_get::<String, _>("type")?)
                    .bind(r.try_get::<String, _>("body")?)
                    .bind(r.try_get::<Option<String>, _>("tags")?.unwrap_or_default())
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    for (k, v, on) in [("stamp", &stamp, src_behind), ("rec_stamp", &rec_stamp, rec_behind)] {
        if on {
            sqlx::query(
                "INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            )
            .bind(k)
            .bind(v)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    index.close().await;
    Ok(true)
}

/// Every word quoted and ANDed: a query is words, never FTS5 syntax, so no input can be an error.
fn match_expr(q: &str) -> Option<String> {
    let words: Vec<String> = words(q).iter().map(|w| format!("\"{w}\"")).collect();
    (!words.is_empty()).then(|| words.join(" "))
}

/// The words of `q`: alphanumeric runs, at most `MAX_WORDS`.
pub(crate) fn words(q: &str) -> Vec<String> {
    q.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(MAX_WORDS)
        .map(str::to_owned)
        .collect()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SearchQuery {
    /// Words to find; all must appear.
    pub q: String,
    /// At most this many hits (default 20, most 100).
    pub limit: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct Hit {
    pub item_id: String,
    pub source_kind: String,
    pub title: String,
    /// The matching text, the words between « and ».
    pub snippet: String,
    pub started_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct Hits {
    pub hits: Vec<Hit>,
}

/// The best `limit` hits of an open room for `expr`, each with its bm25 rank (lower is better).
pub(crate) async fn fts(
    app: &App,
    key: &[u8; 32],
    access: &crate::rooms::RoomAccess,
    limit: u32,
    expr: &str,
) -> Result<Vec<(f64, Hit)>, ApiError> {
    let file = files::index_path(&files::root(app), access.room());
    ensure(access.pool(), &file, key).await?;
    let index = files::open_migrated(&file, key, false, INDEX)
        .await
        .map_err(|e| code(500, "index_unavailable", e.to_string()))?;
    let rows = sqlx::query(
        "SELECT item_id, source_kind, title, started_at, snippet(fts, 4, '«', '»', '…', 16) AS snip, bm25(fts) AS rank \
         FROM fts WHERE fts MATCH ? ORDER BY bm25(fts), item_id LIMIT ?",
    )
    .bind(expr)
    .bind(limit)
    .fetch_all(&index)
    .await?;
    let hits = rows
        .iter()
        .map(|r| {
            Ok((
                r.try_get("rank")?,
                Hit {
                    item_id: r.try_get("item_id")?,
                    source_kind: r.try_get("source_kind")?,
                    title: r.try_get("title")?,
                    snippet: r.try_get("snip")?,
                    started_at: r.try_get("started_at")?,
                },
            ))
        })
        .collect::<Result<_, sqlx::Error>>()?;
    index.close().await;
    Ok(hits)
}

/// The best `limit` facts in force of an open room for `expr`: record ids with their bm25 rank (lower
/// is better). Ids only: the caller reads the text from `memory`, so nothing stale can leave.
pub(crate) async fn rec_fts(
    app: &App,
    key: &[u8; 32],
    access: &crate::rooms::RoomAccess,
    limit: u32,
    expr: &str,
) -> Result<Vec<(f64, String)>, ApiError> {
    let file = files::index_path(&files::root(app), access.room());
    ensure(access.pool(), &file, key).await?;
    let index = files::open_migrated(&file, key, false, INDEX)
        .await
        .map_err(|e| code(500, "index_unavailable", e.to_string()))?;
    let rows = sqlx::query(
        "SELECT record, bm25(rec_fts) AS rank FROM rec_fts WHERE rec_fts MATCH ? \
         ORDER BY bm25(rec_fts), record LIMIT ?",
    )
    .bind(expr)
    .bind(limit)
    .fetch_all(&index)
    .await?;
    index.close().await;
    Ok(rows
        .iter()
        .map(|r| Ok((r.try_get("rank")?, r.try_get("record")?)))
        .collect::<Result<_, sqlx::Error>>()?)
}

#[utoipa::path(get, path = "/rooms/{room}/search", operation_id = "brainRoomSearch", tag = "brain",
    params(("room" = String, Path, description = "Room id"), SearchQuery),
    responses((status = 200, description = "Full-text hits in an open room, best first", body = Hits)))]
pub(crate) async fn search(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    UrlPath(room): UrlPath<String>,
    Query(q): Query<SearchQuery>,
) -> ApiResult<Hits> {
    let expr =
        match_expr(&q.q).ok_or_else(|| ApiError::bad_request("q needs at least one word"))?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let key = b.key(&app).await?;
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    let hits = fts(&app, &key, &access, limit, &expr)
        .await?
        .into_iter()
        .map(|(_, h)| h)
        .collect();
    access.pool().close().await;
    Ok(Json(Hits { hits }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LatestQuery {
    /// At most this many items (default 20, most 100).
    pub limit: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct LatestItem {
    pub item_id: String,
    /// `source`: an imported item, not a distilled record.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    pub source_kind: String,
    pub title: String,
    pub started_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct Latest {
    pub items: Vec<LatestItem>,
    /// Records in the room, any status. 0 while nothing was distilled: the items are only imported.
    pub records: i64,
}

#[utoipa::path(get, path = "/rooms/{room}/latest", operation_id = "brainRoomLatest", tag = "brain",
    params(("room" = String, Path, description = "Room id"), LatestQuery),
    responses((status = 200, description = "An open room's newest sources, newest first, and its record count", body = Latest)))]
pub(crate) async fn latest(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    UrlPath(room): UrlPath<String>,
    Query(q): Query<LatestQuery>,
) -> ApiResult<Latest> {
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let access = crate::inbox::open_room(&app, &b, &room).await?;
    // Newest first. Sub-agent and scratch-prompt sources are hidden (stored before they were
    // skipped at intake), and sources with one first prompt show once, the newest.
    let rows = sqlx::query(
        "SELECT item_id, source_kind, title, started_at, path FROM sources ORDER BY started_at DESC, item_id DESC",
    )
    .fetch_all(access.pool())
    .await?;
    let mut seen = std::collections::HashSet::new();
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|r| {
            let (path, title, kind): (String, String, String) =
                (r.get("path"), r.get("title"), r.get("source_kind"));
            let session = matches!(
                kind.as_str(),
                "claude_code"
                    | "codex"
                    | "opencode"
                    | "antigravity"
                    | "cursor"
                    | "kimi"
                    | "core_transcript"
            );
            !brain_model::item::is_agent_noise(&path, &title)
                && (!session || seen.insert(brain_model::item::prompt_key(&title)))
        })
        .take(limit as usize)
        .collect();
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
        .fetch_one(access.pool())
        .await?;
    access.pool().close().await;
    let items = rows
        .iter()
        .map(|r| {
            Ok(LatestItem {
                item_id: r.try_get("item_id")?,
                kind: "source".to_owned(),
                source_kind: r.try_get("source_kind")?,
                title: r.try_get("title")?,
                started_at: r.try_get("started_at")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok(Json(Latest { items, records }))
}

struct IndexJob(Brain);

impl JobHandler for IndexJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            // No key yet (nothing imported) or a locked brain: nothing to index.
            let Ok(key) = self.0.key(app).await else {
                run.idle();
                return Ok(());
            };
            let rooms: Vec<String> =
                sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
                    .fetch_all(&app.pool)
                    .await
                    .map_err(|e| e.to_string())?;
            let mut built = 0;
            for room in rooms {
                // A room whose file is missing or newer is left alone; the next run tries again.
                let Ok(canon) = files::open_migrated(
                    &files::room_path(&files::root(app), &room),
                    &key,
                    false,
                    CANON,
                )
                .await
                else {
                    continue;
                };
                let rebuilt =
                    ensure(&canon, &files::index_path(&files::root(app), &room), &key).await;
                canon.close().await;
                built += usize::from(rebuilt.map_err(|e| e.message)?);
            }
            if built == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_index",
        Schedule::Every(INDEX_EVERY_SECS),
        Arc::new(IndexJob(b.clone())),
    )
}
