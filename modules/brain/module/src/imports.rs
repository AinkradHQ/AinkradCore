//! Import runs and intake (E1-2, E1-5): start a run, take batches of items (validate, rule check,
//! dedupe, clean, stage), close the collectors and let discovery run.

use std::collections::BTreeMap;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::item::{Item, MAX_BATCH_BYTES};
use brain_model::rules::{self, Rule, RuleKind};
use brain_model::signals::extract;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::files::{self, STAGING};
use crate::{Brain, clean, code, rand_id, record};

/// Most items in one batch; the byte cap is the real bound.
const MAX_ITEMS: usize = 500;

#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
pub struct Counts {
    pub found: u64,
    pub stored: u64,
    pub duplicate: u64,
    pub refused: u64,
    pub rejected: u64,
    pub cleaned: u64,
    pub pointers: u64,
    /// Skipped items by reason code (`rule:<id>`), never any text.
    pub skipped: BTreeMap<String, u64>,
}

#[derive(Deserialize, ToSchema)]
pub struct StartRun {
    /// `full` or `incremental`.
    pub kind: String,
    /// The collectors that will report in; discovery starts when all have said `collected`.
    pub sources: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RunId {
    pub run: String,
}

#[derive(Deserialize, ToSchema)]
pub struct Batch {
    /// Items as `brain-model`'s JSON Schema describes them.
    #[schema(value_type = Vec<Object>)]
    pub items: Vec<Item>,
}

#[derive(Serialize, ToSchema)]
pub struct ItemReply {
    pub item_id: String,
    /// `stored`, `cleaned`, `duplicate`, `refused` or `rejected`.
    pub status: String,
    /// The rule id, the redaction count or the rejection code.
    pub detail: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Replies {
    pub results: Vec<ItemReply>,
}

#[derive(Deserialize, ToSchema)]
pub struct Collected {
    pub source: String,
}

#[derive(Serialize, ToSchema)]
pub struct RunView {
    pub run: String,
    pub kind: String,
    /// `collecting`, `discovering`, `review`, `committing`, `committed` or `abandoned`.
    pub state: String,
    pub stage: String,
    pub counts: Counts,
    pub sources: Vec<String>,
    pub started_at: String,
}

pub(crate) async fn staging(
    app: &App,
    b: &Brain,
    run: &str,
    create: bool,
) -> Result<SqlitePool, ApiError> {
    staging_for(app, b, run, create, None).await
}

async fn staging_for(
    app: &App,
    b: &Brain,
    run: &str,
    create: bool,
    owner: Option<&str>,
) -> Result<SqlitePool, ApiError> {
    if !files::safe_id(run) {
        return Err(ApiError::not_found("no such run"));
    }
    let key = b.key_for(app, owner).await?;
    files::open_migrated(
        &files::staging_path(&files::root(app), run),
        &key,
        create,
        STAGING,
    )
    .await
    .map_err(|e| code(500, "staging_unavailable", e.to_string()))
}

pub(crate) async fn run_state(app: &App, run: &str) -> Result<(String, Vec<String>), ApiError> {
    let row = sqlx::query("SELECT state, sources FROM brain_import_runs WHERE id = ?")
        .bind(run)
        .fetch_optional(&app.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("no such run"))?;
    let sources: String = row.try_get("sources")?;
    Ok((
        row.try_get("state")?,
        serde_json::from_str(&sources).unwrap_or_default(),
    ))
}

#[utoipa::path(post, path = "/imports", operation_id = "brainStartImport", tag = "brain",
    request_body = StartRun,
    responses((status = 200, description = "The run id (audited as `brain.import.started`)", body = RunId)))]
pub(crate) async fn start(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<ainkrad_core_server::api::v1::Caller>,
    Json(req): Json<StartRun>,
) -> ApiResult<RunId> {
    if !["full", "incremental"].contains(&req.kind.as_str())
        || req.sources.is_empty()
        || req.sources.len() > 30
        || req.sources.iter().any(|s| {
            s.is_empty() || s.len() > 40 || !s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
        })
    {
        return Err(ApiError::bad_request(
            "a kind of full or incremental and 1 to 30 source names",
        ));
    }
    let run = start_run(&app, &b, &req.kind, &req.sources, Some(&me.device.id)).await?;
    Ok(Json(RunId { run }))
}

/// A run row and its staging file; the file first, as a run row with no file would be a run
/// nobody can finish. `owner` makes the brain key when none exists yet.
pub(crate) async fn start_run(
    app: &App,
    b: &Brain,
    kind: &str,
    sources: &[String],
    owner: Option<&str>,
) -> Result<String, ApiError> {
    let run = rand_id("run-");
    staging_for(app, b, &run, true, owner).await?.close().await;
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("INSERT INTO brain_import_runs (id, kind, state, sources, counts) VALUES (?, ?, 'collecting', ?, ?)")
        .bind(&run)
        .bind(kind)
        .bind(json!(sources).to_string())
        .bind(serde_json::to_string(&Counts::default()).expect("counts"))
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        "brain.import.started",
        json!({"run": run, "kind": kind, "sources": sources}),
        Some((
            "brain.import",
            json!({"run": run, "stage": "collect", "counts": Counts::default()}),
        )),
    )
    .await?;
    tx.commit().await?;
    Ok(run)
}

async fn load_rules(app: &App) -> Result<Vec<Rule>, ApiError> {
    let rows = sqlx::query("SELECT id, kind, pattern, enabled FROM brain_rules WHERE action = 'refuse' AND enabled = 1")
        .fetch_all(&app.pool)
        .await?;
    let mut out = Vec::new();
    for r in rows {
        let kind: String = r.try_get("kind")?;
        if let Some(kind) = RuleKind::parse(&kind) {
            out.push(Rule {
                id: r.try_get("id")?,
                kind,
                pattern: r.try_get("pattern")?,
                enabled: true,
            });
        }
    }
    Ok(out)
}

#[utoipa::path(post, path = "/imports/{run}/items", operation_id = "brainAddItems", tag = "brain",
    params(("run" = String, Path, description = "Run id")), request_body = Batch,
    responses((status = 200, description = "One reply per item", body = Replies)))]
pub(crate) async fn items(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
    Json(batch): Json<Batch>,
) -> ApiResult<Replies> {
    let (state, _) = run_state(&app, &run).await?;
    if state != "collecting" {
        return Err(ApiError::conflict("the run is not collecting"));
    }
    let bytes: usize = batch
        .items
        .iter()
        .map(|i| i.text.len() + i.title.len())
        .sum();
    if batch.items.len() > MAX_ITEMS || bytes > MAX_BATCH_BYTES {
        return Err(code(
            413,
            "batch_too_large",
            "a batch is at most 500 items and 1 MiB of text",
        ));
    }
    Ok(Json(Replies {
        results: stage_items(&app, &b, &run, &batch.items).await?,
    }))
}

/// Validates, rule-checks, dedupes, cleans and stages `items` into the run's file, one reply each.
/// The caller has checked the run is collecting and the batch bounds.
pub(crate) async fn stage_items(
    app: &App,
    b: &Brain,
    run: &str,
    items: &[Item],
) -> Result<Vec<ItemReply>, ApiError> {
    let rules = load_rules(app).await?;
    let staging = staging(app, b, run, false).await?;
    let mut counts = load_counts(app, run).await?;
    let mut results = Vec::with_capacity(items.len());
    let mut stx = staging.begin().await?;
    let mut seen_tx = begin_write(&app.pool).await?;
    for item in items {
        counts.found += 1;
        let reply = |status: &str, detail: Option<String>| ItemReply {
            item_id: item.item_id.clone(),
            status: status.to_owned(),
            detail,
        };
        if let Err(why) = item.validate() {
            counts.rejected += 1;
            results.push(reply("rejected", Some(why.code().to_owned())));
            continue;
        }
        let signals = extract(item);
        if let Some(rule) = rules::first_match(&rules, item, &signals) {
            let reason = format!("rule:{}", rule.id);
            *counts.skipped.entry(reason.clone()).or_default() += 1;
            counts.refused += 1;
            sqlx::query("INSERT OR IGNORE INTO brain_seen (content_hash, room, run) VALUES (?, 'refused', ?)")
                .bind(&item.content_hash)
                .bind(run)
                .execute(&mut *seen_tx)
                .await?;
            sqlx::query("INSERT INTO skips (item_id, reason) VALUES (?, ?)")
                .bind(&item.item_id)
                .bind(&reason)
                .execute(&mut *stx)
                .await?;
            results.push(reply("refused", Some(rule.id.to_string())));
            continue;
        }
        let known: i64 =
            sqlx::query_scalar("SELECT count(*) FROM brain_seen WHERE content_hash = ?")
                .bind(&item.content_hash)
                .fetch_one(&mut *seen_tx)
                .await?;
        let staged: i64 = sqlx::query_scalar("SELECT count(*) FROM items WHERE content_hash = ?")
            .bind(&item.content_hash)
            .fetch_one(&mut *stx)
            .await?;
        if known > 0 || staged > 0 {
            counts.duplicate += 1;
            results.push(reply("duplicate", None));
            continue;
        }
        let c = clean::clean(item);
        sqlx::query(
            "INSERT INTO items (item_id, content_hash, source_kind, device, path, project_hint, author_kind, \
             author_name, title, text, links, started_at, ended_at, warnings, pointer) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&item.item_id)
        .bind(&item.content_hash)
        .bind(item.source_kind.as_str())
        .bind(&item.origin.device)
        .bind(&item.origin.path)
        .bind(&item.project_hint)
        .bind(serde_json::to_value(item.author.kind).expect("kind").as_str().unwrap_or("person"))
        .bind(&item.author.name)
        .bind(&c.title)
        .bind(&c.text)
        .bind(json!(item.links).to_string())
        .bind(&item.started_at)
        .bind(&item.ended_at)
        .bind(json!(c.warnings).to_string())
        .bind(i64::from(c.pointer))
        .execute(&mut *stx)
        .await
        .map_err(|e| match e {
            // The same item id twice in one run: a collector bug, said plainly.
            sqlx::Error::Database(ref d) if d.is_unique_violation() => ApiError::conflict("an item id was sent twice"),
            e => e.into(),
        })?;
        counts.stored += 1;
        if c.pointer {
            counts.pointers += 1;
        }
        if c.redactions > 0 {
            counts.cleaned += 1;
            results.push(reply("cleaned", Some(c.redactions.to_string())));
        } else {
            results.push(reply("stored", None));
        }
    }
    stx.commit().await?;
    save_counts(&mut seen_tx, run, &counts).await?;
    record_progress(&mut seen_tx, run, "collect", &counts).await?;
    seen_tx.commit().await?;
    staging.close().await;
    Ok(results)
}

pub(crate) async fn load_counts(app: &App, run: &str) -> Result<Counts, ApiError> {
    let s: String = sqlx::query_scalar("SELECT counts FROM brain_import_runs WHERE id = ?")
        .bind(run)
        .fetch_one(&app.pool)
        .await?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

pub(crate) async fn save_counts(
    conn: &mut sqlx::SqliteConnection,
    run: &str,
    counts: &Counts,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE brain_import_runs SET counts = ? WHERE id = ?")
        .bind(serde_json::to_string(counts).expect("counts"))
        .bind(run)
        .execute(conn)
        .await?;
    Ok(())
}

/// The `brain.import` event: ids, stage and counts (Q-15).
pub(crate) async fn record_progress(
    conn: &mut sqlx::SqliteConnection,
    run: &str,
    stage: &str,
    counts: &Counts,
) -> Result<(), sqlx::Error> {
    ainkrad_core_server::store::events::append(
        conn,
        "brain.import",
        &json!({"run": run, "stage": stage, "counts": counts}),
    )
    .await
    .map(drop)
}

#[utoipa::path(post, path = "/imports/{run}/collected", operation_id = "brainCollected", tag = "brain",
    params(("run" = String, Path, description = "Run id")), request_body = Collected,
    responses((status = 200, description = "The run; the last collector to report starts discovery", body = RunView)))]
pub(crate) async fn collected(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(run): Path<String>,
    Json(req): Json<Collected>,
) -> ApiResult<RunView> {
    let (state, sources) = run_state(&app, &run).await?;
    if state != "collecting" {
        return Err(ApiError::conflict("the run is not collecting"));
    }
    if !sources.contains(&req.source) {
        return Err(ApiError::bad_request("that source is not part of this run"));
    }
    let finished = mark_done(&app, &run, &req.source, &sources).await?;
    if finished {
        crate::review::discover(&app, &b, &run).await?;
    }
    get(State(app), Path(run)).await
}

/// Records that `source` reported (a retry is harmless); true when every source of the run has.
pub(crate) async fn mark_done(
    app: &App,
    run: &str,
    source: &str,
    all: &[String],
) -> Result<bool, ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    let done: String = sqlx::query_scalar("SELECT done FROM brain_import_runs WHERE id = ?")
        .bind(run)
        .fetch_one(&mut *tx)
        .await?;
    let mut done: Vec<String> = serde_json::from_str(&done).unwrap_or_default();
    if !done.iter().any(|d| d == source) {
        done.push(source.to_owned());
    }
    sqlx::query("UPDATE brain_import_runs SET done = ? WHERE id = ?")
        .bind(json!(done).to_string())
        .bind(run)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(all.iter().all(|s| done.contains(s)))
}

#[utoipa::path(get, path = "/imports/{run}", operation_id = "brainGetImport", tag = "brain",
    params(("run" = String, Path, description = "Run id")),
    responses((status = 200, description = "Stage and counts", body = RunView)))]
pub(crate) async fn get(State(app): State<App>, Path(run): Path<String>) -> ApiResult<RunView> {
    let row = sqlx::query("SELECT id, kind, state, stage, counts, sources, started_at FROM brain_import_runs WHERE id = ?")
        .bind(&run)
        .fetch_optional(&app.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("no such run"))?;
    let counts: String = row.try_get("counts")?;
    let sources: String = row.try_get("sources")?;
    Ok(Json(RunView {
        run: row.try_get("id")?,
        kind: row.try_get("kind")?,
        state: row.try_get("state")?,
        stage: row.try_get("stage")?,
        counts: serde_json::from_str(&counts).unwrap_or_default(),
        sources: serde_json::from_str(&sources).unwrap_or_default(),
        started_at: row.try_get("started_at")?,
    }))
}
