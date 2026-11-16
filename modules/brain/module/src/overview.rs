//! The room Overview: a summary, rule sets and instructions for one room, written from the room's
//! own items. The local model picks what the cloud model reads (`semantic::pick`); the cloud model
//! writes, through the same fallback chain, policy check, claim and AI session as distillation
//! (`distil`). A room that does not allow cloud, or a Core with no account, calls nothing. One room
//! is written at a time. The instructions are the person's to edit and approve; nothing reads them yet.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use ainkrad_core_server::agents;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::agents::NewSession;
use ainkrad_core_server::store::chains::{self as ch, Request};
use ainkrad_core_server::store::{alloc, begin_write};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::claim::{self, check_chain};
use crate::distil::{AGENT, answer_of, canon, distilled_by, pick_runner};
use crate::overview_write::{self as w, Overview};
use crate::policy::{self, APPROVED_CLOUD, Policy};
use crate::{Brain, code, record};

pub const OVERVIEW_EVERY_SECS: u64 = 60;
const MAX_INSTRUCTIONS: usize = 8000;

#[derive(Serialize, ToSchema)]
pub struct Progress {
    /// Rooms in the current write-all (or the one room), and how many are finished.
    pub total: i64,
    pub done: i64,
    pub failed: i64,
    /// The room being written now.
    pub room: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OverviewView {
    pub room: String,
    /// `not_written`, `writing`, `written`, `failed`, `needs_account` or `cloud_off`.
    pub state: String,
    /// Why it waits, failed, or cannot be written.
    pub detail: String,
    pub written_at: Option<String>,
    /// The provider and account that wrote it.
    pub model: Option<String>,
    pub overview: Option<Overview>,
    /// The editable instructions; approved when `instructions_approved_at` is set.
    pub instructions: Option<String>,
    pub instructions_approved_at: Option<String>,
    pub progress: Progress,
    /// Title of every item a rule cites, by item id (for "from N items").
    pub source_titles: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize, ToSchema)]
pub struct InstructionsPatch {
    /// New text; omitted keeps the current text.
    pub text: Option<String>,
    /// True approves the text as it is after this call; false withdraws approval.
    pub approved: bool,
}

async fn progress(app: &App) -> Result<Progress, sqlx::Error> {
    let batch: Option<String> = sqlx::query_scalar(
        "SELECT batch FROM brain_overview_queue ORDER BY (state IN ('queued','running')) DESC, updated_at DESC LIMIT 1",
    )
    .fetch_optional(&app.pool)
    .await?;
    let Some(batch) = batch else {
        return Ok(Progress {
            total: 0,
            done: 0,
            failed: 0,
            room: None,
        });
    };
    let c = |sql: &'static str| {
        sqlx::query_scalar::<_, i64>(sql)
            .bind(batch.clone())
            .fetch_one(&app.pool)
    };
    Ok(Progress {
        total: c("SELECT count(*) FROM brain_overview_queue WHERE batch = ?").await?,
        done: c("SELECT count(*) FROM brain_overview_queue WHERE batch = ? AND state IN ('done','failed')").await?,
        failed: c("SELECT count(*) FROM brain_overview_queue WHERE batch = ? AND state = 'failed'").await?,
        room: sqlx::query_scalar("SELECT room FROM brain_overview_queue WHERE batch = ? AND state = 'running'")
            .bind(&batch)
            .fetch_optional(&app.pool)
            .await?,
    })
}

async fn row(pool: &SqlitePool, now: &str) -> Result<sqlx::sqlite::SqliteRow, sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO room_overview (id, updated_at) VALUES (1, ?)")
        .bind(now)
        .execute(pool)
        .await?;
    sqlx::query("SELECT * FROM room_overview WHERE id = 1")
        .fetch_one(pool)
        .await
}

async fn view(app: &App, room: &str, pool: &SqlitePool) -> Result<OverviewView, ApiError> {
    let r = row(pool, &app.clock.now()).await?;
    let overview: Option<Overview> = r
        .try_get::<Option<String>, _>("overview")?
        .and_then(|j| serde_json::from_str(&j).ok());
    let mut source_titles = std::collections::BTreeMap::new();
    if let Some(o) = &overview {
        let rs = &o.rules;
        for id in [&rs.workflow, &rs.code, &rs.design, &rs.never]
            .into_iter()
            .flatten()
            .flat_map(|x| &x.sources)
        {
            if source_titles.contains_key(id) {
                continue;
            }
            let t: Option<String> = sqlx::query_scalar("SELECT title FROM sources WHERE item_id = ?")
                .bind(id)
                .fetch_optional(pool)
                .await?;
            if let Some(t) = t {
                source_titles.insert(id.clone(), t);
            }
        }
    }
    Ok(OverviewView {
        source_titles,
        room: room.to_owned(),
        state: r.try_get("state")?,
        detail: r.try_get("detail")?,
        written_at: r.try_get("written_at")?,
        model: r.try_get("model")?,
        overview,
        instructions: r.try_get("instructions")?,
        instructions_approved_at: r.try_get("instructions_approved_at")?,
        progress: progress(app).await?,
    })
}

async fn set_state(
    pool: &SqlitePool,
    state: &str,
    detail: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    row(pool, now).await?;
    sqlx::query("UPDATE room_overview SET state = ?, detail = ?, updated_at = ? WHERE id = 1")
        .bind(state)
        .bind(detail)
        .bind(now)
        .execute(pool)
        .await
        .map(drop)
}

async fn audit(
    app: &App,
    action: &str,
    room: &str,
    extra: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        action,
        json!({"room": room, "detail": extra}),
        None,
    )
    .await?;
    tx.commit().await
}

#[utoipa::path(get, path = "/rooms/{room}/overview", operation_id = "brainOverview", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "The room's Overview: summary, facts, rule sets, instructions, its state and the progress of the write in flight", body = OverviewView)))]
pub(crate) async fn get(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(room): Path<String>,
) -> ApiResult<OverviewView> {
    policy::load(&app, &room).await?;
    let pool = canon(&app, &b, &room).await?;
    let v = view(&app, &room, &pool).await;
    pool.close().await;
    Ok(Json(v?))
}

/// Why a room cannot be written now: (state, reason). `None` when it can.
async fn blocked(
    app: &App,
    p: &Policy,
    by: &str,
) -> Result<Option<(&'static str, String)>, ApiError> {
    if !APPROVED_CLOUD.iter().any(|c| p.allows(c)) {
        return Ok(Some((
            "cloud_off",
            format!("room {} does not allow a cloud model", p.name),
        )));
    }
    let user = ch::user_of(&app.pool, by).await?;
    let entries = {
        let mut conn = app.pool.acquire().await?;
        match ch::resolve_for(&mut conn, user, None, Some(AGENT)).await? {
            Some(id) => ch::load(&mut conn, id).await?,
            None => vec![],
        }
    };
    Ok(check_chain(&entries, p)
        .err()
        .map(|why| ("needs_account", why)))
}

async fn batch_of_open(app: &App) -> Result<String, sqlx::Error> {
    let open: Option<String> = sqlx::query_scalar(
        "SELECT batch FROM brain_overview_queue WHERE state IN ('queued','running') LIMIT 1",
    )
    .fetch_optional(&app.pool)
    .await?;
    if let Some(b) = open {
        return Ok(b);
    }
    sqlx::query("DELETE FROM brain_overview_queue WHERE state IN ('done','failed')")
        .execute(&app.pool)
        .await?;
    Ok(w::new_batch())
}

/// Queues one room, or records why it cannot be written. Returns whether it was queued.
async fn enqueue(app: &App, b: &Brain, room: &str, by: &str) -> Result<bool, ApiError> {
    let p = policy::load(app, room).await?;
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_overview_queue WHERE room = ? AND state IN ('queued','running')",
    )
    .bind(room)
    .fetch_one(&app.pool)
    .await?;
    if open > 0 {
        return Err(code(
            409,
            "overview_open",
            "this room's overview is already being written",
        ));
    }
    let pool = canon(app, b, room).await?;
    let now = app.clock.now();
    if let Some((state, why)) = blocked(app, &p, by).await? {
        set_state(&pool, state, &why, &now).await?;
        pool.close().await;
        return Ok(false);
    }
    set_state(&pool, "writing", "queued", &now).await?;
    pool.close().await;
    let batch = batch_of_open(app).await?;
    sqlx::query(
        "INSERT OR REPLACE INTO brain_overview_queue (room, batch, state, attempt, requested_by, created_at, updated_at) \
         VALUES (?, ?, 'queued', 1, ?, ?, ?)",
    )
    .bind(room)
    .bind(batch)
    .bind(by)
    .bind(&now)
    .bind(&now)
    .execute(&app.pool)
    .await?;
    audit(app, "brain.overview.queued", room, json!({})).await?;
    Ok(true)
}

#[utoipa::path(post, path = "/rooms/{room}/overview/write", operation_id = "brainOverviewWrite", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses(
        (status = 202, description = "Queued: a background job picks the room's items locally and has the cloud model write the overview. One room is written at a time", body = OverviewView),
        (status = 200, description = "Nothing was queued: the state is `cloud_off` (the room does not allow cloud) or `needs_account` (no approved account); no model was called", body = OverviewView)))]
pub(crate) async fn write(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
) -> Result<(StatusCode, Json<OverviewView>), ApiError> {
    let queued = enqueue(&app, &b, &room, &me.device.id).await?;
    if queued {
        advance(&app, &b).await?;
    }
    let pool = canon(&app, &b, &room).await?;
    let v = view(&app, &room, &pool).await;
    pool.close().await;
    let code = if queued {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((code, Json(v?)))
}

#[utoipa::path(post, path = "/overview/write-all", operation_id = "brainOverviewWriteAll", tag = "brain",
    responses((status = 202, description = "Queues every active room that is not already queued and can be written; rooms that cannot (cloud off, no account) get that state. Poll `GET /overview/progress`", body = Progress)))]
pub(crate) async fn write_all(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
) -> Result<(StatusCode, Json<Progress>), ApiError> {
    let rooms: Vec<String> =
        sqlx::query_scalar("SELECT id FROM brain_rooms WHERE state = 'active' ORDER BY id")
            .fetch_all(&app.pool)
            .await?;
    for r in &rooms {
        match enqueue(&app, &b, r, &me.device.id).await {
            Ok(_) => {}
            Err(e) if e.status == StatusCode::CONFLICT => {}
            Err(e) => return Err(e),
        }
    }
    advance(&app, &b).await?;
    Ok((StatusCode::ACCEPTED, Json(progress(&app).await?)))
}

#[utoipa::path(get, path = "/overview/progress", operation_id = "brainOverviewProgress", tag = "brain",
    responses((status = 200, description = "How far the current batch of overview writes is: `done` of `total` rooms", body = Progress)))]
pub(crate) async fn progress_route(State(app): State<App>) -> ApiResult<Progress> {
    Ok(Json(progress(&app).await?))
}

#[utoipa::path(patch, path = "/rooms/{room}/overview/instructions", operation_id = "brainOverviewInstructions", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = InstructionsPatch,
    responses((status = 200, description = "The instructions after the change. Editing the text without `approved: true` withdraws approval. `not_written` (409) before an overview exists", body = OverviewView)))]
pub(crate) async fn instructions(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(room): Path<String>,
    Json(body): Json<InstructionsPatch>,
) -> ApiResult<OverviewView> {
    policy::load(&app, &room).await?;
    if body
        .text
        .as_ref()
        .is_some_and(|t| t.chars().count() > MAX_INSTRUCTIONS)
    {
        return Err(code(
            400,
            "instructions_too_long",
            "the instructions are over 8000 characters",
        ));
    }
    let pool = canon(&app, &b, &room).await?;
    let now = app.clock.now();
    let r = row(&pool, &now).await?;
    if r.try_get::<Option<String>, _>("overview")?.is_none() {
        pool.close().await;
        return Err(code(409, "not_written", "this room has no overview yet"));
    }
    sqlx::query(
        "UPDATE room_overview SET instructions = coalesce(?, instructions), \
         instructions_approved_at = ?, updated_at = ? WHERE id = 1",
    )
    .bind(body.text.as_deref())
    .bind(body.approved.then_some(now.as_str()))
    .bind(&now)
    .execute(&pool)
    .await?;
    audit(
        &app,
        "brain.overview.instructions",
        &room,
        json!({"approved": body.approved}),
    )
    .await?;
    let v = view(&app, &room, &pool).await;
    pool.close().await;
    Ok(Json(v?))
}

/// Moves the queue one step: finishes the running room, else starts the oldest queued one. Never
/// runs twice at once, and never more than one room at a time.
pub(crate) async fn advance(app: &App, b: &Brain) -> Result<(), ApiError> {
    if b.inner.overviewing.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let out = advance_inner(app, b).await;
    b.inner.overviewing.store(false, Ordering::SeqCst);
    out
}

async fn advance_inner(app: &App, b: &Brain) -> Result<(), ApiError> {
    let next = sqlx::query(
        "SELECT room, attempt, session, requested_by, state FROM brain_overview_queue \
         WHERE state IN ('queued','running') ORDER BY (state = 'running') DESC, created_at, room LIMIT 1",
    )
    .fetch_optional(&app.pool)
    .await?;
    let Some(n) = next else { return Ok(()) };
    let room: String = n.try_get("room")?;
    let (attempt, by): (i64, String) = (n.try_get("attempt")?, n.try_get("requested_by")?);
    let step = if n.try_get::<String, _>("state")? == "running" {
        finish(
            app,
            b,
            &room,
            attempt,
            n.try_get::<Option<String>, _>("session")?.as_deref(),
        )
        .await
    } else {
        launch(app, b, &room, attempt, &by).await
    };
    if let Err(e) = step {
        let why = format!("{}: {}", e.code, e.message);
        if let Ok(pool) = canon(app, b, &room).await {
            let _ = set_state(&pool, "failed", &why, &app.clock.now()).await;
            pool.close().await;
        }
        queue_state(app, &room, "failed", None, attempt).await?;
    }
    Ok(())
}

async fn queue_state(
    app: &App,
    room: &str,
    state: &str,
    session: Option<&str>,
    attempt: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE brain_overview_queue SET state = ?, session = ?, attempt = ?, updated_at = ? WHERE room = ?")
        .bind(state)
        .bind(session)
        .bind(attempt)
        .bind(app.clock.now())
        .bind(room)
        .execute(&app.pool)
        .await
        .map(drop)
}

async fn launch(app: &App, b: &Brain, room: &str, attempt: i64, by: &str) -> Result<(), ApiError> {
    let p = policy::load(app, room).await?;
    let pool = canon(app, b, room).await?;
    let now = app.clock.now();
    // The same checks as the POST, again: the room or the chain may have changed while it waited.
    if let Some((state, why)) = blocked(app, &p, by).await? {
        set_state(&pool, state, &why, &now).await?;
        pool.close().await;
        return Ok(queue_state(app, room, "done", None, attempt).await?);
    }
    let Some(runner) = pick_runner(app) else {
        set_state(&pool, "writing", "waiting: no runner is online", &now).await?;
        pool.close().await;
        return Ok(());
    };
    let sel = w::select(b, &pool).await?;
    if sel.items.is_empty() {
        set_state(&pool, "failed", "the room has no items to read", &now).await?;
        pool.close().await;
        return Ok(queue_state(app, room, "failed", None, attempt).await?);
    }
    let retry: Option<String> = sqlx::query_scalar("SELECT detail FROM room_overview WHERE id = 1")
        .fetch_one(&pool)
        .await
        .ok()
        .and_then(|d: String| d.strip_prefix("rejected: ").map(str::to_owned))
        .filter(|_| attempt > 1);
    let prompt = w::build_prompt(&p.name, &sel, retry.as_deref());
    let user = ch::user_of(&app.pool, by).await?;
    let policy = json!({"mode": "ask"});
    let new = NewSession {
        runner: &runner,
        harness: "",
        model: None,
        prompt: Some(&prompt),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: by,
    };
    let req = Request {
        user_id: user,
        chain: None,
        agent: Some(AGENT),
    };
    let s = ch::create_session(&app.pool, &new, None, None, req, BY, &now)
        .await
        .map_err(ApiError::from)?;
    if let Err(e) = claim::claim(app, room, &s.id, by).await {
        alloc::end_unstarted_why(&app.pool, &s.id, &now, "the room refused its claim").await?;
        set_state(&pool, "needs_account", &e.message, &now).await?;
        pool.close().await;
        return Ok(queue_state(app, room, "done", None, attempt).await?);
    }
    sqlx::query("UPDATE room_overview SET selection = ? WHERE id = 1")
        .bind(json!(sel.ids()).to_string())
        .execute(&pool)
        .await?;
    set_state(&pool, "writing", "", &now).await?;
    pool.close().await;
    match agents::start(app, &s).await {
        Ok(()) => Ok(queue_state(app, room, "running", Some(&s.id), attempt).await?),
        Err(_) => {
            alloc::end_unstarted_why(&app.pool, &s.id, &now, "it could not start").await?;
            let pool = canon(app, b, room).await?;
            set_state(
                &pool,
                "writing",
                "waiting: the AI session could not start",
                &now,
            )
            .await?;
            pool.close().await;
            Ok(())
        }
    }
}

async fn finish(
    app: &App,
    b: &Brain,
    room: &str,
    attempt: i64,
    session: Option<&str>,
) -> Result<(), ApiError> {
    let Some(session) = session else {
        return Err(code(500, "no_session", "no session"));
    };
    let Some(s) = ainkrad_core_server::store::agents::get(&app.pool, session).await? else {
        return Err(code(500, "session_gone", "the AI session is gone"));
    };
    if s.live() {
        return Ok(());
    }
    let output = answer_of(app, &s.id).await?;
    let pool = canon(app, b, room).await?;
    let now = app.clock.now();
    let known: HashSet<String> = serde_json::from_str::<Vec<String>>(
        &sqlx::query_scalar::<_, String>("SELECT selection FROM room_overview WHERE id = 1")
            .fetch_one(&pool)
            .await?,
    )
    .unwrap_or_default()
    .into_iter()
    .collect();
    let parsed = match output.as_deref() {
        None => Err("the AI session gave no answer".to_owned()),
        Some(o) => w::parse(o, &known),
    };
    // The answer's text goes into the room (C-08); the Core keeps a placeholder.
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('overview.answer', ?, ?)")
        .bind(json!({"session": s.id, "answer": output}).to_string())
        .bind(&now)
        .execute(&pool)
        .await?;
    ainkrad_core_server::store::agents::seal(&app.pool, &s.id).await?;
    match parsed {
        Err(why) if attempt < 2 => {
            set_state(&pool, "writing", &format!("rejected: {why}"), &now).await?;
            queue_state(app, room, "queued", None, attempt + 1).await?;
        }
        Err(why) => {
            set_state(&pool, "failed", &format!("answer rejected: {why}"), &now).await?;
            queue_state(app, room, "failed", None, attempt).await?;
            audit(app, "brain.overview.failed", room, json!({})).await?;
        }
        Ok(o) => {
            let by = distilled_by(app, &s).await;
            let model = match (by.provider, by.account) {
                (Some(p), Some(a)) => Some(format!("{p}:{a}")),
                (Some(p), None) => Some(p),
                _ => s.model.clone(),
            };
            // An approved text of the person's stays; the model's new one waits in `overview`.
            sqlx::query(
                "UPDATE room_overview SET state = 'written', detail = '', overview = ?, written_at = ?, model = ?, \
                 instructions = CASE WHEN instructions_approved_at IS NULL OR instructions IS NULL THEN ? ELSE instructions END, \
                 updated_at = ? WHERE id = 1",
            )
            .bind(serde_json::to_string(&o).unwrap_or_default())
            .bind(&now)
            .bind(model)
            .bind(&o.instructions)
            .bind(&now)
            .execute(&pool)
            .await?;
            queue_state(app, room, "done", None, attempt).await?;
            audit(app, "brain.overview.written", room, json!({})).await?;
        }
    }
    pool.close().await;
    Ok(())
}

struct OverviewJob(Brain);

impl JobHandler for OverviewJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            let open: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM brain_overview_queue WHERE state IN ('queued','running')",
            )
            .fetch_one(&app.pool)
            .await
            .map_err(|e| e.to_string())?;
            if open == 0 {
                run.idle();
                return Ok(());
            }
            advance(app, &self.0)
                .await
                .map_err(|e| format!("{}: {}", e.code, e.message))
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_overview",
        Schedule::Every(OVERVIEW_EVERY_SECS),
        Arc::new(OverviewJob(b.clone())),
    )
}
