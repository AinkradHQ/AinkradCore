//! Distillation (E6-2, E6-3): an AI session claimed to one room reads that room's new sources and
//! answers with candidate records, each linked to the sources it came from. The answer is JSON
//! checked strictly; an answer that does not pass is rejected, never stored. The model is chosen by
//! the room's policy through the session's fallback chain (`claim`): a local-only room waits as
//! "Needs a local model" and never claims a cloud account. The text read and written stays in the
//! room's `canon.db`; the Core's transcript keeps a placeholder (Q-16, C-08).
//! ponytail: one session per run, sources capped per run; the rest wait for the next run.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use ainkrad_core_server::agents::{self, Refusal};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::agents::NewSession;
use ainkrad_core_server::store::chains::{self as ch, Request};
use ainkrad_core_server::store::{alloc, begin_write};
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::answer::{Candidate, Source, build_prompt, parse_output};
use crate::claim::{self, check_chain};
use crate::files::{self, CANON};
use crate::policy::{self, AUTO_KINDS};
use crate::transcripts::render;
use crate::{Brain, code, rand_id, record};

/// The agent name a user may bind a fallback chain to, so distillation can use its own chain.
pub const AGENT: &str = "brain-distil";
/// How often the `brain_distil` job moves waiting and running distillations.
pub const DISTIL_EVERY_SECS: u64 = 60;
/// Sources in one run, and their text in one prompt.
const MAX_SOURCES: i64 = 30;
const MAX_PROMPT_BYTES: usize = 120_000;
#[derive(Serialize, ToSchema)]
pub struct DistilView {
    pub id: String,
    pub room: String,
    /// `queued`, `needs_local_model`, `waiting`, `running`, `done` or `failed`.
    pub state: String,
    /// The AI session doing the work, once started.
    pub session: Option<String>,
    pub sources: i64,
    pub candidates: i64,
    /// Why it waits or failed: no chain, no runner, a refused claim naming the entry, a rejected answer.
    pub detail: String,
    pub created_at: String,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<DistilView, sqlx::Error> {
    Ok(DistilView {
        id: r.try_get("id")?,
        room: r.try_get("room")?,
        state: r.try_get("state")?,
        session: r.try_get("session")?,
        sources: r.try_get("sources")?,
        candidates: r.try_get("candidates")?,
        detail: r.try_get("detail")?,
        created_at: r.try_get("created_at")?,
    })
}

async fn canon(app: &App, b: &Brain, room: &str) -> Result<SqlitePool, ApiError> {
    let key = b.key(app).await?;
    files::open_migrated(
        &files::room_path(&files::root(app), room),
        &key,
        false,
        CANON,
    )
    .await
    .map_err(|e| code(500, "room_unavailable", e.to_string()))
}

async fn set_state(
    app: &App,
    id: &str,
    state: &str,
    detail: &str,
    extra: Option<(&str, i64)>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE brain_distils SET state = ?, detail = ?, updated_at = ?, \
         candidates = coalesce(?, candidates) WHERE id = ?",
    )
    .bind(state)
    .bind(detail)
    .bind(app.clock.now())
    .bind(extra.map(|(_, n)| n))
    .bind(id)
    .execute(&app.pool)
    .await
    .map(drop)
}

#[utoipa::path(post, path = "/rooms/{room}/distil", operation_id = "brainDistil", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Queues the distillation of the room's new sources. A room set to local-only waits as `needs_local_model`; `nothing_new` (409) when every source was read", body = DistilView)))]
pub(crate) async fn start(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
) -> ApiResult<DistilView> {
    let p = policy::load(&app, &room).await?;
    let pool = canon(&app, &b, &room).await?;
    let fresh: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sources WHERE distilled IS NULL AND pointer = 0")
            .fetch_one(&pool)
            .await?;
    pool.close().await;
    if fresh == 0 {
        return Err(code(
            409,
            "nothing_new",
            "every source of the room was already read",
        ));
    }
    let open: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_distils WHERE room = ? AND state IN ('queued','needs_local_model','waiting','running')",
    )
    .bind(&room)
    .fetch_one(&app.pool)
    .await?;
    if open > 0 {
        return Err(code(
            409,
            "distil_open",
            "a distillation of this room is already open",
        ));
    }
    let id = rand_id("dst-");
    let state = if p.local_only() {
        "needs_local_model"
    } else {
        "queued"
    };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "INSERT INTO brain_distils (id, room, state, requested_by, sources, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&room)
    .bind(state)
    .bind(&me.device.id)
    .bind(fresh.min(MAX_SOURCES))
    .bind(app.clock.now())
    .bind(app.clock.now())
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        "brain.distil.queued",
        json!({"room": room, "distil": id, "state": state}),
        None,
    )
    .await?;
    tx.commit().await?;
    advance(&app, &b).await?;
    let r = sqlx::query("SELECT * FROM brain_distils WHERE id = ?")
        .bind(&id)
        .fetch_one(&app.pool)
        .await?;
    Ok(Json(view(&r)?))
}

#[utoipa::path(get, path = "/rooms/{room}/distils", operation_id = "brainDistils", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "The room's distillations, newest first", body = Vec<DistilView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Path(room): Path<String>,
) -> ApiResult<Vec<DistilView>> {
    let rows = sqlx::query(
        "SELECT * FROM brain_distils WHERE room = ? ORDER BY created_at DESC, id DESC LIMIT 50",
    )
    .bind(&room)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}

/// Moves every open distillation one step: waiting ones launch when they can, running ones are
/// finished when their session is over. Never runs twice at once.
pub(crate) async fn advance(app: &App, b: &Brain) -> Result<(), ApiError> {
    if b.inner.distilling.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let out = advance_inner(app, b).await;
    b.inner.distilling.store(false, Ordering::SeqCst);
    out
}

async fn advance_inner(app: &App, b: &Brain) -> Result<(), ApiError> {
    let rows = sqlx::query(
        "SELECT * FROM brain_distils WHERE state IN ('queued','needs_local_model','waiting','running') ORDER BY created_at, id",
    )
    .fetch_all(&app.pool)
    .await?;
    for r in &rows {
        let d = view(r)?;
        let by: String = r.try_get("requested_by")?;
        let step = if d.state == "running" {
            finish(app, b, &d).await
        } else {
            launch(app, b, &d, &by).await
        };
        if let Err(e) = step {
            set_state(
                app,
                &d.id,
                "failed",
                &format!("{}: {}", e.code, e.message),
                None,
            )
            .await?;
        }
    }
    Ok(())
}

/// The first online runner that offers AI sessions.
fn pick_runner(app: &App) -> Option<String> {
    let mut all: Vec<_> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| {
            r.online
                && r.drivers
                    .iter()
                    .any(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER)
        })
        .map(|(id, _)| id)
        .collect();
    all.sort();
    all.into_iter().next()
}

async fn sources_for(pool: &SqlitePool) -> Result<Vec<Source>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT item_id, title, text FROM sources WHERE distilled IS NULL AND pointer = 0 \
         ORDER BY started_at, item_id LIMIT ?",
    )
    .bind(MAX_SOURCES)
    .fetch_all(pool)
    .await?;
    let (mut out, mut bytes) = (vec![], 0);
    for r in &rows {
        let mut text: String = r.try_get("text")?;
        let room_left = MAX_PROMPT_BYTES.saturating_sub(bytes);
        if room_left < 500 {
            break;
        }
        let mut end = text.len().min(room_left);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        bytes += text.len();
        out.push(Source {
            item_id: r.try_get("item_id")?,
            title: r.try_get("title")?,
            text,
        });
    }
    Ok(out)
}

/// Resolves the chain, checks it against the room's policy, then creates, claims and starts the
/// session. Anything that cannot happen yet leaves the distillation waiting, with the reason.
async fn launch(app: &App, b: &Brain, d: &DistilView, by: &str) -> Result<(), ApiError> {
    let p = policy::load(app, &d.room).await?;
    // The same chain the session will walk: the snapshot is taken at create, checked again by the claim.
    let user = ch::user_of(&app.pool, by).await?;
    let entries = {
        let mut conn = app.pool.acquire().await?;
        match ch::resolve_for(&mut conn, user, None, Some(AGENT)).await? {
            Some(id) => ch::load(&mut conn, id).await?,
            None => vec![],
        }
    };
    if let Err(why) = check_chain(&entries, &p) {
        // A local-only room has no local model to give: that is its own state, not a failure.
        let state = if p.local_only() {
            "needs_local_model"
        } else {
            "waiting"
        };
        return Ok(set_state(app, &d.id, state, &why, None).await?);
    }
    let Some(runner) = pick_runner(app) else {
        return Ok(set_state(app, &d.id, "waiting", "no runner is online", None).await?);
    };
    let pool = canon(app, b, &d.room).await?;
    let sources = sources_for(&pool).await?;
    if sources.is_empty() {
        pool.close().await;
        return Ok(set_state(
            app,
            &d.id,
            "done",
            "no new sources",
            Some(("candidates", 0)),
        )
        .await?);
    }
    let prompt = build_prompt(&p.name, &sources);
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
    let s = ch::create_session(&app.pool, &new, None, None, req, BY, &app.clock.now())
        .await
        .map_err(ApiError::from)?;
    if let Err(e) = claim::claim(app, &d.room, &s.id, by).await {
        // The chain moved between the check and the snapshot: the session never starts.
        alloc::end_unstarted_why(
            &app.pool,
            &s.id,
            &app.clock.now(),
            "the room refused its claim",
        )
        .await?;
        pool.close().await;
        return Ok(set_state(app, &d.id, "waiting", &e.message, None).await?);
    }
    // Mark the sources taken, so a second run never reads them again; a failed run gives them back.
    let mut tx = pool.begin().await?;
    for s in &sources {
        sqlx::query("UPDATE sources SET distilled = ? WHERE item_id = ?")
            .bind(&d.id)
            .bind(&s.item_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    pool.close().await;
    sqlx::query("UPDATE brain_distils SET session = ?, sources = ? WHERE id = ?")
        .bind(&s.id)
        .bind(i64::try_from(sources.len()).unwrap_or(0))
        .bind(&d.id)
        .execute(&app.pool)
        .await?;
    match agents::start(app, &s).await {
        Ok(()) => Ok(set_state(app, &d.id, "running", "", None).await?),
        Err(r) => {
            alloc::end_unstarted_why(&app.pool, &s.id, &app.clock.now(), "it could not start")
                .await?;
            give_back(app, b, d).await?;
            let why = match r {
                Refusal::Runner(e) => e.message,
                Refusal::Secrets(e) => e.to_string(),
                Refusal::Db(e) => e.to_string(),
            };
            Ok(set_state(app, &d.id, "waiting", &why, None).await?)
        }
    }
}

async fn give_back(app: &App, b: &Brain, d: &DistilView) -> Result<(), ApiError> {
    let pool = canon(app, b, &d.room).await?;
    sqlx::query("UPDATE sources SET distilled = NULL WHERE distilled = ?")
        .bind(&d.id)
        .execute(&pool)
        .await?;
    pool.close().await;
    Ok(())
}

/// The model's answer: the last thing the assistant said in the session.
async fn answer_of(app: &App, session: &str) -> Result<Option<String>, sqlx::Error> {
    let (mut after, mut last) = (0, None);
    loop {
        let page =
            ainkrad_core_server::store::agents::transcript(&app.pool, session, after, 500).await?;
        let Some(end) = page.last() else { break };
        after = i64::try_from(end.seq).unwrap_or(i64::MAX);
        for e in &page {
            if let Some(t) =
                render(&e.body).and_then(|t| t.strip_prefix("Assistant: ").map(str::to_owned))
            {
                last = Some(t);
            }
        }
    }
    Ok(last)
}

async fn finish(app: &App, b: &Brain, d: &DistilView) -> Result<(), ApiError> {
    let Some(session) = d.session.as_deref() else {
        return Ok(set_state(app, &d.id, "failed", "no session", None).await?);
    };
    let s = ainkrad_core_server::store::agents::get(&app.pool, session).await?;
    let Some(s) = s.filter(|s| !s.live()) else {
        // Still working (or gone: a deleted session is a failure the next line reports).
        if ainkrad_core_server::store::agents::get(&app.pool, session)
            .await?
            .is_none()
        {
            give_back(app, b, d).await?;
            return Ok(set_state(app, &d.id, "failed", "the AI session is gone", None).await?);
        }
        return Ok(());
    };
    let output = answer_of(app, &s.id).await?;
    let pool = canon(app, b, &d.room).await?;
    let known: HashSet<String> =
        sqlx::query_scalar("SELECT item_id FROM sources WHERE distilled = ?")
            .bind(&d.id)
            .fetch_all(&pool)
            .await?
            .into_iter()
            .collect();
    let parsed = match output.as_deref() {
        None => Err("the AI session gave no answer".to_owned()),
        Some(o) => parse_output(o, &known),
    };
    let out = match parsed {
        Err(why) => {
            // Rejected: nothing of the answer is stored, the sources go back to be read again.
            pool.close().await;
            give_back(app, b, d).await?;
            ainkrad_core_server::store::agents::seal(&app.pool, &s.id).await?;
            let mut tx = begin_write(&app.pool).await?;
            record(
                &mut tx,
                "brain.distil.rejected",
                json!({"room": d.room, "distil": d.id}),
                None,
            )
            .await?;
            tx.commit().await?;
            return Ok(set_state(
                app,
                &d.id,
                "failed",
                &format!("answer rejected: {why}"),
                None,
            )
            .await?);
        }
        Ok(c) => c,
    };
    let p = policy::load(app, &d.room).await?;
    let (n, accepted) =
        store_candidates(&pool, &d.id, &out, &p.auto_accept, &app.clock.now()).await?;
    // The transcript's answer goes into the room (C-08); the Core keeps a placeholder.
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('distil.answer', ?, ?)")
        .bind(json!({"distil": d.id, "session": s.id, "answer": output}).to_string())
        .bind(app.clock.now())
        .execute(&pool)
        .await?;
    pool.close().await;
    ainkrad_core_server::store::agents::seal(&app.pool, &s.id).await?;
    let mut tx = begin_write(&app.pool).await?;
    let waiting = n - accepted;
    record(
        &mut tx,
        "brain.distil.done",
        json!({"room": d.room, "distil": d.id, "candidates": n, "auto_accepted": accepted}),
        (waiting > 0).then(|| {
            (
                "brain.inbox",
                json!({"room": d.room, "op": "candidates", "waiting": waiting}),
            )
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(set_state(app, &d.id, "done", "", Some(("candidates", n))).await?)
}

/// Writes the candidates into the room as `records`, with their op-log and outbox rows, in one
/// transaction; kinds the room auto-accepts go straight to `accepted`. Returns (stored, auto-accepted).
pub(crate) async fn store_candidates(
    pool: &SqlitePool,
    distil: &str,
    out: &[Candidate],
    auto: &[String],
    now: &str,
) -> Result<(i64, i64), sqlx::Error> {
    let redactor = Redactor::new();
    let (mut n, mut accepted) = (0, 0);
    let mut tx = pool.begin().await?;
    for c in out {
        let id = rand_id("rec-");
        let auto_ok = AUTO_KINDS.contains(&c.kind.as_str()) && auto.contains(&c.kind);
        sqlx::query(
            "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, reviewed_at, decided_by, distil) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&c.kind)
        .bind(if auto_ok { "accepted" } else { "candidate" })
        .bind(redactor.text(c.body.trim()))
        .bind(json!(c.tags).to_string())
        .bind(json!(c.sources).to_string())
        .bind(now)
        .bind(auto_ok.then_some(now))
        .bind(auto_ok.then_some("auto"))
        .bind(distil)
        .execute(&mut *tx)
        .await?;
        log_op(
            &mut tx,
            if auto_ok {
                "record.accepted"
            } else {
                "record.candidate"
            },
            &id,
            now,
        )
        .await?;
        n += 1;
        accepted += i64::from(auto_ok);
    }
    tx.commit().await?;
    Ok((n, accepted))
}

/// An op-log row and its outbox row (BM-04 §5.4), in the caller's transaction.
pub(crate) async fn log_op(
    conn: &mut sqlx::SqliteConnection,
    op: &str,
    id: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    let seq = sqlx::query("INSERT INTO op_log (op, ref, at) VALUES (?, ?, ?)")
        .bind(op)
        .bind(id)
        .bind(now)
        .execute(&mut *conn)
        .await?
        .last_insert_rowid();
    sqlx::query("INSERT INTO outbox (op_seq) VALUES (?)")
        .bind(seq)
        .execute(&mut *conn)
        .await
        .map(drop)
}

struct DistilJob(Brain);

impl JobHandler for DistilJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = self.0.inner.app.get() else {
                return Err("the Core is still starting".to_owned());
            };
            let open: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM brain_distils WHERE state IN ('queued','needs_local_model','waiting','running')",
            )
            .fetch_one(&app.pool)
            .await
            .map_err(|e| e.to_string())?;
            if open == 0 {
                run.idle();
                return Ok(());
            }
            match advance(app, &self.0).await {
                Ok(()) => Ok(()),
                Err(e) if e.status == axum::http::StatusCode::CONFLICT => {
                    run.idle();
                    Ok(())
                }
                Err(e) => Err(format!("{}: {}", e.code, e.message)),
            }
        })
    }
}

pub(crate) fn job(b: &Brain) -> Job {
    Job::new(
        "brain_distil",
        Schedule::Every(DISTIL_EVERY_SECS),
        Arc::new(DistilJob(b.clone())),
    )
}
