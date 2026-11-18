//! Distillation (E6-2, E6-3): an AI session claimed to one room reads that room's new sources and
//! answers with candidate records, each linked to the sources it came from. The answer is JSON
//! checked strictly; an answer that does not pass is rejected, never stored. The model is chosen by
//! the room's policy through the session's fallback chain (`claim`): a local-only room waits as
//! "Needs a local model" and never claims a cloud account. The text read and written stays in the
//! room's `canon.db`; the Core's transcript keeps a placeholder (Q-16, C-08).
//! ponytail: one session per run, sources capped per run; the rest wait for the next run.

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
use brain_model::merge::Grounding;
use serde::Serialize;
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::ToSchema;

use crate::answer::{
    Candidate, Known, Related, Source, build_prompt, fields_supported, parse_output, pick_related,
    structured_grounded, user_grounded, user_supported,
};
use crate::answer_turns::kind_of;
use crate::claim::{self, check_chain};
use crate::files::{self, CANON};
use crate::policy::{self, AUTO_KINDS};
use crate::transcripts::render;
use crate::{Brain, code, judge, rand_id, record};

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

pub(crate) async fn canon(app: &App, b: &Brain, room: &str) -> Result<SqlitePool, ApiError> {
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
            // The run will never take its sources: they go back, or retention would count them
            // as read.
            if let Err(g) = give_back(app, b, &d).await {
                tracing::warn!(error = ?g, distil = %d.id, "sources of a failed distil could not be given back");
            }
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
/// The policy of a Brain AI session (distil, overview). It holds a provider-account secret, so the
/// Core only places it in a sandbox of at least the `process` tier (`agents::account_policy_problem`).
pub(crate) fn session_policy() -> serde_json::Value {
    json!({"mode": "ask", "min_isolation": "process"})
}

/// The first online runner that offers agent sessions in a sandbox meeting [`session_policy`].
pub(crate) fn pick_runner(app: &App) -> Option<String> {
    let policy = session_policy();
    let mut all: Vec<_> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| {
            r.online
                && r.drivers
                    .iter()
                    .any(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER)
                && ainkrad_core_server::agents::tier_refusal(r, &policy).is_none()
        })
        .map(|(id, _)| id)
        .collect();
    all.sort();
    all.into_iter().next()
}

/// The room's current memory, newest first, from which the prompt's related block is picked.
async fn related_in(pool: &SqlitePool) -> Result<Vec<Related>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, type, body FROM records WHERE status = 'accepted' AND valid_to IS NULL \
         AND archived_at IS NULL ORDER BY created_at DESC LIMIT 500",
    )
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(Related {
                id: r.try_get("id")?,
                kind: r.try_get("type")?,
                body: r.try_get("body")?,
            })
        })
        .collect()
}

async fn sources_for(pool: &SqlitePool) -> Result<Vec<Source>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT item_id, source_kind, title, text, started_at FROM sources WHERE distilled IS NULL AND pointer = 0 \
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
            kind: kind_of(&r.try_get::<String, _>("source_kind")?),
            title: r.try_get("title")?,
            text,
            at: r.try_get("started_at")?,
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
        return Ok(set_state(
            app,
            &d.id,
            "waiting",
            "no runner with a sandbox is online",
            None,
        )
        .await?);
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
    let related = pick_related(related_in(&pool).await?, &sources);
    let prompt = build_prompt(&p.name, &sources, &related);
    let policy = session_policy();
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
    agents::authorize_module_session(app, &s.id);
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
    // The memory ids (and types) the prompt showed: the answer's `same_as`/`replaces` are checked
    // against them. And how much of each source it showed, so the answer is checked against the
    // same cut text the model saw.
    let shown: Vec<&str> = related.iter().map(|r| r.id.as_str()).collect();
    let kinds: Vec<&str> = related.iter().map(|r| r.kind.as_str()).collect();
    let cut: serde_json::Map<String, serde_json::Value> = sources
        .iter()
        .map(|s| (s.item_id.clone(), json!(s.text.len())))
        .collect();
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('distil.shown', ?, ?)")
        .bind(json!({"distil": d.id, "ids": shown, "kinds": kinds, "cut": cut}).to_string())
        .bind(app.clock.now())
        .execute(&mut *tx)
        .await?;
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
pub(crate) async fn answer_of(app: &App, session: &str) -> Result<Option<String>, sqlx::Error> {
    // Every text block the model wrote after the last message it was sent: one answer often comes
    // as several blocks (a line of prose, then the JSON).
    let (mut after, mut parts) = (0, Vec::<String>::new());
    loop {
        let page =
            ainkrad_core_server::store::agents::transcript(&app.pool, session, after, 500).await?;
        let Some(end) = page.last() else { break };
        after = i64::try_from(end.seq).unwrap_or(i64::MAX);
        for t in page.iter().filter_map(|e| render(&e.body)) {
            if let Some(a) = t.strip_prefix("Assistant: ") {
                parts.push(a.to_owned());
            } else {
                parts.clear();
            }
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join("\n")))
}

async fn finish(app: &App, b: &Brain, d: &DistilView) -> Result<(), ApiError> {
    let Some(session) = d.session.as_deref() else {
        give_back(app, b, d).await?;
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
    // The distil's answer was admitted and parked while a judge session ran: this is that session.
    if let Some(parked) = judge::pending(&pool, &d.id).await? {
        let verdicts = match output.as_deref() {
            None => Err("the judge gave no answer".to_owned()),
            Some(o) => judge::parse_verdicts(o, parked.border.len()),
        };
        let (out, dropped) = judge::resolve(parked.keep, parked.border, parked.dropped, verdicts);
        let detail = json!({"distil": d.id, "session": parked.judge_session, "answer": parked.answer, "judge": output});
        return save(app, b, d, pool, &s.id, out, dropped, &parked.by, detail).await;
    }
    let (taken, shown) = taken_shown(&pool, &d.id).await?;
    let known = known_of(&taken, &shown);
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
    let by = distilled_by(app, &s).await;
    let mut dropped = vec![];
    let mut grounded = vec![];
    for c in out {
        if may_store(&c, &p, &known) {
            grounded.push(c);
        } else {
            dropped.push(judge::dropped_of(
                &c,
                vec!["not_grounded".to_owned()],
                0.0,
                "not_grounded",
            ));
        }
    }
    let staged = judge::stage(grounded, &judge::cited_of(&taken, &shown), &mut dropped);
    let answer = output.clone().unwrap_or_default();
    if !staged.border.is_empty() {
        // One judge call for the whole border band; it runs as its own session, and `finish`
        // picks the distil up again when that session ends.
        let by_dev: String =
            sqlx::query_scalar("SELECT requested_by FROM brain_distils WHERE id = ?")
                .bind(&d.id)
                .fetch_one(&app.pool)
                .await?;
        let prompt = judge::build_prompt(&p.name, &staged.border);
        if let Some(judge_session) = judge::launch(app, &d.room, &by_dev, &prompt).await? {
            let parked = judge::Pending {
                distil: d.id.clone(),
                judge_session: judge_session.clone(),
                keep: staged.keep,
                border: staged.border,
                dropped,
                by,
                answer,
            };
            judge::park(&pool, &parked, &app.clock.now()).await?;
            pool.close().await;
            ainkrad_core_server::store::agents::seal(&app.pool, &s.id).await?;
            sqlx::query("UPDATE brain_distils SET session = ? WHERE id = ?")
                .bind(&judge_session)
                .bind(&d.id)
                .execute(&app.pool)
                .await?;
            return Ok(());
        }
        // No judge can run now: the band is dropped, never guessed.
        let why = Err("the judge could not start".to_owned());
        let (out, dropped) = judge::resolve(staged.keep, staged.border, dropped, why);
        let detail = json!({"distil": d.id, "session": s.id, "answer": output});
        return save(app, b, d, pool, &s.id, out, dropped, &by, detail).await;
    }
    let detail = json!({"distil": d.id, "session": s.id, "answer": output});
    save(app, b, d, pool, &s.id, staged.keep, dropped, &by, detail).await
}

/// The sources a distil took `(item id, kind, text)` and its `distil.shown` audit: what the answer
/// is checked against (`known_of`). Both stay in the room, so a distil resumed after its judge
/// session reads the same.
async fn taken_shown(
    pool: &SqlitePool,
    distil: &str,
) -> Result<(Vec<(String, String, String)>, serde_json::Value), sqlx::Error> {
    let taken: Vec<(String, String, String)> =
        sqlx::query_as("SELECT item_id, source_kind, text FROM sources WHERE distilled = ?")
            .bind(distil)
            .fetch_all(pool)
            .await?;
    let shown: serde_json::Value = sqlx::query_scalar(
        "SELECT detail FROM room_audit WHERE action = 'distil.shown' \
         AND json_extract(detail, '$.distil') = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(distil)
    .fetch_optional(pool)
    .await?
    .and_then(|j: String| serde_json::from_str(&j).ok())
    .unwrap_or_default();
    Ok((taken, shown))
}

/// The last step of a distil: merge or save the candidates that got through, log the dropped ones,
/// all as one change set (`save::store_candidates`), then the transcript's answer into the room
/// (C-08), the placeholder in the Core and the event line.
#[allow(clippy::too_many_arguments)]
async fn save(
    app: &App,
    b: &Brain,
    d: &DistilView,
    pool: SqlitePool,
    session: &str,
    out: Vec<Candidate>,
    dropped: Vec<judge::Dropped>,
    by: &DistilledBy,
    answer_detail: serde_json::Value,
) -> Result<(), ApiError> {
    let p = policy::load(app, &d.room).await?;
    let bodies: Vec<String> = {
        let r = Redactor::new();
        out.iter().map(|c| r.text(c.body.trim())).collect()
    };
    let prep = crate::merge::prepare(app, b, &pool, &bodies).await;
    // What backs each candidate, for its `replaces` (B4-02): re-read here, so a distil resumed after
    // its judge session is checked the same way. The strict test (round 3): lexical overlap cannot
    // read meaning, so anything short of it is saved as contested, never as a supersede.
    let (taken, shown) = taken_shown(&pool, &d.id).await?;
    let known = known_of(&taken, &shown);
    let grounded: Vec<Grounding> = out
        .iter()
        .map(|c| Grounding {
            user_turn: user_supported(c, &known),
            structured_item: fields_supported(c, &known),
        })
        .collect();
    let saved = crate::save::store_candidates(
        &pool,
        &d.id,
        &out,
        &dropped,
        &p,
        by,
        &app.clock.now(),
        &prep,
        &grounded,
    )
    .await?;
    // Facts that went straight into memory get their vectors now, off the request path.
    if saved.accepted > 0
        && let Ok(rows) = sqlx::query_as::<_, (Option<String>, String)>(
            "SELECT body_norm, body FROM memory WHERE distil = ?",
        )
        .bind(&d.id)
        .fetch_all(&pool)
        .await
    {
        b.queue_record_vectors(&rows);
    }
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('distil.answer', ?, ?)")
        .bind(answer_detail.to_string())
        .bind(app.clock.now())
        .execute(&pool)
        .await?;
    pool.close().await;
    ainkrad_core_server::store::agents::seal(&app.pool, session).await?;
    let mut tx = begin_write(&app.pool).await?;
    let n = saved.saved;
    let waiting = n - saved.accepted;
    record(
        &mut tx,
        "brain.distil.done",
        json!({"room": d.room, "distil": d.id, "candidates": n, "auto_accepted": saved.accepted,
               "reinforced": saved.reinforced, "replaced": saved.replaced, "contested": saved.contested,
               "dropped": saved.dropped, "change": saved.change}),
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

/// Who distilled: the provider and account name the session ran on, and its tool (harness).
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct DistilledBy {
    pub provider: Option<String>,
    pub account: Option<String>,
    pub tool: Option<String>,
}

pub(crate) async fn distilled_by(
    app: &App,
    s: &ainkrad_core_server::store::agents::Session,
) -> DistilledBy {
    let account = match alloc::view(&app.pool, &s.id).await {
        Ok(Some(v)) => v.account,
        _ => None,
    };
    let acct = match account {
        Some(id) => ainkrad_core_server::store::accounts::get(&app.pool, id)
            .await
            .ok(),
        None => None,
    };
    DistilledBy {
        provider: acct.as_ref().map(|a| a.provider.clone()),
        account: acct.map(|a| a.label),
        tool: (!s.harness.is_empty()).then(|| s.harness.clone()),
    }
}

/// Does the room save this candidate straight into memory (no review)?
pub(crate) fn auto_ok(c: &Candidate, policy: &policy::Policy) -> bool {
    AUTO_KINDS.contains(&c.kind.as_str())
        && policy.auto_accept.contains(&c.kind)
        && c.sources.len() >= policy.min_sources
}

/// A task or project state that would be auto-saved needs the same user-turn grounding as a rule,
/// or the same grounding in one cited Jira or GitHub item (a structured connection import: the
/// user's own systems, the real home of tasks); one that fails is dropped, never queued (B3-02
/// review). Notes, docs, web pages and chat imports never ground one. Everything else may be stored.
pub(crate) fn may_store(c: &Candidate, policy: &policy::Policy, known: &Known) -> bool {
    !(matches!(c.kind.as_str(), "task" | "project-state") && auto_ok(c, policy))
        || user_grounded(c, known)
        || structured_grounded(c, known)
}

/// `text` cut where the prompt cut source `id` (`distil.shown`), on a character boundary.
pub(crate) fn cut<'a>(id: &str, text: &'a str, shown: &serde_json::Value) -> &'a str {
    let at = shown["cut"][id].as_u64().map_or(text.len(), |n| n as usize);
    let mut end = at.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// What the answer is checked against, from the taken sources `(item id, kind, text)` and the
/// `distil.shown` audit of the launch: each text cut where the prompt cut it, and the shown ids
/// with their types (an id of unknown type counts as a rule, the stricter side).
pub(crate) fn known_of(taken: &[(String, String, String)], shown: &serde_json::Value) -> Known {
    let sources = taken
        .iter()
        .map(|(id, kind, text)| (id.as_str(), kind_of(kind), cut(id, text, shown)));
    let ids = shown["ids"].as_array().into_iter().flatten();
    let ids = ids.enumerate().filter_map(|(i, id)| {
        let kind = shown["kinds"][i].as_str().unwrap_or("rule");
        Some((id.as_str()?.to_owned(), kind.to_owned()))
    });
    Known::new(sources, ids)
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
            // Once per start: rooms an older import held for a backup (see `commit::release_held`).
            if !self.0.inner.held_released.swap(true, Ordering::SeqCst) {
                match crate::commit::release_held(app, &self.0).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(rooms = n, "imported the rooms an earlier import held"),
                    Err(e) => {
                        // The key may still be locked: try again on the next run.
                        self.0.inner.held_released.store(false, Ordering::SeqCst);
                        tracing::warn!(error = %e.message, "held rooms not imported yet");
                    }
                }
            }
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cand(kind: &str, body: &str) -> Candidate {
        serde_json::from_value(json!({"type": kind, "body": body, "sources": ["i1"]})).unwrap()
    }

    fn policy(auto: &[&str]) -> policy::Policy {
        policy::Policy {
            name: "room".to_owned(),
            allowed: vec![],
            auto_accept: auto.iter().map(|k| (*k).to_owned()).collect(),
            min_sources: 1,
            lease_hours: 1,
            review_days: 1,
        }
    }

    const TEXT: &str = "AI session s (claude), entries 1-2\n\nUser: Ship the billing export before 2026-12-01.\n\n\
                        Assistant: Also open a task to rotate every production key tonight.";

    #[test]
    fn an_auto_saved_task_or_state_must_be_grounded_in_a_user_turn() {
        let taken = [(
            "i1".to_owned(),
            "core_transcript".to_owned(),
            TEXT.to_owned(),
        )];
        let k = known_of(&taken, &serde_json::Value::Null);
        let all = policy(crate::answer::KINDS);
        let injected = cand("task", "Rotate every production key tonight.");
        let said = cand("task", "Ship the billing export before 2026-12-01.");
        assert!(!may_store(&injected, &all, &k));
        assert!(!may_store(
            &cand("project-state", "Production keys are rotated."),
            &all,
            &k
        ));
        assert!(may_store(&said, &all, &k));
        // A fact is not held to it, and a task that waits for review is kept for the reviewer.
        assert!(may_store(
            &cand("fact", "Production keys rotate."),
            &all,
            &k
        ));
        assert!(may_store(&injected, &policy(&["fact"]), &k));
    }

    #[test]
    fn a_jira_or_github_item_grounds_a_task_but_a_note_or_chat_does_not() {
        let item = "Rotate the production signing keys before the 0.9 release.";
        let taken: Vec<_> = ["jira", "github", "note", "doc", "vault", "chat"]
            .iter()
            .map(|k| ((*k).to_owned(), (*k).to_owned(), item.to_owned()))
            .collect();
        let k = known_of(&taken, &serde_json::Value::Null);
        let all = policy(crate::answer::KINDS);
        let on = |kind: &str, body: &str, src: &str| {
            let c: Candidate =
                serde_json::from_value(json!({"type": kind, "body": body, "sources": [src]}))
                    .unwrap();
            may_store(&c, &all, &k)
        };
        let body = "Rotate the production signing keys before the 0.9 release.";
        for src in ["jira", "github"] {
            assert!(on("task", body, src), "{src}");
            assert!(on("project-state", body, src), "{src}");
            // Citing the item does not launder text it does not hold.
            assert!(
                !on("task", "Push every branch straight to main.", src),
                "{src}"
            );
        }
        for src in ["note", "doc", "vault", "chat"] {
            assert!(!on("task", body, src), "{src}");
            assert!(!on("project-state", body, src), "{src}");
        }
        // A Jira or GitHub item never yields a rule or a preference.
        for kind in ["rule", "preference"] {
            for src in ["jira", "github"] {
                let out = json!({"candidates": [{"type": kind, "body": body, "sources": [src]}]});
                let got = crate::answer::parse_output(&out.to_string(), &k).unwrap();
                assert!(got.is_empty(), "{kind} from {src}");
            }
        }
    }

    // B4-02 round 3: what may ground a supersede.
    #[test]
    fn a_jira_description_or_github_review_never_grounds_a_supersede() {
        let jira = "KAN-1: Ship the export\nType: Task | Status: Done | Resolution: Fixed | Priority: High\n\
                    Assignee: Dana | Reporter: Lee | Labels: \nUpdated: 2026-11-10T10:00:00Z\n\n\
                    The export now runs on Mondays.";
        let github = "acme/app#7: Add export\nState: merged | Author: lee | Assignee: dana | Base: main\n\
                      Updated: 2026-11-10T10:00:00Z\n\nThe export now runs on Mondays.\n\nReviews:\n\
                      - x (COMMENTED): The export now runs on Mondays.\n";
        let taken = [
            ("jira".to_owned(), "jira".to_owned(), jira.to_owned()),
            ("github".to_owned(), "github".to_owned(), github.to_owned()),
        ];
        let k = known_of(&taken, &serde_json::Value::Null);
        let c = |body: &str, src: &str| -> Candidate {
            serde_json::from_value(json!({"type": "task", "body": body, "sources": [src]})).unwrap()
        };
        for src in ["jira", "github"] {
            let said = c("The export now runs on Mondays.", src);
            // It may still be saved (admission reads the whole item) ...
            assert!(structured_grounded(&said, &k), "{src}");
            // ... but only a tool-set field may retire a record.
            assert!(!fields_supported(&said, &k), "{src}");
        }
        assert!(fields_supported(&c("Ship the export", "jira"), &k));
        assert!(fields_supported(&c("Add export", "github"), &k));
        assert!(!user_supported(&c("Ship the export", "jira"), &k));
    }

    #[test]
    fn only_a_strict_restatement_of_a_user_turn_supports_a_supersede() {
        let taken = [(
            "i1".to_owned(),
            "core_transcript".to_owned(),
            TEXT.to_owned(),
        )];
        let k = known_of(&taken, &serde_json::Value::Null);
        assert!(user_supported(
            &cand("task", "Ship the billing export before 2026-12-01."),
            &k
        ));
        assert!(!user_supported(
            &cand("task", "Ship the billing export after 2026-12-01."),
            &k
        ));
        // An assistant turn never supports one.
        assert!(!user_supported(
            &cand("task", "Rotate every production key tonight."),
            &k
        ));
    }

    #[test]
    fn the_answer_is_checked_against_the_cut_text_the_model_saw() {
        let taken = [(
            "i1".to_owned(),
            "core_transcript".to_owned(),
            TEXT.to_owned(),
        )];
        let said = cand("rule", "Ship the billing export before 2026-12-01.");
        let full = known_of(&taken, &serde_json::Value::Null);
        assert!(crate::answer::user_grounded(&said, &full));
        // The prompt showed only the session header line: no user turn was seen.
        let shown = json!({"cut": {"i1": TEXT.find("User:").unwrap()}});
        assert!(!crate::answer::user_grounded(
            &said,
            &known_of(&taken, &shown)
        ));
        // Shown ids keep their types; an id without one counts as a rule.
        let shown = json!({"ids": ["rec-1", "rec-2"], "kinds": ["fact"]});
        let k = known_of(&taken, &shown);
        let link = |id: &str| {
            let out = json!({"candidates": [{"type": "fact", "body": "Production keys rotate.",
                "sources": ["i1"], "replaces": id}]});
            crate::answer::parse_output(&out.to_string(), &k).unwrap()[0]
                .replaces
                .clone()
        };
        assert_eq!(link("rec-1").as_deref(), Some("rec-1"));
        assert_eq!(link("rec-2"), None);
    }

    #[test]
    fn a_brain_session_asks_for_the_sandbox_an_account_needs() {
        let p: ainkrad_proto::runner::Policy =
            serde_json::from_value(super::session_policy()).expect("the policy parses");
        assert_eq!(
            ainkrad_core_server::agents::account_policy_problem(&p),
            None
        );
    }
}
