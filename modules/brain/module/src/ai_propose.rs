//! `brainAiPropose` (B3-04): an AI session's proposed fact goes through the SAME save pipeline as a
//! distilled one (grounding, admission, merge, save), lands as a change set of kind `ai` that a
//! person can Undo, and is never queued for approval unless the room's policy says so.
//!
//! SECURITY MODEL (Brain v2, B3-04; read before changing anything here)
//!
//! 1. An agent is an untrusted writer. Its text is outside data from the moment it arrives (the
//!    body is redacted, stored as-is and only ever read back inside the untrusted envelope).
//! 2. A proposal can never be a `rule` or `preference`: those come only from a user turn, through
//!    distil's grounding. Both are the same 400 as any other invalid proposal (no oracle).
//! 3. Citations must be sources THIS session read through `brainAiEvidence` in THIS room (the
//!    `brain.ai.evidence` audit rows) and that still exist. Anything else is that same 400.
//! 4. Grounding is against the cited sources' text, never the proposal's own text. A proposal that
//!    cites nothing, or whose words are not in what it cites, is dropped (logged, not saved).
//!    A task or project-state needs the same user-turn (or Jira/GitHub) grounding as in distil.
//! 5. The agent supplies no `durable`/`confidence`: those would let it raise its own score.
//! 6. The border band is dropped, not judged: this route is synchronous and a judge call is a
//!    session of its own. Stricter than a distil, never looser.
//! 7. `replaces` follows the contested rule: the new fact is saved and the target stays in force,
//!    linked as contested (`ai.contested` in the room audit). It NEVER supersedes, so the
//!    candidate's own `replaces` is cleared before it reaches merge. The target must be a fact in
//!    memory, else the same 400.
//! 8. Rate cap: 20 proposals per session per hour (dropped ones count), 429 past it.
//! 9. Every attempt writes a control audit row (`brain.ai.proposed`: ids, type, outcome, no text)
//!    and a room audit row; a dropped body is kept only under the `bodies` key of `admit.dropped`,
//!    which the 30-day purge clears.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::ai::{MAX_BODY, PROPOSED, room_of, session_of};
use crate::answer::{Candidate, KINDS};
use crate::distil::{DistilledBy, known_of, may_store};
use crate::inbox::open_room;
use crate::{Brain, code, judge, merge, policy, record, save};

/// Proposals one session may make in an hour.
/// ponytail: counted from the control audit, so two calls racing can pass the cap by one or two.
const PER_HOUR: i64 = 20;
const INVALID: &str = "a known type other than rule or preference, a body of 1 to 2000 characters, at most 8 tags of 1 to 40, at most 20 sources that this session read with brainAiEvidence in this room, and a replaces that is a fact of this room";

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Propose {
    /// `decision`, `fact`, `project-state`, `task` or `summary`. Never `rule` or `preference`.
    #[serde(rename = "type")]
    #[schema(rename = "type")]
    pub kind: String,
    /// One self-contained statement, 1 to 2000 characters.
    pub body: String,
    /// At most 8 tags of 1 to 40 characters.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Item ids of sources this session read through `brainAiEvidence` (at most 20). A proposal
    /// that cites none is dropped.
    #[serde(default)]
    pub sources: Vec<String>,
    /// A memory record this one disagrees with. It never replaces it: both stay, linked as contested.
    #[serde(default)]
    pub replaces: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Proposed {
    pub room: String,
    /// The new record's id when `status` is `saved` or `candidate`; empty otherwise.
    pub id: String,
    /// `saved` (in memory, with Undo for the person), `candidate` (the room's policy asks for a
    /// review), `reinforced` (memory already held it) or `dropped` (it did not pass admission).
    pub status: String,
    /// The first reason code of a drop.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub reason: Option<String>,
    /// True when memory already held the statement (`status` is `reinforced`).
    pub duplicate: bool,
}

struct Outcome {
    status: &'static str,
    id: String,
    reason: Option<String>,
    /// Candidates waiting in the Inbox, when this one is one.
    waiting: Option<i64>,
}

#[utoipa::path(post, path = "/ai/rooms/{room}/propose", operation_id = "brainAiPropose", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = Propose,
    responses((status = 200, description = "The proposal goes through the same grounding, admission, merge and save steps as a distilled fact and is saved with Undo (`saved`), queued when the room asks for a review (`candidate`), merged into a fact memory already holds (`reinforced`) or `dropped`. Never a rule or preference; citations must be sources this session read; 20 per session per hour", body = Proposed)))]
pub(crate) async fn propose(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
    Json(req): Json<Propose>,
) -> ApiResult<Proposed> {
    let session = session_of(&me)?;
    let body = Redactor::new().text(req.body.trim());
    let ok = KINDS.contains(&req.kind.as_str())
        && !matches!(req.kind.as_str(), "rule" | "preference")
        && (1..=MAX_BODY).contains(&body.chars().count())
        && req.tags.len() <= 8
        && req
            .tags
            .iter()
            .all(|t| (1..=40).contains(&t.chars().count()))
        && req.sources.len() <= 20;
    if !ok {
        return Err(ApiError::bad_request(INVALID));
    }
    let v = room_of(&app, &session, &room).await?;
    let used: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'brain.ai.proposed' \
         AND json_extract(details, '$.session') = ? \
         AND at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 hour')",
    )
    .bind(&session)
    .fetch_one(&app.pool)
    .await?;
    if used >= PER_HOUR {
        return Err(code(
            429,
            "too_many_proposals",
            "this session proposed enough in the last hour",
        ));
    }
    // What this session read in this room: the only sources it may cite.
    let seen: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT json_extract(details, '$.source') FROM audit_events \
         WHERE action = 'brain.ai.evidence' AND json_extract(details, '$.session') = ? \
         AND json_extract(details, '$.room') = ? AND json_extract(details, '$.source') IS NOT NULL",
    )
    .bind(&session)
    .bind(&v.id)
    .fetch_all(&app.pool)
    .await?;
    if req.sources.iter().any(|s| !seen.contains(s)) {
        return Err(ApiError::bad_request(INVALID));
    }
    let a = open_room(&app, &b, &v.id).await?;
    // The room's file closes on every path: a pool left open holds a rolled-back read.
    let done = land(&app, &b, &v.id, a.pool(), &session, &req, &body).await;
    a.pool().close().await;
    let o = done?;
    // Ids, the type and the outcome only (Q-15); the origin is the session's, set by the dispatcher.
    let mut ctl = begin_write(&app.pool).await?;
    record(
        &mut ctl,
        "brain.ai.proposed",
        json!({"room": v.id, "record": o.id, "session": session, "type": req.kind,
            "outcome": o.status, "reason": o.reason,
            "project": ainkrad_core_server::ops_catalog::session_project(&app.pool, &session).await}),
        o.waiting.map(|w| {
            (
                "brain.inbox",
                json!({"room": v.id, "op": "proposed", "waiting": w}),
            )
        }),
    )
    .await?;
    ctl.commit().await?;
    Ok(Json(Proposed {
        room: v.id,
        duplicate: o.status == "reinforced",
        id: o.id,
        status: o.status.to_owned(),
        reason: o.reason,
    }))
}

/// Runs the proposal through the pipeline in the open room.
async fn land(
    app: &App,
    b: &Brain,
    room: &str,
    pool: &sqlx::SqlitePool,
    session: &str,
    req: &Propose,
    body: &str,
) -> Result<Outcome, ApiError> {
    let mut sources: Vec<String> = vec![];
    let mut taken: Vec<(String, String, String)> = vec![];
    for s in &req.sources {
        if sources.contains(s) {
            continue;
        }
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT source_kind, text FROM sources WHERE item_id = ?")
                .bind(s)
                .fetch_optional(pool)
                .await?;
        // Read through evidence once, gone since (purged): the same 400.
        let (kind, text) = row.ok_or_else(|| ApiError::bad_request(INVALID))?;
        taken.push((s.clone(), kind, text));
        sources.push(s.clone());
    }
    if let Some(target) = &req.replaces {
        let known: i64 = sqlx::query_scalar("SELECT count(*) FROM memory WHERE id = ?")
            .bind(target)
            .fetch_one(pool)
            .await?;
        if known == 0 {
            return Err(ApiError::bad_request(INVALID));
        }
    }
    let now = app.clock.now();
    let marker = format!("{PROPOSED}{session}");
    let p = policy::load(app, room).await?;
    // `replaces` is NOT carried into the candidate: merge must never see it (it would supersede).
    let c = Candidate {
        kind: req.kind.clone(),
        body: body.to_owned(),
        tags: req.tags.clone(),
        sources,
        same_as: None,
        replaces: None,
        durable: None,
        confidence: None,
    };
    let shown = json!({});
    let known = known_of(&taken, &shown);
    let mut dropped = vec![];
    let grounded = if may_store(&c, &p, &known) {
        vec![c]
    } else {
        dropped.push(judge::dropped_of(
            &c,
            vec!["not_grounded".to_owned()],
            0.0,
            "not_grounded",
        ));
        vec![]
    };
    let staged = judge::stage(grounded, &judge::cited_of(&taken, &shown), &mut dropped);
    // No judge call here (security model 6): the border band is dropped, never guessed.
    let (out, dropped) = judge::resolve(
        staged.keep,
        staged.border,
        dropped,
        Err("a direct proposal has no judge".to_owned()),
    );
    let prep = merge::prepare(app, b, pool, &[body.to_owned()]).await;
    let saved = save::store_candidates(
        pool,
        &marker,
        &out,
        &dropped,
        &p,
        &DistilledBy::default(),
        &now,
        &prep,
        true,
    )
    .await?;
    let mut o = Outcome {
        status: "dropped",
        id: String::new(),
        reason: dropped.first().and_then(|d| d.reasons.first().cloned()),
        waiting: None,
    };
    if saved.saved == 1 {
        o.id = sqlx::query_scalar(
            "SELECT id FROM records WHERE distil = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(&marker)
        .fetch_one(pool)
        .await?;
        o.status = if saved.accepted == 1 {
            "saved"
        } else {
            "candidate"
        };
        o.waiting = if saved.accepted == 1 {
            None
        } else {
            Some(
                sqlx::query_scalar("SELECT count(*) FROM records WHERE status = 'candidate'")
                    .fetch_one(pool)
                    .await?,
            )
        };
        if saved.accepted == 1 {
            // Off the request path, as distil does it: the vector of what just entered memory.
            let rows: Vec<(Option<String>, String)> =
                sqlx::query_as("SELECT body_norm, body FROM memory WHERE id = ?")
                    .bind(&o.id)
                    .fetch_all(pool)
                    .await?;
            b.queue_record_vectors(&rows);
        }
        if let Some(target) = &req.replaces {
            audit(pool, "ai.contested", json!({"record": o.id, "target": target}), &now).await?;
        }
    } else if saved.reinforced == 1 {
        o.status = "reinforced";
        o.reason = None;
    }
    audit(
        pool,
        "ai.proposed",
        json!({"session": session, "outcome": o.status, "record": o.id}),
        &now,
    )
    .await?;
    Ok(o)
}

async fn audit(
    pool: &sqlx::SqlitePool,
    action: &str,
    detail: serde_json::Value,
    now: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES (?, ?, ?)")
        .bind(action)
        .bind(detail.to_string())
        .bind(now)
        .execute(pool)
        .await
        .map(drop)
}
