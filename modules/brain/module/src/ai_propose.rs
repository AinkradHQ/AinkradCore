//! `brainAiPropose` (B3-04): an AI session's proposed fact goes through the SAME save pipeline as a
//! distilled one (grounding, admission, merge, save) and lands as a change set of kind `ai` that a
//! person can Undo. Auto-save only: a proposal is saved or dropped, never queued for review.
//!
//! SECURITY MODEL (Brain v2, B3-04 and its review; read before changing anything here)
//!
//! 1. An agent is an untrusted writer. Its text is outside data from the moment it arrives (the
//!    body is redacted, stored as-is and only ever read back inside the untrusted envelope, whose
//!    label says `origin=ai` on every read surface).
//! 2. A proposal can never be a `rule` or `preference`: those come only from a user turn, through
//!    distil's grounding. Both are the same 400 as any other invalid proposal (no oracle).
//! 3. Citations must be sources THIS session read through `brainAiEvidence` in THIS room (the
//!    `brain.ai.evidence` audit rows). Anything else is that same 400. The evidence row keeps the
//!    hash of the snippet the session read; a source whose snippet hashes differently now (edited,
//!    re-imported, compacted) is dropped (`source_changed`), so nothing written after the read can
//!    be laundered in.
//! 4. Grounding is against what the session saw (the `EVIDENCE_CHARS` cut), never the proposal's
//!    own text and never the full source. Only USER turns of a transcript, or a non-transcript
//!    source whose last editor is a person (`sources.author_kind`; a Lore note last edited by an AI
//!    session is an `agent` source), can ground; assistant turns never do. EVERY
//!    content stem of the body (negation and order words included) must be in one clause of ONE
//!    such block of ONE cited source, and that clause must carry exactly the body's set of negation
//!    words (`Grounds::supports`, B4-02's strict rule). Anything else is dropped (`not_grounded`).
//! 5. Kinds: `fact` and `summary` may be saved; a `decision` only when it grounds in a user turn.
//!    `task` and `project-state` are dropped (`kind_not_saved`) until Jira/GitHub grounding checks
//!    the reporter (#348 follow-up). The agent supplies no `durable`/`confidence`.
//! 6. `replaces` is dropped (`contests_memory`): an AI can never retire or contest a fact.
//! 7. The border band is dropped, not judged: this route is synchronous and a judge call is a
//!    session of its own. A proposal the room would not auto-save is dropped (`not_auto_saved`).
//! 8. An AI session reinforces one record at most once (`already_reinforced`), so it cannot pump a
//!    fact's support by repeating it.
//! 9. Rate caps: 20 proposals per session and 60 per room per hour (dropped ones count), 429 past
//!    either. The slot is reserved (count + `brain.ai.proposed` row) in ONE write transaction before
//!    any work, so racing calls cannot pass the cap; `brain.ai.outcome` records how it ended.
//! 10. Audit rows hold ids, the type and the outcome, never text; a dropped body is kept only under
//!     the `bodies` key of `admit.dropped`, which the 30-day purge clears.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::redact::Redactor;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::admit::Grounds;
use brain_model::merge::{Decision, body_norm};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::ai::{EVIDENCE_CHARS, MAX_BODY, PROPOSED, cut, room_of, session_of, snippet_hash};
use crate::answer::{Candidate, KINDS};
use crate::answer_turns::{Author, is_transcript, kind_of, split};
use crate::distil::{DistilledBy, auto_ok};
use crate::{Brain, code, judge, merge, policy, rand_id, record, save};

/// Proposals one session may make in an hour.
const PER_HOUR: i64 = 20;
/// Proposals all sessions together may make in one room in an hour.
const ROOM_PER_HOUR: i64 = 60;
/// The kinds an AI proposal may save (a `decision` only from a user turn).
const AI_KINDS: &[&str] = &["fact", "summary", "decision"];
const INVALID: &str = "a known type other than rule or preference, a body of 1 to 2000 characters, at most 8 tags of 1 to 40, and at most 20 sources that this session read with brainAiEvidence in this room";

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Propose {
    /// `fact` or `summary`; a `decision` is saved only when a user turn says it. `task` and
    /// `project-state` are dropped for now. Never `rule` or `preference`.
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
    /// A memory record this one disagrees with. An AI may not contest memory: a proposal that sets
    /// it is dropped (`contests_memory`).
    #[serde(default)]
    pub replaces: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct Proposed {
    pub room: String,
    /// The new record's id when `status` is `saved`; empty otherwise.
    pub id: String,
    /// `saved` (in memory, with Undo for the person), `reinforced` (memory already held it) or
    /// `dropped` (it did not pass the checks; nothing is queued).
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
}

#[utoipa::path(post, path = "/ai/rooms/{room}/propose", operation_id = "brainAiPropose", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = Propose,
    responses((status = 200, description = "The proposal goes through the same grounding, admission, merge and save steps as a distilled fact and is saved with Undo (`saved`), merged into a fact memory already holds (`reinforced`) or `dropped`; never queued. Only a fact, a summary, or a decision a user turn says; never a rule or preference, never a replaces. It must be grounded in a user turn or a person's document this session read, unchanged since; 20 per session and 60 per room per hour", body = Proposed)))]
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
    // What this session read in this room, with the hash of what it saw: the only sources it may cite.
    let seen: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT json_extract(details, '$.source'), json_extract(details, '$.hash') FROM audit_events \
         WHERE action = 'brain.ai.evidence' AND json_extract(details, '$.session') = ? \
         AND json_extract(details, '$.room') = ? AND json_extract(details, '$.source') IS NOT NULL",
    )
    .bind(&session)
    .bind(&v.id)
    .fetch_all(&app.pool)
    .await?;
    if req
        .sources
        .iter()
        .any(|s| !seen.iter().any(|(x, _)| x == s))
    {
        return Err(ApiError::bad_request(INVALID));
    }
    let proposal = rand_id("aip-");
    reserve(&app, &v.id, &session, &proposal, &req.kind).await?;
    let a = crate::inbox::open_room(&app, &b, &v.id).await?;
    // The room's file closes on every path: a pool left open holds a rolled-back read.
    let done = land(&app, &b, &v.id, a.pool(), &session, &req, &body, &seen).await;
    a.pool().close().await;
    let o = done?;
    // Ids, the outcome and the reason only (Q-15).
    let mut ctl = begin_write(&app.pool).await?;
    record(
        &mut ctl,
        "brain.ai.outcome",
        json!({"proposal": proposal, "room": v.id, "record": o.id, "session": session,
            "outcome": o.status, "reason": o.reason}),
        None,
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

/// Takes one slot of the hourly caps: both counts and the `brain.ai.proposed` row in ONE write
/// transaction, so two calls racing cannot both take the last slot. A slot is spent whatever the
/// proposal's fate.
async fn reserve(
    app: &App,
    room: &str,
    session: &str,
    proposal: &str,
    kind: &str,
) -> Result<(), ApiError> {
    let mut ctl = begin_write(&app.pool).await?;
    let (mine, here): (i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(json_extract(details, '$.session') = ?1), 0), \
                coalesce(sum(json_extract(details, '$.room') = ?2), 0) \
         FROM audit_events WHERE action = 'brain.ai.proposed' \
         AND at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 hour')",
    )
    .bind(session)
    .bind(room)
    .fetch_one(&mut *ctl)
    .await?;
    if mine >= PER_HOUR || here >= ROOM_PER_HOUR {
        ctl.rollback().await?;
        return Err(code(
            429,
            "too_many_proposals",
            if mine >= PER_HOUR {
                "this session proposed enough in the last hour"
            } else {
                "this room took enough proposals in the last hour"
            },
        ));
    }
    let project = ainkrad_core_server::ops_catalog::session_project(&app.pool, session).await;
    record(
        &mut ctl,
        "brain.ai.proposed",
        json!({"proposal": proposal, "room": room, "session": session, "type": kind,
            "project": project}),
        None,
    )
    .await?;
    ctl.commit().await?;
    Ok(())
}

/// Runs the proposal through the pipeline in the open room.
#[allow(clippy::too_many_arguments)]
async fn land(
    app: &App,
    b: &Brain,
    room: &str,
    pool: &sqlx::SqlitePool,
    session: &str,
    req: &Propose,
    body: &str,
    seen: &[(String, Option<String>)],
) -> Result<Outcome, ApiError> {
    let mut sources: Vec<String> = vec![];
    // (item id, kind, the cut the session saw): what admission scores against.
    let mut taken: Vec<(String, String, String)> = vec![];
    // The blocks that may ground: (a user turn, its text).
    let mut blocks: Vec<(bool, String)> = vec![];
    let mut changed = false;
    for s in &req.sources {
        if sources.contains(s) {
            continue;
        }
        let row: Option<(String, String, String, Option<String>)> = sqlx::query_as(
            "SELECT source_kind, text, author_kind, compacted_at FROM sources WHERE item_id = ?",
        )
        .bind(s)
        .fetch_optional(pool)
        .await?;
        // Read through evidence once, gone since (purged): the same 400.
        let (kind, text, author, compacted) = row.ok_or_else(|| ApiError::bad_request(INVALID))?;
        let hash = snippet_hash(&text);
        changed |= compacted.is_some()
            || !seen
                .iter()
                .any(|(x, h)| x == s && h.as_deref() == Some(hash.as_str()));
        let (snip, _) = cut(&text, EVIDENCE_CHARS);
        let k = kind_of(&kind);
        if is_transcript(k) {
            blocks.extend(
                split(&snip, k)
                    .into_iter()
                    .filter(|(a, _)| *a == Author::User)
                    .map(|(_, t)| (true, t)),
            );
        } else if author == "person" {
            blocks.push((false, snip.clone()));
        }
        taken.push((s.clone(), kind, snip));
        sources.push(s.clone());
    }
    let now = app.clock.now();
    let marker = format!("{PROPOSED}{session}");
    let p = policy::load(app, room).await?;
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
    let user_only = c.kind == "decision";
    let usable = blocks
        .iter()
        .filter(|(user, _)| *user || !user_only)
        .map(|(_, t)| t.as_str());
    let refused = if req.replaces.is_some() {
        Some("contests_memory")
    } else if !AI_KINDS.contains(&c.kind.as_str()) {
        Some("kind_not_saved")
    } else if changed {
        Some("source_changed")
    } else if !grounded_in_one(body, usable) {
        Some("not_grounded")
    } else if !auto_ok(&c, &p) {
        Some("not_auto_saved")
    } else {
        None
    };
    let mut dropped = vec![];
    let grounded = match refused {
        Some(why) => {
            dropped.push(judge::dropped_of(&c, vec![why.to_owned()], 0.0, "ai"));
            vec![]
        }
        None => vec![c],
    };
    let staged = judge::stage(grounded, &judge::cited_of(&taken, &json!({})), &mut dropped);
    // No judge call here (security model 7): the border band is dropped, never guessed.
    let (mut out, mut dropped) = judge::resolve(
        staged.keep,
        staged.border,
        dropped,
        Err("a direct proposal has no judge".to_owned()),
    );
    let prep = merge::prepare(app, b, pool, &[body.to_owned()]).await;
    // Security model 8. ponytail: checked before the save's own transaction, so two identical
    // proposals of one session racing may both reinforce; one write lock per room if that matters.
    let mut target = None;
    if let Some(c) = out.first() {
        let mut conn = pool.acquire().await?;
        let d = merge::Memory::load(&mut conn, &prep).await?.decide(
            &c.kind,
            &body_norm(body),
            prep.candidate(0),
            None,
        );
        drop(conn);
        if let Decision::Reinforce { id, .. } = d {
            let again: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM room_audit WHERE action = 'ai.proposed' \
                 AND json_extract(detail, '$.session') = ? \
                 AND json_extract(detail, '$.outcome') = 'reinforced' \
                 AND json_extract(detail, '$.target') = ?",
            )
            .bind(session)
            .bind(&id)
            .fetch_one(pool)
            .await?;
            if again > 0 {
                let c = out.remove(0);
                dropped.push(judge::dropped_of(
                    &c,
                    vec!["already_reinforced".to_owned()],
                    0.0,
                    "ai",
                ));
            } else {
                target = Some(id);
            }
        }
    }
    let saved = save::store_candidates(
        pool,
        &marker,
        &out,
        &dropped,
        &p,
        &DistilledBy::default(),
        &now,
        &prep,
        // No grounding: an AI save can never supersede (and `replaces` is dropped before this).
        &[],
        // What the Brain gave sessions in this room: a session that was shown a record and proposes
        // it back is an echo, never a new origin.
        &crate::loaded::of_room(app, room).await?,
        true,
    )
    .await?;
    let mut o = Outcome {
        status: "dropped",
        id: String::new(),
        reason: dropped.first().and_then(|d| d.reasons.first().cloned()),
    };
    if saved.accepted == 1 {
        o.id = sqlx::query_scalar(
            "SELECT id FROM records WHERE distil = ? ORDER BY rowid DESC LIMIT 1",
        )
        .bind(&marker)
        .fetch_one(pool)
        .await?;
        o.status = "saved";
        // Off the request path, as distil does it: the vector of what just entered memory.
        let rows: Vec<(Option<String>, String)> =
            sqlx::query_as("SELECT body_norm, body FROM memory WHERE id = ?")
                .bind(&o.id)
                .fetch_all(pool)
                .await?;
        b.queue_record_vectors(&rows);
        target = None;
    } else if saved.reinforced == 1 {
        o.status = "reinforced";
        o.reason = None;
    } else {
        target = None;
    }
    audit(
        pool,
        "ai.proposed",
        json!({"session": session, "outcome": o.status, "record": o.id, "target": target}),
        &now,
    )
    .await?;
    Ok(o)
}

/// Security model 4: the body is grounded in ONE block (never the union of several) under B4-02's
/// strict rule (`Grounds::supports`, #351): every content stem of the body, negation and order
/// words included, is in one clause of that block, and that clause has exactly the body's set of
/// negation words. Stricter than a `Q_USER_GROUNDING` share, which cannot tell "only after" from
/// "before" or "never" from "not".
pub(crate) fn grounded_in_one<'a>(body: &str, blocks: impl IntoIterator<Item = &'a str>) -> bool {
    blocks.into_iter().any(|b| Grounds::of(b).supports(body))
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

#[cfg(test)]
mod tests {
    use super::grounded_in_one;

    #[test]
    fn one_block_must_hold_the_body_never_the_union_of_two() {
        let a = "migrations always run";
        let b = "with the --locked flag in billing";
        let body = "Billing migrations always run with the --locked flag.";
        assert!(!grounded_in_one(body, [a, b]));
        assert!(grounded_in_one(body, [format!("{a} {b}").as_str()]));
    }

    #[test]
    fn polarity_must_match_as_a_set_of_negation_words() {
        let turn = "No, don't deploy on Fridays";
        assert!(!grounded_in_one("deploy on Fridays", [turn]));
        assert!(grounded_in_one(
            "Don't deploy on Fridays",
            ["don't deploy on Fridays"]
        ));
        // Sets, not parity: "never" is not "not".
        assert!(!grounded_in_one(
            "Never deploy on Fridays",
            ["don't deploy on Fridays"]
        ));
        assert!(!grounded_in_one(
            "ننشر يوم الجمعة",
            ["لا، لا ننشر يوم الجمعة"]
        ));
    }

    #[test]
    fn order_words_are_content() {
        let turn = "deploy only after tests pass";
        assert!(!grounded_in_one("deploy before tests pass", [turn]));
        assert!(grounded_in_one("Deploy only after tests pass.", [turn]));
    }

    #[test]
    fn too_few_words_in_the_block_is_not_grounded() {
        let turn = "we talked about the billing service yesterday";
        assert!(!grounded_in_one(
            "The billing service retries payments three times with exponential backoff.",
            [turn]
        ));
        assert!(!grounded_in_one("anything at all", std::iter::empty()));
    }
}
