//! `brainAiContext` (B7-03): the memory a session is given without asking, at its start and with each
//! prompt. A read op: no model call is made to write it (the local e5 model only scores), and it
//! reads MEMORY ONLY.
//!
//! SECURITY MODEL (read before changing anything here)
//! 1. Memory only: every record comes from the `memory` view (current, accepted, not archived).
//!    No query here names `sources`, so no `sources.text` can leave. Raw sources stay behind
//!    `brainAiEvidence`. The only other text is a room's person-approved instructions (the Overview
//!    field the person edited and approved), the room card and the me card, all built from memory.
//! 2. Contested records never leave: every record query has `contests IS NULL` and no
//!    `conflict`/`contested` tag. The two cards apply the same rule.
//! 3. Isolation: rooms come from `access::visible_rooms` / `room_of` (project link or access list,
//!    inside each room's model policy; a hidden room is the 404 of an unknown one). The me card is
//!    gated by its own per-source-room chain check (`me_card`). Nothing here reads another room.
//! 4. Outside data: the WHOLE bundle is wrapped once in the shared envelope (`untrusted::wrap`, which
//!    defangs markers in every part, cards and instructions included). The response carries no raw
//!    card text, only the wrapped bundle and the ids. How the bundle is DELIVERED is the harness
//!    side (B8): in a system-prompt file or `additionalContext`, never as a `User:` turn; if it
//!    does reach a transcript, the envelope is what the no-echo guard (B5-02) cuts out.
//! 5. Loaded ledger: every record id handed out is written to `brain_session_loaded` (session,
//!    room, record) in the same transaction that audits the call, BEFORE the answer is returned. If
//!    that write fails the call fails and no text leaves (fail closed): the no-echo guard and the
//!    prompt-mode no-repeat rule both depend on it.
//! 6. Audit: `brain.ai.context` (mode, rooms, counts) and, when the me card was served,
//!    `brain.me_card.served` (record ids only). No text is audited.
//! 7. Budget: the body is capped (`Q_START_TOKENS` / `Q_PROMPT_TOKENS`, chars / 4); a caller may only
//!    lower it. `complete: false` says something was cut.
//! 8. Support is counted as distinct cited sources in `record_sources` that are not echoes
//!    (`SUPPORT_SQL`, `echo = 0`), never the raw `support` counter.
//! 9. Rate: each session gets a burst of 10 calls, then one a second (429 past that); a budget of 0
//!    answers empty.

use std::collections::HashSet;

use ainkrad_core::untrusted::wrap;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Query, State};
use axum::{Extension, Json};
use brain_model::merge::DEMOTE_SQL;
use brain_model::semantic::{Q_MEMORY_MARGIN, within_margin};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqlitePool};
use utoipa::{IntoParams, ToSchema};

use crate::ai::{cut, open_all, scope, session_of, stale_cutoff};
use crate::ai_semantic::{WAIT, available, embed_text, record_hash};
use crate::card::{self, CHARS_PER_TOKEN, CONTESTED, LINE_CHARS, one_line};
use crate::semantic::service::similar;
use crate::{Brain, me_card, record};

/// Q (placeholders, B1-04 tunes them): the session-start budget in tokens.
pub const Q_START_TOKENS: usize = 1500;
/// Q: the per-prompt budget and its record count `k`.
pub const Q_PROMPT_TOKENS: usize = 600;
pub const Q_PROMPT_K: usize = 5;
/// Q: records in the start bundle, and how many of them are picked by meaning and by support; the
/// rest are the newest. A third each, the remainder to recency.
pub const Q_START_K: usize = 10;
pub const Q_START_BY_MEANING: usize = Q_START_K / 3;
pub const Q_START_BY_SUPPORT: usize = Q_START_K / 3;
/// Q: the cosine a record must reach to count as matching a prompt. e5 scores unrelated text near
/// 0.82-0.85, so this sits above that; it is a placeholder until B1-04 calibrates it.
pub const Q_PROMPT_FLOOR: f32 = 0.86;
/// Approved instructions are cut to this many tokens in the start bundle.
const INSTRUCTION_TOKENS: usize = 300;
/// Newest records scored by meaning per room.
/// ponytail: newest 500 per room (as `brainAiSearch`); a vector index if rooms outgrow this.
const MAX_SCORED: usize = 500;
const MAX_PROMPT_CHARS: usize = 2000;
/// Records queued for embedding by one call.
const MAX_QUEUE: usize = 100;

const NOT_CONTESTED: &str = "contests IS NULL";
/// Distinct cited sources of a record. Raw `support` is not used (it is being changed to count
/// origins, B5-02), and this reads the same facts directly.
const SUPPORT_SQL: &str = "(SELECT count(DISTINCT rs.source) FROM record_sources rs WHERE rs.record = memory.id AND rs.echo = 0)";

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AiContextQuery {
    /// `start` or `prompt`.
    pub mode: String,
    /// One room; none means the rooms this session may see.
    pub room: Option<String>,
    /// The user's prompt (`prompt` mode, required) or the task in a few words (`start`, optional).
    pub prompt: Option<String>,
    /// Tokens; a caller may lower the cap, never raise it.
    pub budget: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct AiContext {
    pub mode: String,
    /// The bundle, wrapped once as outside data; empty when there is nothing to add. Every record
    /// line starts with its id in brackets.
    pub text: String,
    /// The ids of the records in the bundle.
    pub ids: Vec<String>,
    /// Tokens of the bundle body (characters / 4).
    pub tokens: usize,
    /// False when the budget (or a card's own cap) cut something.
    pub complete: bool,
}

struct Rec {
    room: String,
    id: String,
    body: String,
    hash: String,
    demote: i64,
    support: i64,
    seen: String,
    /// An AI session wrote it (`brainAiPropose`): its line says `origin=ai` (B3-04).
    ai: bool,
}

/// Fetches `memory` rows of one room that may be shown, in `order`, at most `n`.
async fn fetch(
    pool: &SqlitePool,
    room: &str,
    cutoff: &str,
    order: &str,
    n: usize,
) -> Result<Vec<Rec>, sqlx::Error> {
    let sql = format!(
        "SELECT id, body, body_norm, {DEMOTE_SQL} AS demote, {SUPPORT_SQL} AS support, \
                coalesce(last_seen_at, created_at) AS seen, origin = 'ai' AS ai \
         FROM memory WHERE {NOT_CONTESTED} \
           AND NOT EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(tags) THEN tags ELSE '[]' END) WHERE value IN {CONTESTED}) \
         ORDER BY {order} LIMIT {n}"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(cutoff)
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|r| {
            let body: String = r.try_get("body")?;
            let norm: Option<String> = r.try_get("body_norm")?;
            Ok(Rec {
                room: room.to_owned(),
                id: r.try_get("id")?,
                hash: record_hash(norm.as_deref().unwrap_or(&body)),
                demote: r.try_get("demote")?,
                support: r.try_get("support")?,
                seen: r.try_get("seen")?,
                ai: r.try_get("ai")?,
                body,
            })
        })
        .collect()
}

const BY_RECENT: &str = "demote, seen DESC, id";
const BY_SUPPORT: &str = "demote, support DESC, seen DESC, id";
const BY_NEWEST: &str = "created_at DESC, id";

/// The records of `recs` that match `q` by meaning: above the floor, within the margin of the best,
/// best first. `None` when meaning cannot answer now (model off, slow or failed): the caller then
/// adds nothing by meaning.
async fn by_meaning(app: &App, b: &Brain, q: &str, recs: &[Rec]) -> Option<Vec<usize>> {
    if recs.is_empty() || !available(app, b).await {
        return None;
    }
    let qv = b.embed_query(&embed_text(q), WAIT).await?;
    let hashes: Vec<String> = recs.iter().map(|r| r.hash.clone()).collect();
    let have = b.vectors_for(&hashes).await.ok()?;
    // What has no vector yet goes to the worker; this call scores what it has.
    let mut seen = HashSet::new();
    let queue: Vec<(String, String)> = recs
        .iter()
        .filter(|r| !have.contains_key(&r.hash) && seen.insert(r.hash.clone()))
        .take(MAX_QUEUE)
        .map(|r| (r.hash.clone(), embed_text(&r.body)))
        .collect();
    if !queue.is_empty() {
        b.queue_embed(queue);
    }
    let scored: Vec<(String, Vec<f32>)> = recs
        .iter()
        .enumerate()
        .filter_map(|(i, r)| have.get(&r.hash).map(|v| (i.to_string(), v.clone())))
        .collect();
    let mut top = similar(&qv, &scored, scored.len());
    top.retain(|t| t.1 >= Q_PROMPT_FLOOR);
    let keep = within_margin(
        &top.iter().map(|t| t.1).collect::<Vec<_>>(),
        Q_MEMORY_MARGIN,
    );
    top.truncate(keep);
    let mut idx: Vec<usize> = top.iter().filter_map(|t| t.0.parse().ok()).collect();
    // Fresh before stale, each group still best first (stable).
    idx.sort_by_key(|i| recs[*i].demote);
    Some(idx)
}

/// The bundle body under a character cap: whole parts only, in order.
struct Body {
    text: String,
    cap: usize,
    complete: bool,
    /// `(room, record)` of everything in the text.
    at: Vec<(String, String)>,
}

impl Body {
    fn put(&mut self, part: &str, at: &[(String, String)]) -> bool {
        if self.text.chars().count() + part.chars().count() > self.cap {
            self.complete = false;
            return false;
        }
        self.text.push_str(part);
        self.at.extend(at.iter().cloned());
        true
    }
}

/// The session's ids already loaded, for the no-repeat rule.
async fn loaded_ids(app: &App, session: &str) -> Result<HashSet<String>, sqlx::Error> {
    Ok(
        sqlx::query_scalar("SELECT record FROM brain_session_loaded WHERE session = ?")
            .bind(session)
            .fetch_all(&app.pool)
            .await?
            .into_iter()
            .collect(),
    )
}

#[utoipa::path(get, path = "/ai/context", operation_id = "brainAiContext", tag = "brain",
    params(AiContextQuery),
    responses((status = 200, description = "Memory for this session, from memory only (never raw sources, never contested records), wrapped once as outside data, every record line carrying its id. `start`: approved instructions, the room card, the me card and about 10 records. `prompt`: the few records that match the prompt and were not given to this session before; empty is the normal answer. Every record id is recorded as loaded for this session. `complete` is false when a budget cut something.", body = AiContext)))]
pub(crate) async fn context(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Query(q): Query<AiContextQuery>,
) -> ApiResult<AiContext> {
    let session = session_of(&me)?;
    if !b.context_allowed(&session) {
        return Err(crate::code(
            429,
            "rate_limited",
            "too many context calls; wait a second",
        ));
    }
    let start = match q.mode.as_str() {
        "start" => true,
        "prompt" => false,
        _ => return Err(ApiError::bad_request("mode is start or prompt")),
    };
    let prompt = q
        .prompt
        .as_deref()
        .map(|p| cut(p, MAX_PROMPT_CHARS).0)
        .filter(|p| !p.is_empty());
    if !start && prompt.is_none() {
        return Err(ApiError::bad_request("prompt mode needs a prompt"));
    }
    let max = if start {
        Q_START_TOKENS
    } else {
        Q_PROMPT_TOKENS
    };
    if q.budget == Some(0) {
        return Ok(Json(AiContext {
            mode: q.mode,
            text: String::new(),
            ids: vec![],
            tokens: 0,
            complete: false,
        }));
    }
    let tokens = (q.budget.map_or(max, |n| n as usize)).clamp(50, max);
    let named = q.room.is_some();
    let (rooms, rooms_cut) = scope(&app, &session, q.room.as_deref()).await?;
    let solo = rooms.len() == 1;
    let (open, closed) = open_all(&app, &b, rooms, named).await?;

    let mut body = Body {
        text: String::new(),
        cap: tokens * CHARS_PER_TOKEN,
        complete: true,
        at: vec![],
    };
    let mut used: HashSet<String> = HashSet::new();
    let mut me_ids: Vec<String> = vec![];
    let now = app.clock.now();

    // Candidate records of every open room.
    let mut newest: Vec<Rec> = vec![];
    let mut by_support: Vec<Rec> = vec![];
    let mut by_recent: Vec<Rec> = vec![];
    let mut capped = false;
    let result: Result<(), ApiError> = async {
        if start && solo && open.len() == 1 {
            let (v, a) = &open[0];
            let ins: Option<String> = sqlx::query_scalar(
                "SELECT instructions FROM room_overview \
                 WHERE id = 1 AND instructions_approved_at IS NOT NULL AND instructions IS NOT NULL",
            )
            .fetch_optional(a.pool())
            .await?;
            if let Some(t) = ins.filter(|t| !t.trim().is_empty()) {
                let (t, was_cut) = cut(&t, INSTRUCTION_TOKENS * CHARS_PER_TOKEN);
                body.complete &= !was_cut;
                body.put(&format!("Instructions:\n{t}\n"), &[]);
            }
            let c = card::build(&app, a.pool(), &v.id, &now).await?;
            body.complete &= c.complete;
            let at: Vec<(String, String)> = c.ids.iter().map(|i| (v.id.clone(), i.clone())).collect();
            body.put(&c.text, &at);
        }
        if start {
            if let Some((c, at)) = me_card::build_located(&app, &b, &session).await {
                body.complete &= c.complete;
                if body.put(&c.text, &at) {
                    me_ids = c.ids.clone();
                }
            }
        }
        used.extend(body.at.iter().map(|x| x.1.clone()));
        if !start {
            used.extend(loaded_ids(&app, &session).await?);
        }
        let k = if start { Q_START_K } else { Q_PROMPT_K };
        for (v, a) in &open {
            let cutoff = stale_cutoff(&app, &v.id).await;
            let mut all = fetch(a.pool(), &v.id, &cutoff, BY_NEWEST, MAX_SCORED + 1).await?;
            if all.len() > MAX_SCORED {
                all.truncate(MAX_SCORED);
                capped = true;
            }
            newest.extend(all);
            if start {
                // Room by room, then merged below: the best `k` of each list are enough.
                by_support.extend(fetch(a.pool(), &v.id, &cutoff, BY_SUPPORT, k).await?);
                by_recent.extend(fetch(a.pool(), &v.id, &cutoff, BY_RECENT, k).await?);
            }
        }
        Ok(())
    }
    .await;
    for (_, a) in &open {
        a.pool().close().await;
    }
    result?;
    by_support.sort_by(|a, b| (a.demote, b.support, &b.seen).cmp(&(b.demote, a.support, &a.seen)));
    by_recent.sort_by(|a, b| (a.demote, &b.seen).cmp(&(b.demote, &a.seen)));
    body.complete &= !capped && !rooms_cut && closed == 0;

    // Choose the records: by meaning, by support, then the newest for the rest of the quota.
    let k = if start { Q_START_K } else { Q_PROMPT_K };
    let meaning = match &prompt {
        Some(p) => by_meaning(&app, &b, p, &newest).await,
        None => None,
    };
    let mut seen: HashSet<&str> = HashSet::new();
    let mut order: Vec<&Rec> = vec![];
    for i in meaning.iter().flatten() {
        let n = if start { Q_START_BY_MEANING } else { k };
        let r = &newest[*i];
        if order.len() < n && !used.contains(&r.id) && seen.insert(&r.id) {
            order.push(r);
        }
    }
    if start {
        let from = order.len();
        for r in &by_support {
            if order.len() - from < Q_START_BY_SUPPORT
                && !used.contains(&r.id)
                && seen.insert(&r.id)
            {
                order.push(r);
            }
        }
        for r in &by_recent {
            if order.len() < k && !used.contains(&r.id) && seen.insert(&r.id) {
                order.push(r);
            }
        }
    }

    let mut first = true;
    for r in order {
        let origin = if r.ai { ", origin=ai" } else { "" };
        let line = format!("- [{}{origin}] {}\n", r.id, one_line(&r.body, LINE_CHARS));
        let part = if first {
            format!("Memory:\n{line}")
        } else {
            line
        };
        if !body.put(&part, &[(r.room.clone(), r.id.clone())]) {
            break;
        }
        first = false;
    }

    if body.at.is_empty() && body.text.is_empty() {
        return Ok(Json(AiContext {
            mode: q.mode,
            text: String::new(),
            ids: vec![],
            tokens: 0,
            complete: body.complete,
        }));
    }

    // The ledger and the audit first; no text leaves if they fail.
    let mut tx = begin_write(&app.pool).await?;
    for (room, id) in &body.at {
        crate::loaded::record_in(&mut tx, &session, room, std::slice::from_ref(id)).await?;
    }
    let mut rooms_used: Vec<&str> = body.at.iter().map(|x| x.0.as_str()).collect();
    rooms_used.sort_unstable();
    rooms_used.dedup();
    record(
        &mut tx,
        "brain.ai.context",
        json!({"session": session, "mode": q.mode, "rooms": rooms_used, "records": body.at.len(), "complete": body.complete}),
        None,
    )
    .await?;
    if !me_ids.is_empty() {
        record(
            &mut tx,
            "brain.me_card.served",
            json!({"session": session, "records": me_ids}),
            None,
        )
        .await?;
    }
    tx.commit().await?;

    let n = body.text.chars().count() / CHARS_PER_TOKEN;
    let mut seen_ids = HashSet::new();
    let ids: Vec<String> = body
        .at
        .iter()
        .filter(|x| seen_ids.insert(x.1.clone()))
        .map(|x| x.1.clone())
        .collect();
    Ok(Json(AiContext {
        text: wrap(&format!("Brain memory | {}", q.mode), &body.text),
        mode: q.mode,
        ids,
        tokens: n,
        complete: body.complete,
    }))
}
