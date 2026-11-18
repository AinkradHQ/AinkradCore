//! Mid-session checkpoints (Brain v2, B5-02): a running AI session's new turns are distilled
//! before it ends, by the Core on its own and when a hook asks (`brainAiCheckpoint`).
//!
//! Security model (this is a cost surface and a session-text surface):
//! - A checkpoint is only a trigger. It collects through the same path as a session end
//!   (`sync_core_as`: no-echo guard, cursor, routing) and queues through `auto_distil::queue`, so
//!   the room cap, the global cap, the one-open-distil rule and the policy chain all apply. Nothing
//!   here can start a distil outside them.
//! - `brainAiCheckpoint` takes no arguments. It names no room and no text: it can only ask for a
//!   checkpoint of the calling session itself (the session comes from the dispatcher's caller, never
//!   from input), and only while that session is live and not Brain-owned. It does no work: it
//!   marks the session, and the 30 s auto-distil tick acts on it.
//! - Rate: one request per session per 10 minutes, one run per session per 10 minutes, at most
//!   `MAX_PER_SESSION` checkpoint distils per session (counted from `brain_distils`, so a restart
//!   cannot reset it), `MAX_PER_TICK` sessions per tick, `MAX_TRACKED` sessions remembered.
//! - Only whole turns are taken: nothing after the last answer, and the session is debounced
//!   (`IDLE_SECS` waiting) unless a hook asked. The cursor is per session, so session end takes
//!   only the rest and the two never share source text.
//! - Brain-owned and claimed sessions are never checkpointed (as for a session end).
//!
//! ponytail: the request map and run times live in memory; a restart forgets them and the next
//! tick simply looks again. Persist only if restarts become frequent.

use std::collections::HashMap;
use std::sync::PoisonError;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::{agents, begin_write};
use axum::extract::State;
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;

use crate::ai::session_of;
use crate::auto_distil::{IDLE_SECS, queue};
use crate::sync::sync_core_as;
use crate::{Brain, MODULE, record};

/// About 8k tokens of new User/Assistant text (a Q value).
const MIN_NEW_CHARS: usize = 32_000;
/// A hook asked: about 500 tokens is enough to be worth a run.
const MIN_ASKED_CHARS: usize = 2_000;
/// Between two requests, and between two runs, of one session.
const EVERY_SECS: i64 = 600;
const MAX_PER_SESSION: i64 = 6;
const MAX_PER_TICK: usize = 5;
const MAX_TRACKED: usize = 256;

/// What the Core remembers of one session's checkpoints.
#[derive(Default)]
pub(crate) struct Ckpt {
    requested: Option<i64>,
    pending: bool,
    ran: Option<i64>,
    /// The session's `last_seq` at the last look: unchanged means nothing to read.
    seen_seq: i64,
}

/// Records a request unless the session asked in the last 10 minutes or too many are tracked.
fn ask(m: &mut HashMap<String, Ckpt>, session: &str, now: i64) -> Result<(), &'static str> {
    if m.len() >= MAX_TRACKED && !m.contains_key(session) {
        let recent = |t: Option<i64>| t.is_some_and(|t| now - t < EVERY_SECS);
        m.retain(|_, c| c.pending || recent(c.requested) || recent(c.ran));
        if m.len() >= MAX_TRACKED {
            return Err("busy");
        }
    }
    let c = m.entry(session.to_owned()).or_default();
    if c.requested.is_some_and(|t| now - t < EVERY_SECS) {
        return Err("rate_limited");
    }
    c.requested = Some(now);
    c.pending = true;
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct CheckpointAsked {
    /// True when the request was taken. The Core acts on it at its next tick, under its caps;
    /// nothing is distilled in this call.
    pub requested: bool,
    /// Why not: `rate_limited`, `busy` or `not_eligible`.
    pub reason: Option<String>,
}

#[utoipa::path(post, path = "/ai/checkpoint", operation_id = "brainAiCheckpoint", tag = "brain",
    responses((status = 200, description = "Asks the Core to distil this AI session's new turns now. It only requests: the Core's caps still decide (1 request per 10 minutes per session), and it never names a room or text. A refusal is a normal answer, not an error.", body = CheckpointAsked)))]
pub(crate) async fn request(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Extension(me): Extension<Caller>,
) -> ApiResult<CheckpointAsked> {
    let session = session_of(&me)?;
    let refused = |r: &str| {
        Json(CheckpointAsked {
            requested: false,
            reason: Some(r.to_owned()),
        })
    };
    let eligible = agents::get(&app.pool, &session)
        .await?
        .is_some_and(|s| s.live() && s.owner_module.as_deref() != Some(MODULE))
        && !crate::claim::claimed_sessions(&app)
            .await?
            .contains(&session);
    if !eligible {
        return Ok(refused("not_eligible"));
    }
    let now = app.clock.unix();
    let asked = ask(
        &mut b.inner.ckpt.lock().unwrap_or_else(PoisonError::into_inner),
        &session,
        now,
    );
    if let Err(why) = asked {
        return Ok(refused(why));
    }
    // Ids only (Q-15).
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.ai.checkpoint_requested",
        json!({"session": session}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(CheckpointAsked {
        requested: true,
        reason: None,
    }))
}

/// Takes new turns of live sessions and queues their distils; returns how many it queued.
pub(crate) async fn step(app: &App, b: &Brain, now: i64) -> Result<u32, ApiError> {
    let asked: Vec<String> = b
        .inner
        .ckpt
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter_mut()
        .filter(|(_, c)| c.pending)
        .map(|(id, c)| {
            c.pending = false;
            id.clone()
        })
        .collect();
    let mut todo: Vec<(agents::Session, bool)> = vec![];
    for s in agents::live(&app.pool).await? {
        let was_asked = asked.contains(&s.id);
        let idle =
            s.api_state() == "waiting" && s.waiting_since.is_some_and(|w| w <= now - IDLE_SECS);
        if s.owner_module.as_deref() != Some(MODULE) && (was_asked || idle) {
            todo.push((s, was_asked));
        }
    }
    // Asked first, then the longest waiting.
    todo.sort_by_key(|(s, asked)| (!asked, s.waiting_since));
    let mut queued = 0;
    for (s, was_asked) in todo.into_iter().take(MAX_PER_TICK) {
        let state = {
            let mut m = b.inner.ckpt.lock().unwrap_or_else(PoisonError::into_inner);
            if m.len() >= MAX_TRACKED && !m.contains_key(&s.id) {
                continue;
            }
            let c = m.entry(s.id.clone()).or_default();
            let too_soon = c.ran.is_some_and(|t| now - t < EVERY_SECS);
            let unchanged = !was_asked && c.seen_seq == s.last_seq;
            c.seen_seq = s.last_seq;
            (too_soon, unchanged)
        };
        if state.0 || state.1 {
            continue;
        }
        let done: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM brain_distils WHERE of_session = ? AND \"trigger\" IN ('checkpoint','hook')",
        )
        .bind(&s.id)
        .fetch_one(&app.pool)
        .await?;
        if done >= MAX_PER_SESSION {
            continue;
        }
        let min = if was_asked {
            MIN_ASKED_CHARS
        } else {
            MIN_NEW_CHARS
        };
        let r = match sync_core_as(app, b, None, None, Some((&s.id, min))).await {
            Ok(r) => r,
            // The brain key is missing or locked: wait, nothing is lost.
            Err(e) if e.status == axum::http::StatusCode::CONFLICT => break,
            Err(e) => return Err(e),
        };
        if r.run.is_none() {
            continue;
        }
        if let Some(c) = b
            .inner
            .ckpt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&s.id)
        {
            c.ran = Some(now);
        }
        let trigger = if was_asked { "hook" } else { "checkpoint" };
        for routed in r.routed {
            if queue(app, &routed.room, trigger, Some(&s.id), routed.sources, now).await?
                == crate::auto_distil::Queued::Yes
            {
                queued += 1;
            }
        }
    }
    Ok(queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_may_ask_once_per_ten_minutes_and_the_map_is_bounded() {
        let mut m = HashMap::new();
        assert_eq!(ask(&mut m, "a", 1000), Ok(()));
        assert_eq!(ask(&mut m, "a", 1599), Err("rate_limited"));
        assert_eq!(ask(&mut m, "a", 1600), Ok(()));
        for i in 0..MAX_TRACKED {
            let _ = ask(&mut m, &format!("s{i}"), 1600);
        }
        // Full of fresh requests: a new session is told to come back, not remembered.
        assert_eq!(ask(&mut m, "new", 1601), Err("busy"));
        // Ten minutes on and nothing pending, the old ones are forgotten and the map takes it.
        m.values_mut().for_each(|c| c.pending = false);
        assert_eq!(ask(&mut m, "new", 1600 + EVERY_SECS + 1), Ok(()));
    }
}
