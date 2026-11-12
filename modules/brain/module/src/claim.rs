//! A session claims a room (E6-1, C-04 subset, Q-12). The claim checks the WHOLE fallback chain
//! the session walks against the room's model policy: when any entry is outside it, the claim is
//! refused and names that entry. A session with no chain is refused too: it would start on the
//! runner's own login, which no policy can see. The chain is the session's own snapshot, so a
//! later edit of the chain moves nothing, and a claim is made while the session is still
//! `starting` (no account yet).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::store::alloc::Entry;
use ainkrad_core_server::store::{agents, alloc, begin_write};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

use crate::policy::{self, Policy};
use crate::{Brain, code, record};

/// `Ok` when every entry is inside the policy; else why, naming the first one that is not.
pub(crate) fn check_chain(chain: &[Entry], p: &Policy) -> Result<(), String> {
    if chain.is_empty() {
        return Err(
            "the session has no fallback chain: it would use the runner's own login, which no room policy covers"
                .to_owned(),
        );
    }
    for (i, e) in chain.iter().enumerate() {
        if !p.allows(&e.provider) {
            return Err(format!(
                "chain entry {} (provider {}{}) is outside the model policy of room {}",
                i + 1,
                e.provider,
                e.model
                    .as_deref()
                    .map_or(String::new(), |m| format!(", model {m}")),
                p.name
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize, ToSchema)]
pub struct ClaimRequest {
    /// An AI session that has not started yet.
    pub session: String,
}

#[derive(Serialize, ToSchema)]
pub struct RoomClaim {
    pub room: String,
    pub session: String,
    /// Chain entries checked.
    pub entries: usize,
}

/// Claims `session` for `room` on behalf of device `by`.
pub(crate) async fn claim(
    app: &App,
    room: &str,
    session: &str,
    by: &str,
) -> Result<RoomClaim, ApiError> {
    let p = policy::load(app, room).await?;
    let s = agents::get(&app.pool, session)
        .await?
        .ok_or_else(|| ApiError::not_found("no such AI session"))?;
    if s.state != "starting" {
        return Err(code(
            409,
            "session_started",
            "only an AI session that has not started can claim a room",
        ));
    }
    let chain = alloc::view(&app.pool, session)
        .await?
        .and_then(|v| v.chain)
        .unwrap_or_default();
    if let Err(why) = check_chain(&chain, &p) {
        let mut tx = begin_write(&app.pool).await?;
        record(
            &mut tx,
            "brain.session.refused",
            json!({"room": room, "session": session}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Err(code(403, "claim_refused", why));
    }
    let mut tx = begin_write(&app.pool).await?;
    let made = sqlx::query(
        "INSERT OR IGNORE INTO brain_session_rooms (session, room, chain, claimed_by, claimed_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(session)
    .bind(room)
    .bind(json!(chain).to_string())
    .bind(by)
    .bind(app.clock.now())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if made == 0 {
        return Err(code(
            409,
            "already_claimed",
            "the AI session already claimed a room",
        ));
    }
    record(
        &mut tx,
        "brain.session.claimed",
        json!({"room": room, "session": session, "entries": chain.len()}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(RoomClaim {
        room: room.to_owned(),
        session: session.to_owned(),
        entries: chain.len(),
    })
}

/// The ids of every claimed session: the Core's own transcript collector skips them, so the Brain
/// never reads its own distillation back in.
pub(crate) async fn claimed_sessions(
    app: &App,
) -> Result<std::collections::HashSet<String>, sqlx::Error> {
    Ok(
        sqlx::query_scalar("SELECT session FROM brain_session_rooms")
            .fetch_all(&app.pool)
            .await?
            .into_iter()
            .collect(),
    )
}

#[utoipa::path(post, path = "/rooms/{room}/claims", operation_id = "brainClaimRoom", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = ClaimRequest,
    responses((status = 200, description = "The AI session works for the room: every entry of its fallback chain is inside the room's model policy (step-up; refusal `claim_refused` names the entry)", body = RoomClaim)))]
pub(crate) async fn claim_route(
    State(app): State<App>,
    Extension(_b): Extension<Brain>,
    Extension(me): Extension<Caller>,
    Path(room): Path<String>,
    Json(req): Json<ClaimRequest>,
) -> ApiResult<RoomClaim> {
    Ok(Json(claim(&app, &room, &req.session, &me.device.id).await?))
}
