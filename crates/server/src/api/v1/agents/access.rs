//! `connection_access` of a session create (C5; design §4, C4's contract): the capabilities the
//! session may call through its connections. Admin only; checked against the kinds' descriptors
//! before any row is written; an absent field is the default (read-class capabilities only, and
//! for an agent's session none until an allowlist is given, C4) and an empty list is refused
//! (400 `empty_allowlist`); written to
//! `core_session_connections` after the session row and before the session starts, so the
//! supervisor never sees the session without it. If the write fails the session is ended
//! unstarted: it never runs with more or less than was asked.
//!
//! Capability names only: the stored allowlist is per capability, so an operation name (`github.
//! get_issue`) cannot be narrower than its capability and is refused rather than widened.

use axum::http::StatusCode;
use serde_json::json;

use super::super::ApiError;
use crate::api::App;
use crate::store::connections::access;
use crate::store::events;

const MAX: usize = 16;

/// The allowlist to write: `None` for an absent field. A non-admin caller that names the field
/// at all is refused.
pub(in crate::api::v1) fn checked(
    app: &App,
    admin: bool,
    given: Option<&[String]>,
) -> Result<Option<Vec<String>>, ApiError> {
    let Some(list) = given else {
        return Ok(None);
    };
    if !admin {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "naming connection access requires the admin scope",
        ));
    }
    // An empty list is not "the default": absent is. Said plainly so no one believes `[]`
    // narrows (or widens) a session.
    if list.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_allowlist",
            "connection_access names at least one capability; leave it out for the default \
             (read-class capabilities only)",
        ));
    }
    let known = |name: &str| {
        let kinds = app.connections.registry().descriptors();
        kinds.iter().any(|d| d.capability(name).is_some())
    };
    if list.len() > MAX || !list.iter().all(|n| known(n)) {
        return Err(ApiError::bad_request(
            "connection_access is at most 16 capability names of the connection kinds \
             (`listConnectionKinds`); operations and wildcards are not accepted",
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for n in list {
        if !out.contains(n) {
            out.push(n.clone());
        }
    }
    Ok(Some(out))
}

/// Writes the allowlist of session `id`; on failure the unstarted session is ended and the
/// request refused.
pub(in crate::api::v1) async fn apply(
    app: &App,
    id: &str,
    list: &Option<Vec<String>>,
) -> Result<(), ApiError> {
    let Some(list) = list else {
        return Ok(());
    };
    let Err(e) = access::set(&app.pool, id, list).await else {
        return Ok(());
    };
    // It has not started: no runner session exists, so ending it here is complete.
    let now = app.clock.now();
    let outcome = json!({"kind": "failed", "reason": "its connection access could not be stored"});
    let ended = sqlx::query(
        "UPDATE core_agent_sessions SET state = 'ended', outcome = ?, updated_at = ?, \
         ended_at = ? WHERE id = ? AND state = 'starting'",
    )
    .bind(outcome.to_string())
    .bind(&now)
    .bind(&now)
    .bind(id)
    .execute(&app.pool)
    .await;
    if ended.is_ok_and(|r| r.rows_affected() > 0) {
        let payload = json!({"session": id, "state": "ended", "outcome": "failed"});
        if let Ok(mut conn) = app.pool.acquire().await {
            let _ = events::append(&mut conn, "agent.ended", &payload).await;
        }
    }
    Err(e.into())
}
