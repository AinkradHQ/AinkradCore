//! A room's model policy (E6-3) and auto-accept rules (E6-4). Cloud is the default: every room may
//! use the approved cloud provider (plan section 12, answer 4). A room set to local-only never
//! claims a cloud account; its distillation waits as "Needs a local model".

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use utoipa::ToSchema;

use crate::{Brain, record};

/// The cloud providers Ahmed approved for the Brain (the Anthropic account, 2026-11-11).
/// ponytail: a constant; a setting when a second provider is approved.
pub const APPROVED_CLOUD: &[&str] = &["anthropic", "claude-sub"];
/// The class a policy names for the approved cloud providers.
pub const CLOUD: &str = "approved_cloud";
/// The class for a runner's declared local model (Q-51). No provider is local yet, so a local-only
/// room matches no chain entry.
pub const LOCAL: &str = "local";
/// Candidate kinds that may be accepted without a review: low risk, never a decision, rule or task.
pub const AUTO_KINDS: &[&str] = &["fact", "preference", "summary"];

pub(crate) struct Policy {
    pub name: String,
    pub allowed: Vec<String>,
    pub auto_accept: Vec<String>,
    pub lease_hours: i64,
    pub review_days: i64,
}

impl Policy {
    pub fn local_only(&self) -> bool {
        !self.allowed.is_empty() && self.allowed.iter().all(|a| a == LOCAL)
    }

    pub fn allows(&self, provider: &str) -> bool {
        self.allowed.iter().any(|a| match a.as_str() {
            CLOUD => APPROVED_CLOUD.contains(&provider),
            LOCAL => provider.starts_with("local"),
            other => other == provider,
        })
    }
}

pub(crate) async fn load(app: &App, room: &str) -> Result<Policy, ApiError> {
    let r = sqlx::query(
        "SELECT r.name, r.review_days, p.allowed_providers, p.auto_accept, p.lease_hours \
         FROM brain_rooms r JOIN brain_room_policy p ON p.room = r.id WHERE r.id = ? AND r.state = 'active'",
    )
    .bind(room)
    .fetch_optional(&app.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("no such room"))?;
    let list = |col: &str| -> Result<Vec<String>, sqlx::Error> {
        Ok(serde_json::from_str(&r.try_get::<String, _>(col)?).unwrap_or_default())
    };
    Ok(Policy {
        name: r.try_get("name")?,
        allowed: list("allowed_providers")?,
        auto_accept: list("auto_accept")?,
        lease_hours: r.try_get("lease_hours")?,
        review_days: r.try_get("review_days")?,
    })
}

#[derive(Serialize, ToSchema)]
pub struct PolicyView {
    pub room: String,
    /// `cloud` (the approved provider) or `local_only`.
    pub model: String,
    pub allowed_providers: Vec<String>,
    /// Candidate kinds accepted without a review; empty (off) by default.
    pub auto_accept: Vec<String>,
    pub lease_hours: i64,
    pub review_days: i64,
}

fn view(room: &str, p: &Policy) -> PolicyView {
    PolicyView {
        room: room.to_owned(),
        model: if p.local_only() {
            "local_only"
        } else {
            "cloud"
        }
        .to_owned(),
        allowed_providers: p.allowed.clone(),
        auto_accept: p.auto_accept.clone(),
        lease_hours: p.lease_hours,
        review_days: p.review_days,
    }
}

#[derive(Deserialize, ToSchema)]
pub struct PolicyPatch {
    /// `cloud` or `local_only`.
    pub model: Option<String>,
    /// Kinds to accept without a review: `fact`, `preference`, `summary`. An empty list turns it off.
    pub auto_accept: Option<Vec<String>>,
}

#[utoipa::path(get, path = "/rooms/{room}/policy", operation_id = "brainRoomPolicy", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Which models may read the room and what is accepted without review", body = PolicyView)))]
pub(crate) async fn get(State(app): State<App>, Path(room): Path<String>) -> ApiResult<PolicyView> {
    Ok(Json(view(&room, &load(&app, &room).await?)))
}

#[utoipa::path(patch, path = "/rooms/{room}/policy", operation_id = "brainPatchRoomPolicy", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = PolicyPatch,
    responses((status = 200, description = "The policy after the change (step-up; audited as `brain.room.policy`)", body = PolicyView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Extension(_b): Extension<Brain>,
    Path(room): Path<String>,
    Json(req): Json<PolicyPatch>,
) -> ApiResult<PolicyView> {
    let mut p = load(&app, &room).await?;
    match req.model.as_deref() {
        None => {}
        Some("cloud") => p.allowed = vec![CLOUD.to_owned()],
        Some("local_only") => p.allowed = vec![LOCAL.to_owned()],
        Some(_) => return Err(ApiError::bad_request("model is `cloud` or `local_only`")),
    }
    if let Some(kinds) = req.auto_accept {
        if kinds.iter().any(|k| !AUTO_KINDS.contains(&k.as_str())) {
            return Err(ApiError::bad_request(
                "auto_accept takes `fact`, `preference` or `summary` only",
            ));
        }
        let mut kinds = kinds;
        kinds.sort();
        kinds.dedup();
        p.auto_accept = kinds;
    }
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE brain_room_policy SET allowed_providers = ?, auto_accept = ? WHERE room = ?",
    )
    .bind(json!(p.allowed).to_string())
    .bind(json!(p.auto_accept).to_string())
    .bind(&room)
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        "brain.room.policy",
        json!({"room": room, "allowed": p.allowed, "auto_accept": p.auto_accept}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(&room, &p)))
}
