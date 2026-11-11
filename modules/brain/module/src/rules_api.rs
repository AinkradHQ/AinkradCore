//! Rules (E1-4): list, add, switch on and off. No delete; `enabled = false` instead. A locked rule
//! (the seeded deprecated projects) refuses change, and switching a rule off widens what the Brain
//! takes in, so it needs a step-up.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::Json;
use axum::extract::{Path, State};
use brain_model::rules::RuleKind;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use utoipa::ToSchema;

use crate::{code, record};

#[derive(Serialize, ToSchema)]
pub struct RuleView {
    pub id: i64,
    pub kind: String,
    pub pattern: String,
    pub action: String,
    pub room: Option<String>,
    /// `seed` or `user`.
    pub origin: String,
    pub locked: bool,
    pub enabled: bool,
    pub reason: String,
}

#[derive(Deserialize, ToSchema)]
pub struct NewRule {
    pub kind: String,
    pub pattern: String,
    /// `refuse` or `route_to_room`.
    pub action: String,
    pub room: Option<String>,
    pub reason: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct RulePatch {
    pub enabled: bool,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<RuleView, sqlx::Error> {
    Ok(RuleView {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        pattern: r.try_get("pattern")?,
        action: r.try_get("action")?,
        room: r.try_get("room")?,
        origin: r.try_get("origin")?,
        locked: r.try_get::<i64, _>("locked")? == 1,
        enabled: r.try_get::<i64, _>("enabled")? == 1,
        reason: r.try_get("reason")?,
    })
}

#[utoipa::path(get, path = "/rules", operation_id = "brainRules", tag = "brain",
    responses((status = 200, description = "Every rule, the locked seed rules first", body = Vec<RuleView>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<RuleView>> {
    let rows = sqlx::query("SELECT * FROM brain_rules ORDER BY locked DESC, id")
        .fetch_all(&app.pool)
        .await?;
    Ok(Json(rows.iter().map(view).collect::<Result<_, _>>()?))
}

#[utoipa::path(post, path = "/rules", operation_id = "brainCreateRule", tag = "brain", request_body = NewRule,
    responses((status = 200, description = "The new rule (audited as `brain.rule.created`)", body = RuleView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Json(req): Json<NewRule>,
) -> ApiResult<RuleView> {
    if RuleKind::parse(&req.kind).is_none()
        || !["refuse", "route_to_room"].contains(&req.action.as_str())
        || req.pattern.trim().is_empty()
        || req.pattern.len() > 500
        || (req.action == "route_to_room") != req.room.is_some()
        || req.reason.as_deref().is_some_and(|r| r.len() > 300)
    {
        return Err(ApiError::bad_request(
            "a known kind, a pattern, refuse or route_to_room (with a room)",
        ));
    }
    let mut tx = begin_write(&app.pool).await?;
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO brain_rules (kind, pattern, action, room, origin, reason) VALUES (?, ?, ?, ?, 'user', ?) \
         ON CONFLICT(kind, pattern, action) DO NOTHING RETURNING id",
    )
    .bind(&req.kind)
    .bind(req.pattern.trim())
    .bind(&req.action)
    .bind(&req.room)
    .bind(req.reason.as_deref().unwrap_or(""))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(id) = id else {
        return Err(ApiError::conflict("that rule exists"));
    };
    record(
        &mut tx,
        "brain.rule.created",
        json!({"rule": id, "kind": req.kind, "action": req.action}),
        None,
    )
    .await?;
    let row = sqlx::query("SELECT * FROM brain_rules WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(view(&row)?))
}

#[utoipa::path(patch, path = "/rules/{id}", operation_id = "brainPatchRule", tag = "brain",
    params(("id" = i64, Path, description = "Rule id")), request_body = RulePatch,
    responses((status = 200, description = "Switched (step-up; audited as `brain.rule.changed`)", body = RuleView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(req): Json<RulePatch>,
) -> ApiResult<RuleView> {
    let mut tx = begin_write(&app.pool).await?;
    let row = sqlx::query("SELECT * FROM brain_rules WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::not_found("no such rule"))?;
    if row.try_get::<i64, _>("locked")? == 1 {
        return Err(code(409, "rule_locked", "a locked rule cannot be changed"));
    }
    sqlx::query("UPDATE brain_rules SET enabled = ? WHERE id = ?")
        .bind(i64::from(req.enabled))
        .bind(id)
        .execute(&mut *tx)
        .await?;
    record(
        &mut tx,
        "brain.rule.changed",
        json!({"rule": id, "enabled": req.enabled}),
        None,
    )
    .await?;
    let row = sqlx::query("SELECT * FROM brain_rules WHERE id = ?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(view(&row)?))
}
