//! The audit log, newest first (API minor 16): every audited change, paged backwards, for the
//! app's activity screen. Working in a company (`X-Citadel-Company`) it keeps only that
//! company's rows; without the header the admin sees every row, as `/events` does.

use citadel_core::audit::AuditSeq;
use axum::Json;
use axum::extract::{Extension, Query, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use super::events::EventActor;
use super::scope::Acting;
use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::audit;

/// Default and most audit rows on a page.
const AUDIT_PAGE: u32 = 100;

/// Which audit rows, from where.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Only rows with a `seq` below this (the previous page's `next_before`).
    pub before: Option<i64>,
    /// At most this many (default and most 100).
    pub limit: Option<u32>,
    /// Only actions starting with this: `knowledge.` or `issue.state_changed`.
    pub kind: Option<String>,
    /// Only rows about this entity: its kind (`issue`), or kind and id (`issue:12`).
    pub target: Option<String>,
    /// Only rows done by this kind of actor: `user`, `agent`, `system` (or `runner`) (API
    /// minor 17); another value is a 400.
    pub actor: Option<String>,
}

/// One audited change.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: Timestamp,
    /// Dotted: `issue.state_changed`, `knowledge.accepted`, ….
    pub action: String,
    pub actor: EventActor,
    pub entity_kind: Option<String>,
    pub entity_id: Option<i64>,
    pub company_id: Option<i64>,
    pub run_id: Option<i64>,
    #[schema(value_type = Object)]
    pub details: Value,
}

/// A page of the audit log, newest first. `next_before` continues with older rows, absent on
/// the last page.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditPage {
    pub items: Vec<AuditEntry>,
    pub next_before: Option<i64>,
}

#[utoipa::path(get, path = "/api/v1/audit", operation_id = "listAudit", tag = "events",
    params(AuditQuery),
    responses((status = 200, description = "Audit rows, newest first; of the acting company \
        only when `X-Citadel-Company` names one. A `target` id that is not a number, or an unknown `actor`, is a 400",
        body = AuditPage)))]
pub async fn list(
    State(app): State<App>,
    Extension(acting): Extension<Acting>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<AuditPage> {
    let limit = q.limit.unwrap_or(AUDIT_PAGE).clamp(1, AUDIT_PAGE);
    let target = match q.target.as_deref().map(|t| t.split_once(':')) {
        None => None,
        Some(None) => q.target.as_deref().map(|kind| (kind, None)),
        Some(Some((kind, id))) => {
            let id = id
                .parse::<i64>()
                .map_err(|_| ApiError::bad_request("target is <kind> or <kind>:<id>"))?;
            Some((kind, Some(id)))
        }
    };
    let actor = match q.actor.as_deref() {
        None | Some("") => None,
        Some(a @ ("user" | "agent" | "runner" | "system")) => Some(a),
        Some(_) => {
            return Err(ApiError::bad_request(
                "actor is user, agent, runner or system",
            ));
        }
    };
    let kind = q.kind.as_deref().filter(|k| !k.is_empty());
    let rows = audit::page(
        &app.pool,
        acting.0,
        q.before.map(AuditSeq),
        kind,
        target,
        actor,
        limit + 1,
    )
    .await?;
    Ok(Json(page_of(rows, limit)))
}

/// `rows` (read with one more than `limit`) as a page.
pub(super) fn page_of(rows: Vec<citadel_core::audit::AuditEvent>, limit: u32) -> AuditPage {
    let more = rows.len() > limit as usize;
    let items: Vec<AuditEntry> = rows
        .into_iter()
        .take(limit as usize)
        .map(|e| AuditEntry {
            seq: e.seq.0,
            at: ts(&e.at),
            action: e.action,
            actor: e.actor.into(),
            entity_kind: e.entity.as_ref().map(|x| x.kind.clone()),
            entity_id: e.entity.map(|x| x.id),
            company_id: e.company_id.map(|c| c.0),
            run_id: e.run_id.map(|r| r.0),
            details: serde_json::from_str(&e.details).unwrap_or(Value::Null),
        })
        .collect();
    let next_before = more.then(|| items.last().map(|e| e.seq)).flatten();
    AuditPage { items, next_before }
}
