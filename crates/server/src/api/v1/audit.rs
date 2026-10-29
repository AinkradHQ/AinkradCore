//! The audit log, newest first: every audited change, paged backwards, for the app's activity
//! screen.

use ainkrad_core::audit::{AuditActor, AuditSeq};
use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::audit;

/// Who acted, on an audited change.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventActor {
    User { user_id: i64 },
    System {},
}

impl From<AuditActor> for EventActor {
    fn from(actor: AuditActor) -> Self {
        match actor {
            AuditActor::User(u) => Self::User { user_id: u.0 },
            AuditActor::System => Self::System {},
        }
    }
}

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
    /// Only actions starting with this: `device.` or `setting.set`.
    pub kind: Option<String>,
    /// Only rows about this entity: its kind (`device`), or kind and id (`device:3`).
    pub target: Option<String>,
    /// Only rows done by this kind of actor: `user` or `system`; another value is a 400.
    pub actor: Option<String>,
}

/// One audited change.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: Timestamp,
    /// Dotted: `device.revoked`, `setting.set`, ….
    pub action: String,
    pub actor: EventActor,
    pub entity_kind: Option<String>,
    pub entity_id: Option<i64>,
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
    responses((status = 200, description = "Audit rows, newest first. A `target` id that is \
        not a number, or an unknown `actor`, is a 400",
        body = AuditPage)))]
pub async fn list(State(app): State<App>, Query(q): Query<AuditQuery>) -> ApiResult<AuditPage> {
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
        Some(a @ ("user" | "system")) => Some(a),
        Some(_) => return Err(ApiError::bad_request("actor is user or system")),
    };
    let kind = q.kind.as_deref().filter(|k| !k.is_empty());
    let rows = audit::page(
        &app.pool,
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
fn page_of(rows: Vec<ainkrad_core::audit::AuditEvent>, limit: u32) -> AuditPage {
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
            details: serde_json::from_str(&e.details).unwrap_or(Value::Null),
        })
        .collect();
    let next_before = more.then(|| items.last().map(|e| e.seq)).flatten();
    AuditPage { items, next_before }
}
