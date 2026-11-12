//! The audit log, newest first: every audited change, paged backwards, for the app's activity
//! screen.

use ainkrad_core::audit::{AuditActor, AuditOrigin, AuditSeq, OriginKind};
use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::audit::{self, OriginFilter};

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
    /// Only rows about this entity: its kind (`device`), or kind and id (`device:d_…`, or
    /// `<kind>:<n>` for a kind with numeric ids).
    pub target: Option<String>,
    /// Only rows done by this kind of actor: `user` or `system`; another value is a 400.
    pub actor: Option<String>,
    /// Only rows with this origin: `person`, `schedule`, `brain_import`, `brain_distil`,
    /// `ai_session`, `handoff` or `system`; another value is a 400.
    pub origin: Option<String>,
    /// `true`: only rows with a known origin that is not a person ("nobody watching"); rows
    /// from before origins are unknown and not in it. Not with `origin`.
    pub nobody_watching: Option<bool>,
}

/// What started an audited change, and the root of its chain. Absent on rows from before
/// origins (unknown).
#[derive(Debug, Serialize, ToSchema)]
pub struct EntryOrigin {
    /// `person`, `schedule`, `brain_import`, `brain_distil`, `ai_session`, `handoff`, `system`.
    pub kind: String,
    /// The device (`d_…`), job (`owner/job`) or session (`as_…`) it names, when there is one.
    pub reference: Option<String>,
    /// The kind of the first link of the chain.
    pub root_kind: String,
    pub root_reference: Option<String>,
}

impl From<AuditOrigin> for EntryOrigin {
    fn from(o: AuditOrigin) -> Self {
        Self {
            kind: o.kind.as_str().to_owned(),
            reference: o.reference,
            root_kind: o.root_kind.as_str().to_owned(),
            root_reference: o.root_reference,
        }
    }
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
    /// A numeric entity id; absent for a device, which is named by `entity_ref` only.
    pub entity_id: Option<i64>,
    /// The entity's public id: a device's opaque `d_…` id, else `entity_id` as text.
    pub entity_ref: Option<String>,
    #[schema(value_type = Object)]
    pub details: Value,
    /// What started it; absent on rows from before origins.
    pub origin: Option<EntryOrigin>,
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
        not a `d_…` device id or a number, or an unknown `actor` or `origin`, is a 400",
        body = AuditPage)))]
pub async fn list(State(app): State<App>, Query(q): Query<AuditQuery>) -> ApiResult<AuditPage> {
    let limit = q.limit.unwrap_or(AUDIT_PAGE).clamp(1, AUDIT_PAGE);
    let target = match q.target.as_deref().map(|t| t.split_once(':')) {
        None => None,
        Some(None) => q.target.as_deref().map(|kind| (kind, None)),
        Some(Some((kind, id))) => {
            let bad = || ApiError::bad_request("target is <kind> or <kind>:<id>");
            let id = if kind == DEVICE {
                // A device unknown here matches nothing (row numbers start at 1).
                device_seq(&app, id).await?.unwrap_or(0)
            } else {
                id.parse::<i64>().map_err(|_| bad())?
            };
            Some((kind, Some(id)))
        }
    };
    let actor = match q.actor.as_deref() {
        None | Some("") => None,
        Some(a @ ("user" | "system")) => Some(a),
        Some(_) => return Err(ApiError::bad_request("actor is user or system")),
    };
    let origin = match (
        q.origin.as_deref().filter(|o| !o.is_empty()),
        q.nobody_watching,
    ) {
        (Some(_), Some(true)) => {
            return Err(ApiError::bad_request(
                "origin and nobody_watching are exclusive",
            ));
        }
        (Some(o), _) => OriginFilter::Is(
            OriginKind::parse(o).ok_or_else(|| ApiError::bad_request("unknown origin"))?,
        ),
        (None, Some(true)) => OriginFilter::NobodyWatching,
        (None, _) => OriginFilter::Any,
    };
    let kind = q.kind.as_deref().filter(|k| !k.is_empty());
    let rows = audit::page_by(
        &app.pool,
        q.before.map(AuditSeq),
        kind,
        target,
        actor,
        origin,
        limit + 1,
    )
    .await?;
    let mut page = page_of(rows, limit);
    for e in &mut page.items {
        if e.entity_kind.as_deref() == Some(DEVICE) {
            let seq = e.entity_id.take();
            e.entity_ref = match seq {
                Some(seq) => device_ref(&app, seq).await?,
                None => None,
            };
        }
    }
    Ok(Json(page))
}

/// The entity kind whose public id is opaque (handshake spec §3): its rows' numbers never leave.
const DEVICE: &str = "device";

async fn device_seq(app: &App, id: &str) -> Result<Option<i64>, ApiError> {
    if !crate::auth::crypto::is_id(id, "d_") {
        return Err(ApiError::bad_request("a device target is device:d_…"));
    }
    Ok(
        sqlx::query_scalar("SELECT seq FROM core_devices WHERE id = ?")
            .bind(id)
            .fetch_optional(&app.pool)
            .await?,
    )
}

// ponytail: one primary-key lookup per device row, at most 100 a page.
async fn device_ref(app: &App, seq: i64) -> Result<Option<String>, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT id FROM core_devices WHERE seq = ?")
            .bind(seq)
            .fetch_optional(&app.pool)
            .await?,
    )
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
            entity_ref: e.entity.as_ref().map(|x| x.id.to_string()),
            entity_id: e.entity.map(|x| x.id),
            details: serde_json::from_str(&e.details).unwrap_or(Value::Null),
            origin: e.origin.map(Into::into),
        })
        .collect();
    let next_before = more.then(|| items.last().map(|e| e.seq)).flatten();
    AuditPage { items, next_before }
}
