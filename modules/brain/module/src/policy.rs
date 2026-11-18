//! A room's model policy (E6-3) and auto-accept rules (E6-4). Cloud is the default: every room may
//! use the approved cloud provider (plan section 12, answer 4). A room set to local-only never
//! claims a cloud account; its distillation waits as "Needs a local model".

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
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
/// Candidate kinds a room may accept without a review: every record type (the plan's closed set,
/// `answer::KINDS`), so the Inbox and the policy speak the same words. Off by default (an empty list).
/// A landmine is a `rule` and an open thread a `task`, told apart by tag (plan section 4.4).
pub const AUTO_KINDS: &[&str] = crate::answer::KINDS;

/// A new room's `auto_accept` (Brain v2: auto-save every kind, with Undo). SQLite cannot change a
/// column default, so the two places that insert a policy row bind this; keep it equal to the sorted
/// `AUTO_KINDS` and to the backfill in `0009_brain_v2.up.sql`.
pub(crate) const AUTO_ACCEPT_ALL: &str =
    r#"["decision","fact","preference","project-state","rule","summary","task"]"#;

pub(crate) struct Policy {
    pub name: String,
    pub allowed: Vec<String>,
    pub auto_accept: Vec<String>,
    pub min_sources: usize,
    pub lease_hours: i64,
    pub review_days: i64,
    /// Compact fully distilled sources older than this many days; none = keep (the default).
    pub retention_days: Option<u32>,
    /// Automatic distils a day (0 = off); the ceiling is `MAX_DAILY_DISTILS`.
    pub daily_distils: u32,
}

/// The most automatic distils a day a person may set (the column allows 1000; this bounds cost).
pub const MAX_DAILY_DISTILS: u32 = 50;

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
        "SELECT r.name, r.review_days, p.allowed_providers, p.auto_accept, p.min_sources, p.lease_hours, p.retention_days, p.daily_distils \
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
        min_sources: usize::try_from(r.try_get::<i64, _>("min_sources")?).unwrap_or(1),
        lease_hours: r.try_get("lease_hours")?,
        review_days: r.try_get("review_days")?,
        retention_days: r
            .try_get::<Option<i64>, _>("retention_days")?
            .and_then(|d| u32::try_from(d).ok()),
        daily_distils: u32::try_from(r.try_get::<i64, _>("daily_distils")?).unwrap_or(0),
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
    /// An auto-accepted candidate must cite at least this many sources (1 to 20; default 1).
    #[schema(required = false)]
    pub min_sources: u32,
    /// The accounts the room's model policy lets distillation use (none for a local-only room).
    #[schema(required = false)]
    pub accounts: Vec<PolicyAccount>,
    /// Local models a runner declares (none are declared yet).
    #[schema(required = false)]
    pub local_models: Vec<String>,
    pub lease_hours: i64,
    pub review_days: i64,
    /// Sources older than this many days that are fully distilled lose their text and keep a citation stub. Null (the default) keeps everything.
    pub retention_days: Option<u32>,
    /// Automatic distils a day for the room: 0 is off, the most is 50 (default 12).
    #[schema(required = false)]
    pub daily_distils: u32,
}

#[derive(Serialize, ToSchema)]
pub struct PolicyAccount {
    pub id: i64,
    pub provider: String,
    /// The account's name.
    pub name: String,
    /// `active` or why not.
    pub state: String,
}

async fn view(app: &App, room: &str, p: &Policy) -> Result<PolicyView, sqlx::Error> {
    let accounts = ainkrad_core_server::store::accounts::list(&app.pool)
        .await?
        .into_iter()
        .filter(|a| p.allows(&a.provider))
        .map(|a| PolicyAccount {
            id: a.id,
            provider: a.provider,
            name: a.label,
            state: a.state,
        })
        .collect();
    Ok(PolicyView {
        room: room.to_owned(),
        model: if p.local_only() {
            "local_only"
        } else {
            "cloud"
        }
        .to_owned(),
        allowed_providers: p.allowed.clone(),
        auto_accept: p.auto_accept.clone(),
        min_sources: u32::try_from(p.min_sources).unwrap_or(1),
        accounts,
        local_models: vec![],
        lease_hours: p.lease_hours,
        review_days: p.review_days,
        retention_days: p.retention_days,
        daily_distils: p.daily_distils,
    })
}

#[derive(Deserialize, ToSchema)]
pub struct PolicyPatch {
    /// `cloud` or `local_only`.
    pub model: Option<String>,
    /// Record types to accept without a review: any of `decision`, `fact`, `preference`, `rule`, `project-state`, `task`, `summary`. An empty list turns it off.
    pub auto_accept: Option<Vec<String>>,
    /// 1 to 20: the fewest sources an auto-accepted candidate must cite.
    pub min_sources: Option<u32>,
    /// Compaction is permanent. 1 to 3650 turns it on (step-up; a person only); 0 turns it off (keep). Check `GET /rooms/{room}/retention` first for what it would compact.
    pub retention_days: Option<u32>,
    /// Automatic distils a day: 0 turns auto-distil off for the room, the most is 50. A person only (an AI session is refused); no step-up, it only bounds cost.
    pub daily_distils: Option<u32>,
}

#[utoipa::path(get, path = "/rooms/{room}/policy", operation_id = "brainRoomPolicy", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Which models may read the room and what is accepted without review", body = PolicyView)))]
pub(crate) async fn get(State(app): State<App>, Path(room): Path<String>) -> ApiResult<PolicyView> {
    Ok(Json(view(&app, &room, &load(&app, &room).await?).await?))
}

#[utoipa::path(patch, path = "/rooms/{room}/policy", operation_id = "brainPatchRoomPolicy", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = PolicyPatch,
    responses((status = 200, description = "The policy after the change (step-up; audited as `brain.room.policy`)", body = PolicyView)))]
pub(crate) async fn patch(
    State(app): State<App>,
    Extension(_b): Extension<Brain>,
    Extension(me): Extension<Caller>,
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
                "auto_accept takes record types: decision, fact, preference, rule, project-state, task, summary",
            ));
        }
        let mut kinds = kinds;
        kinds.sort();
        kinds.dedup();
        p.auto_accept = kinds;
    }
    if let Some(n) = req.min_sources {
        if !(1..=20).contains(&n) {
            return Err(ApiError::bad_request("min_sources is 1 to 20"));
        }
        p.min_sources = n as usize;
    }
    if let Some(d) = req.retention_days {
        if d > crate::retention::MAX_DAYS {
            return Err(ApiError::bad_request(
                "retention_days is 0 (keep) or 1 to 3650",
            ));
        }
        // Compaction cannot be undone: only a person turns it on (the route also needs a step-up).
        if d > 0 && me.session.starts_with(crate::ai::SESSION) {
            return Err(crate::code(
                403,
                "person_only",
                "an AI session cannot turn on retention",
            ));
        }
        p.retention_days = (d > 0).then_some(d);
    }
    if let Some(n) = req.daily_distils {
        if n > MAX_DAILY_DISTILS {
            return Err(ApiError::bad_request("daily_distils is 0 (off) to 50"));
        }
        if me.session.starts_with(crate::ai::SESSION) {
            return Err(crate::code(
                403,
                "person_only",
                "an AI session cannot change daily_distils",
            ));
        }
        p.daily_distils = n;
    }
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE brain_room_policy SET allowed_providers = ?, auto_accept = ?, min_sources = ?, retention_days = ?, daily_distils = ? WHERE room = ?",
    )
    .bind(json!(p.allowed).to_string())
    .bind(json!(p.auto_accept).to_string())
    .bind(i64::try_from(p.min_sources).unwrap_or(1))
    .bind(p.retention_days)
    .bind(i64::from(p.daily_distils))
    .bind(&room)
    .execute(&mut *tx)
    .await?;
    record(
        &mut tx,
        "brain.room.policy",
        json!({"room": room, "allowed": p.allowed, "auto_accept": p.auto_accept, "min_sources": p.min_sources, "retention_days": p.retention_days, "daily_distils": p.daily_distils}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(&app, &room, &p).await?))
}
