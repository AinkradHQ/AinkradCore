//! The "why stuck" screen's actions (the Mac plugin): release a dead checkout, retry a run on a
//! runner the admin picks, and bump an issue. Each goes through the engine as the admin and is
//! audited (`store::exec::stuck_actions`, `store::work::set_issue_priority`).

use ainkrad_core::exec::{self as core_exec, RunId, RunnerId};
use ainkrad_core::work::IssueId;
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::model::Issue;
use super::types::{RepairAction, StuckKind, Timestamp, ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::exec::{self, StuckActionError};
use crate::store::work;

impl From<StuckActionError> for ApiError {
    fn from(e: StuckActionError) -> Self {
        match e {
            StuckActionError::NotFound(why) => Self::not_found(why),
            StuckActionError::Conflict(why) => Self::conflict(why),
            StuckActionError::Db(e) => e.into(),
        }
    }
}

/// The routes that came with API minor 8 on paths of their own; those on existing paths are in
/// `router`.
pub(super) fn routes() -> axum::Router<App> {
    use axum::routing::{delete, get, post};

    use super::{money, settings};
    axum::Router::new()
        .route("/api/v1/budgets/{id}", delete(money::delete_budget))
        .route("/api/v1/prices/history", get(money::price_history))
        .route(
            "/api/v1/issues/{id}/release-checkout",
            post(release_checkout),
        )
        .route("/api/v1/runs/{id}/retry", post(retry_run))
        .route("/api/v1/issues/{id}/priority", post(bump_issue))
        .route(
            "/api/v1/companies/{id}/settings/overridden",
            get(settings::overridden),
        )
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/release-checkout",
    operation_id = "releaseCheckout", tag = "controls",
    params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue, released by the run that held it and has \
        ended (the stuck rule `checkout_dead`; audited as `issue.released`). 409 when it is not \
        checked out, or its run is still live: stop the run instead", body = Issue)))]
pub async fn release_checkout(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Issue> {
    let i = exec::release_dead_checkout(&app.pool, IssueId(id), BY).await?;
    super::issues::issue_out(&app, i).await.map(Json)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RetryBody {
    /// The runner to run it on; it must hold every one of the agent's runner tags.
    pub runner_id: i64,
}

/// The wake that will start a retry.
#[derive(Debug, Serialize, ToSchema)]
pub struct Retried {
    pub agent_id: i64,
    pub issue_id: Option<i64>,
    pub wake_id: i64,
    /// The runner it is pinned to.
    pub runner_id: i64,
}

#[utoipa::path(post, path = "/api/v1/runs/{id}/retry", operation_id = "retryRun",
    tag = "controls", params(("id" = i64, Path, description = "Run id")), request_body = RetryBody,
    responses((status = 200, description = "The ended run's agent woken again on its issue, the \
        wake pinned to the runner: only it is given the retry, and the wake is stuck while it \
        cannot take it (audited as `run.retried`). A wake already pending for the agent and issue \
        takes the pin. 404 for no such runner; 409 while the run is live, for a closed issue, or \
        a runner without the agent's tags", body = Retried)))]
pub async fn retry_run(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<RetryBody>,
) -> ApiResult<Retried> {
    let runner = RunnerId(b.runner_id);
    let w = exec::retry_run_on(&app.pool, RunId(id), runner, BY, &app.clock.now()).await?;
    Ok(Json(Retried {
        agent_id: w.agent_id.0,
        issue_id: w.issue_id.map(|i| i.0),
        wake_id: w.id.0,
        runner_id: runner.0,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PriorityBody {
    /// `true` (the default): to the top of its backlog, its wakes dispatched first; `false`
    /// clears the flag and leaves its place.
    #[serde(default = "yes")]
    pub priority: bool,
}

fn yes() -> bool {
    true
}

#[utoipa::path(post, path = "/api/v1/issues/{id}/priority", operation_id = "bumpIssue",
    tag = "controls", params(("id" = i64, Path, description = "Issue id")),
    request_body = PriorityBody,
    responses((status = 200, description = "The issue, bumped or not (audited as \
        `issue.priority_set`)", body = Issue)))]
pub async fn bump_issue(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(b): Json<PriorityBody>,
) -> ApiResult<Issue> {
    let i = work::set_issue_priority(&app.pool, IssueId(id), b.priority, BY)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))?;
    super::issues::issue_out(&app, i).await.map(Json)
}

/// Why an issue is stuck and what would unstick it.
#[derive(Debug, Serialize, ToSchema)]
pub struct StuckIssue {
    pub kind: StuckKind,
    pub issue_id: Option<i64>,
    /// The agent it waits on, when there is one.
    pub agent_id: Option<i64>,
    pub reason: String,
    pub action: String,
    /// What the scheduler does about it by itself (E15.8): the engine's recommendation.
    pub repair: RepairAction,
    /// The issue's last automatic repair (`repair.<rule>` in the audit), if any.
    pub last_repair: Option<LastRepair>,
    /// Since when it has been stuck: an issue's last activity, a wake's or run's wait start;
    /// absent when unknown (a full disk).
    pub stuck_since: Option<Timestamp>,
    /// The run on it: a live one, else the run a wake or dead checkout is about (API minor 18);
    /// absent when there is none.
    pub run_id: Option<i64>,
    /// How long an issue of its project usually stays in the state it is stuck in, in seconds:
    /// the median of its past stays there (at least 3); absent otherwise (API minor 18).
    pub usual_secs: Option<i64>,
    /// What last happened to the issue, oldest first (API minor 18); empty when it has no issue.
    #[schema(required = false)]
    pub trail: Vec<TrailStep>,
}

/// One thing that happened to an issue.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrailStep {
    pub at: Timestamp,
    /// In words: `moved in_progress -> in_review`, `repair rewake`, ….
    pub what: String,
}

/// How many steps a stuck issue's trail shows.
const TRAIL: i64 = 6;

/// A step's text from its audit `action` and `details`.
fn what(action: &str, details: &serde_json::Value) -> String {
    let word = |k: &str| details[k].as_str().map(str::to_owned);
    match (action, word("from"), word("to")) {
        ("issue.state_changed", Some(from), Some(to)) => format!("moved {from} -> {to}"),
        (a, ..) => a.replace(['.', '_'], " "),
    }
}

/// Fills `run_id` (when only the issue is known), `usual_secs` and `trail` of `s`.
pub(super) async fn enrich(app: &crate::api::App, s: &mut StuckIssue) -> Result<(), sqlx::Error> {
    let Some(issue) = s.issue_id else {
        return Ok(());
    };
    if s.run_id.is_none() {
        s.run_id = sqlx::query_scalar(
            "SELECT id FROM runs WHERE issue_id = ? AND state IN ('queued', 'claimed', 'running') \
             ORDER BY id DESC LIMIT 1",
        )
        .bind(issue)
        .fetch_optional(&app.pool)
        .await?;
    }
    let stays: Vec<i64> = sqlx::query_scalar(
        "SELECT CAST((julianday(n.at) - julianday(h.at)) * 86400 AS INTEGER) \
         FROM issue_state_history h JOIN issues i ON i.project_id = \
             (SELECT project_id FROM issues WHERE id = ?1) AND i.id = h.issue_id \
         JOIN issue_state_history n ON n.id = (SELECT min(x.id) FROM issue_state_history x \
             WHERE x.issue_id = h.issue_id AND x.id > h.id) \
         WHERE h.to_state = (SELECT state FROM issues WHERE id = ?1) ORDER BY h.id DESC LIMIT 200",
    )
    .bind(issue)
    .fetch_all(&app.pool)
    .await?;
    if stays.len() >= 3 {
        let mut sorted = stays;
        sorted.sort_unstable();
        s.usual_secs = Some(sorted[sorted.len() / 2]);
    }
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT at, action, details FROM audit_events WHERE entity_kind = 'issue' \
         AND entity_id = ? ORDER BY seq DESC LIMIT ?",
    )
    .bind(issue)
    .bind(TRAIL)
    .fetch_all(&app.pool)
    .await?;
    s.trail = rows
        .into_iter()
        .rev()
        .map(|(at, action, details)| TrailStep {
            at: ts(&at),
            what: what(&action, &serde_json::from_str(&details).unwrap_or_default()),
        })
        .collect();
    Ok(())
}

/// An automatic repair (E15.8): its action (`rewake`, `escalate`, …, or `escalate_to_admin`
/// past the issue's repair budget) and when.
#[derive(Debug, Serialize, ToSchema)]
pub struct LastRepair {
    pub action: String,
    pub at: Timestamp,
}

impl From<core_exec::StuckIssue> for StuckIssue {
    fn from(s: core_exec::StuckIssue) -> Self {
        Self {
            kind: s.kind.into(),
            issue_id: s.issue_id.map(|i| i.0),
            agent_id: s.agent_id.map(|a| a.0),
            reason: s.reason,
            action: s.action,
            repair: s.repair.into(),
            last_repair: s.last_repair.map(|r| LastRepair {
                at: ts(&r.at),
                action: r.action,
            }),
            // Filled in by the route, which knows the report's `now`.
            stuck_since: None,
            run_id: s.run_id.map(|r| r.0),
            usual_secs: None,
            trail: vec![],
        }
    }
}
