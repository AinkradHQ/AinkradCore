//! Reads for the app's home, agent and run screens (E11.3–E11.5): an agent's skills, a
//! company's runs (filtered, paged), its open questions and its spend by the hour, and an
//! issue's diff per repo and its pull requests.

use ainkrad_core::gov::SkillAttach;
use ainkrad_core::org::AgentId;
use ainkrad_core::work::IssueId;
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::hub::{Question, question};
use super::model::Run;
use super::org::company;
use super::types::{Page, PrState, Timestamp, opt_ts, ts};
use super::{ApiError, ApiResult};
use crate::api::App;
use crate::store::exec::{self, RunFilter};
use crate::store::{forge, gov, work};

/// A skill an agent's runs are given (E4.3): its latest version, and what it is attached to.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentSkill {
    pub id: i64,
    pub name: String,
    pub version: i64,
    /// `company`, `department`, `role` or `project`.
    pub attached_to: String,
    /// The department or project id, or the role.
    pub attached_id: Option<i64>,
    pub attached_role: Option<String>,
    /// Its body's size; a run gets as many as fit `skills.budget_bytes`, most specific first.
    pub bytes: i64,
}

#[utoipa::path(get, path = "/api/v1/agents/{id}/skills", operation_id = "listAgentSkills",
    tag = "reads", params(("id" = i64, Path, description = "Agent id")),
    responses((status = 200, description = "The skills its runs are given, by name, before the \
        per-run budget", body = Vec<AgentSkill>)))]
pub async fn agent_skills(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<AgentSkill>> {
    let skills = gov::skills_for_agent(&app.pool, AgentId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no agent {id}")))?;
    Ok(Json(skills.into_iter().map(skill_out).collect()))
}

pub(super) fn skill_out(s: ainkrad_core::gov::Skill) -> AgentSkill {
    let (attached_to, attached_id, attached_role) = match s.attach {
        SkillAttach::Company => ("company", None, None),
        SkillAttach::Department(d) => ("department", Some(d.0), None),
        SkillAttach::Role(r) => ("role", None, Some(r)),
        SkillAttach::Project(p) => ("project", Some(p.0), None),
    };
    AgentSkill {
        id: s.id.0,
        name: s.name,
        version: s.version,
        attached_to: attached_to.to_owned(),
        attached_id,
        attached_role,
        bytes: s.body.len() as i64,
    }
}

/// Which runs: `live` only live (or only ended), one `state`, `agent` or `issue`; `after` (a
/// run id) continues with older runs.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RunQuery {
    pub live: Option<bool>,
    pub state: Option<String>,
    pub agent: Option<i64>,
    pub issue: Option<i64>,
    pub after: Option<i64>,
    pub limit: Option<u32>,
}

/// Default and most runs on a page.
const RUNS_PAGE: u32 = 100;

#[utoipa::path(get, path = "/api/v1/companies/{id}/runs", operation_id = "listCompanyRuns",
    tag = "reads", params(("id" = i64, Path, description = "Company id"), RunQuery),
    responses((status = 200, description = "The company's runs, newest first", body = Page<Run>)))]
pub async fn company_runs(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<RunQuery>,
) -> ApiResult<Page<Run>> {
    let c = company(&app, id).await?;
    if let Some(state) = &q.state
        && state.parse::<ainkrad_core::exec::RunState>().is_err()
    {
        return Err(ApiError::bad_request(format!(
            "unknown run state {state:?}"
        )));
    }
    let limit = q.limit.unwrap_or(RUNS_PAGE).clamp(1, RUNS_PAGE);
    let f = RunFilter {
        live: q.live,
        state: q.state,
        agent: q.agent.map(AgentId),
        issue: q.issue.map(IssueId),
        before: q.after,
    };
    let runs = exec::list_company_runs(&app.pool, c.id, &f, limit + 1).await?;
    let runs: Vec<Run> = runs.into_iter().map(Into::into).collect();
    Ok(Json(Page::of(runs, limit, |r| r.id)))
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/questions", operation_id = "listOpenQuestions",
    tag = "reads", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Its agents' open questions for the admin, across \
        requirements, oldest first (E15.11)", body = Vec<Question>)))]
pub async fn open_questions(
    State(app): State<App>,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Question>> {
    let c = company(&app, id).await?;
    let mut out = vec![];
    for q in work::open_questions(&app.pool, c.id).await? {
        let key = work::issue_key(&app.pool, q.issue_id)
            .await?
            .unwrap_or_default();
        out.push(question(q, key));
    }
    Ok(Json(out))
}

/// One repo's worktree against its base.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RepoDiff {
    /// The repo's name in its project; empty for an issue's only repo.
    pub repo: String,
    pub files: u32,
    pub insertions: u64,
    pub deletions: u64,
}

/// An issue's worktrees as last measured by a run's runner.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssueDiff {
    /// The run that measured them; absent before any did.
    pub run_id: Option<i64>,
    /// When that run last progressed.
    pub measured_at: Option<Timestamp>,
    /// In the issue's repo order.
    pub repos: Vec<RepoDiff>,
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/diff", operation_id = "getIssueDiff",
    tag = "reads", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "Each repo's diff against its base, from the latest \
        run that measured it (runner protocol 1.18)", body = IssueDiff)))]
pub async fn issue_diff(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<IssueDiff> {
    super::issues::issue(&app, id).await?;
    let found = exec::issue_diff(&app.pool, IssueId(id)).await?;
    Ok(Json(match found {
        Some((run, at, repos)) => IssueDiff {
            run_id: Some(run.0),
            measured_at: opt_ts(at.as_deref()),
            repos: repos
                .into_iter()
                .map(|d| RepoDiff {
                    repo: d.repo,
                    files: d.files,
                    insertions: d.insertions,
                    deletions: d.deletions,
                })
                .collect(),
        },
        None => IssueDiff {
            run_id: None,
            measured_at: None,
            repos: vec![],
        },
    }))
}

/// An issue's pull request on one of its repos.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssuePr {
    pub repo_id: i64,
    /// The project repo's name.
    pub repo: String,
    pub state: PrState,
    pub number: Option<u64>,
    pub url: Option<String>,
    pub title: String,
    pub head: String,
    pub base: String,
    pub head_sha: Option<String>,
    /// `none`, `pending`, `success` or `failure`.
    pub checks: String,
    /// What `checks` is made of when the forge token cannot read every check.
    pub checks_note: Option<String>,
    pub last_error: Option<String>,
    /// Why the runner's push of its branch was refused for good; it opens once the branch is
    /// on the forge.
    pub push_held: Option<String>,
    /// When opening it found its head branch not pushed (it waits for a later run's push).
    pub unpushed_at: Option<Timestamp>,
    pub updated_at: Timestamp,
}

#[utoipa::path(get, path = "/api/v1/issues/{id}/prs", operation_id = "listIssuePrs",
    tag = "reads", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue's pull requests, one per repo it asked \
        for, in its project's repo order", body = Vec<IssuePr>)))]
pub async fn issue_prs(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Vec<IssuePr>> {
    super::issues::issue(&app, id).await?;
    let prs = forge::issue_prs(&app.pool, IssueId(id)).await?;
    let extra: Vec<(i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT pr.repo_id, r.name, pr.unpushed_at, pr.updated_at FROM issue_prs pr \
         JOIN project_repos r ON r.id = pr.repo_id WHERE pr.issue_id = ?",
    )
    .bind(id)
    .fetch_all(&app.pool)
    .await?;
    Ok(Json(
        prs.into_iter()
            .filter_map(|p| {
                let (_, repo, unpushed, updated) = extra.iter().find(|e| e.0 == p.repo_id)?;
                Some(IssuePr {
                    repo_id: p.repo_id,
                    repo: repo.clone(),
                    state: p.phase.into(),
                    number: p.number,
                    url: p.url,
                    title: p.title,
                    head: p.head,
                    base: p.base,
                    head_sha: p.head_sha,
                    checks: p.checks,
                    checks_note: p.checks_note,
                    last_error: p.last_error,
                    push_held: p.push_held,
                    unpushed_at: opt_ts(unpushed.as_deref()),
                    updated_at: ts(updated),
                })
            })
            .collect(),
    ))
}

/// A spend window: `since` and `until` (RFC 3339); `until` defaults to now, `since` to a day
/// (by the hour) or 30 days (by the day) before it. `bucket` is `hour` (the default; at most a
/// week) or `day` (at most a year).
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SpendQuery {
    pub bucket: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
}

/// What some cost events spent. Dollars are the priced events' only: unpriced and subscription
/// spend is in tokens and runs, never $0.
#[derive(Debug, Serialize, ToSchema)]
pub struct Spend {
    pub cost_usd_micros: i64,
    pub priced_tokens: i64,
    pub unpriced_tokens: i64,
    pub unpriced_runs: i64,
    pub subscription_tokens: i64,
    pub subscription_runs: i64,
}

impl From<exec::Spend> for Spend {
    fn from(s: exec::Spend) -> Self {
        Self {
            cost_usd_micros: s.cost_usd_micros,
            priced_tokens: s.priced_tokens,
            unpriced_tokens: s.unpriced_tokens,
            unpriced_runs: s.unpriced_runs,
            subscription_tokens: s.subscription_tokens,
            subscription_runs: s.subscription_runs,
        }
    }
}

/// One bucket of a spend series.
#[derive(Debug, Serialize, ToSchema)]
pub struct SpendBucket {
    /// The bucket's start (an hour, or a day at midnight UTC).
    pub start: Timestamp,
    pub spend: Spend,
}

/// `since` and `until` normalised, with `default_days` back when `since` is absent; refused when
/// either is not a time, `since` is after `until`, or the window is longer than `max_days`.
pub(super) async fn window(
    app: &App,
    since: Option<&str>,
    until: Option<&str>,
    default_days: i64,
    max_days: f64,
) -> Result<(String, String), ApiError> {
    let now = app.clock.now();
    let (since, until, days): (Option<String>, Option<String>, Option<f64>) = sqlx::query_as(
        "WITH w (u) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', coalesce(?2, ?3))), \
         v (s, u) AS (SELECT strftime('%Y-%m-%dT%H:%M:%fZ', coalesce(?1, u), \
             CASE WHEN ?1 IS NULL THEN '-' || ?4 || ' days' ELSE '+0 seconds' END), u FROM w) \
         SELECT s, u, julianday(u) - julianday(s) FROM v",
    )
    .bind(since)
    .bind(until)
    .bind(&now)
    .bind(default_days)
    .fetch_one(&app.pool)
    .await?;
    let (Some(since), Some(until), Some(days)) = (since, until, days) else {
        return Err(ApiError::bad_request("since and until are RFC 3339 times"));
    };
    if !(0.0..=max_days).contains(&days) {
        let why = format!("since must be before until, and at most {max_days} days before it");
        return Err(ApiError::bad_request(why));
    }
    Ok((since, until))
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/spend", operation_id = "getSpendSeries",
    tag = "reads", params(("id" = i64, Path, description = "Company id"), SpendQuery),
    responses((status = 200, description = "The company's spend per hour or day in the window, \
        oldest first, every bucket present", body = Vec<SpendBucket>)))]
pub async fn spend_series(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<SpendQuery>,
) -> ApiResult<Vec<SpendBucket>> {
    let c = company(&app, id).await?;
    let (bucket, back, max) = match q.bucket.as_deref() {
        None | Some("hour") => (exec::Bucket::Hour, 1, 7.0),
        Some("day") => (exec::Bucket::Day, 30, 366.0),
        Some(other) => return Err(ApiError::bad_request(format!("unknown bucket {other:?}"))),
    };
    let (since, until) = window(&app, q.since.as_deref(), q.until.as_deref(), back, max).await?;
    let series = exec::spend_series(&app.pool, c.id, bucket, &since, &until).await?;
    Ok(Json(
        series
            .into_iter()
            .map(|(start, spend)| SpendBucket {
                start: ts(&start),
                spend: spend.into(),
            })
            .collect(),
    ))
}

/// A window of the cost ledger: `since` (default 30 days back) to `until` (default now), at
/// most a year.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Period {
    pub since: Option<String>,
    pub until: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AgentSpend {
    pub agent_id: i64,
    pub spend: Spend,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DepartmentSpend {
    /// Absent: agents in no team.
    pub department_id: Option<i64>,
    pub spend: Spend,
}

/// The Cost screen's "by agent · by department": every agent of the company (idle ones at
/// zero), and each department (an agent counts in its first team's department).
#[derive(Debug, Serialize, ToSchema)]
pub struct SpendBreakdown {
    pub since: Timestamp,
    pub until: Timestamp,
    pub agents: Vec<AgentSpend>,
    pub departments: Vec<DepartmentSpend>,
}

#[utoipa::path(get, path = "/api/v1/companies/{id}/costs/breakdown",
    operation_id = "getSpendBreakdown", tag = "reads",
    params(("id" = i64, Path, description = "Company id"), Period),
    responses((status = 200, description = "The company's spend in the window by agent and by \
        department", body = SpendBreakdown)))]
pub async fn spend_breakdown(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<Period>,
) -> ApiResult<SpendBreakdown> {
    let c = company(&app, id).await?;
    let (since, until) = window(&app, q.since.as_deref(), q.until.as_deref(), 30, 366.0).await?;
    let (agents, departments) = exec::spend_breakdown(&app.pool, c.id, &since, &until).await?;
    Ok(Json(SpendBreakdown {
        since: ts(&since),
        until: ts(&until),
        agents: agents
            .into_iter()
            .map(|(a, s)| AgentSpend {
                agent_id: a.0,
                spend: s.into(),
            })
            .collect(),
        departments: departments
            .into_iter()
            .map(|(d, s)| DepartmentSpend {
                department_id: d,
                spend: s.into(),
            })
            .collect(),
    }))
}
