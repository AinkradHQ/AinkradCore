//! The requirement tools (E15.10): `plan_requirement`, for a requirement's planners (its
//! projects' product owners and team leads, the CEO, the CTO): file its epics and tasks, read
//! what keeps the plan from being complete, and submit it for approval (plan-first).

use ainkrad_core::auth::RunScope;
use ainkrad_core::org::AgentId;
use ainkrad_core::work::{
    EpicId, IssueId, NewSprint, ProjectId, RequirementId, SprintId, SprintState,
};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, int, required, text};
use super::plan::planned_project;
use super::tools::summary;
use crate::api::App;
use crate::store::work::{
    ApplyEpic, ApplyError, ApplySprint, ApplyTask, NewPlanEpic, PlannedTask, Requirement,
    RequirementError, Submitted, apply_plan as store_apply, get_issue, get_requirement, get_sprint,
    plan_requirement as plan, submit_plan,
};

/// The most epics, or tasks, one call files.
const MAX_ITEMS: usize = 50;

/// The requirement `asked` names (default: the run's issue's), if it is the run's company's.
pub(super) async fn requirement(
    app: &App,
    scope: RunScope,
    asked: Option<i64>,
) -> Result<Requirement> {
    let id = match (asked, scope.issue_id) {
        (Some(id), _) => Some(id),
        (None, Some(own)) => get_issue(&app.pool, own)
            .await?
            .and_then(|i| i.requirement_id)
            .map(|r| r.0),
        (None, None) => None,
    };
    let id = id.ok_or_else(|| {
        ToolError::Invalid("requirement_id is required: the run's issue has none".to_owned())
    })?;
    match get_requirement(&app.pool, RequirementId(id)).await? {
        Some(r) if r.company_id == scope.company_id => Ok(r),
        _ => Err(ToolError::Refused(format!(
            "no requirement {id} in this company"
        ))),
    }
}

fn refused(e: RequirementError) -> ToolError {
    match e {
        RequirementError::Db(sqlx::Error::InvalidArgument(why)) => ToolError::Invalid(why),
        RequirementError::Db(e) => e.into(),
        e => ToolError::Refused(e.to_string()),
    }
}

fn list<'a>(args: &'a JsonObject, key: &str) -> Result<&'a [Value]> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) if a.len() <= MAX_ITEMS => Ok(a),
        Some(Value::Array(_)) => Err(ToolError::Invalid(format!(
            "{key} holds at most {MAX_ITEMS} items"
        ))),
        Some(_) => Err(ToolError::Invalid(format!("{key} must be a list"))),
    }
}

fn object(v: &Value) -> Result<&JsonObject> {
    v.as_object()
        .ok_or_else(|| ToolError::Invalid("each epic and task is an object".to_owned()))
}

fn task<'a>(t: &'a JsonObject, epic: Option<EpicId>) -> Result<PlannedTask<'a>> {
    let points = match int(t, "points")? {
        Some(p) if !(0..=1000).contains(&p) => {
            return Err(ToolError::Invalid("points must be 0 to 1000".to_owned()));
        }
        p => p.map(|p| p as u32),
    };
    Ok(PlannedTask {
        epic,
        title: required(t, "title", MAX_TITLE)?,
        body: text(t, "body", MAX_TEXT)?.unwrap_or_default(),
        points,
        assignee: int(t, "assignee_agent_id")?.map(AgentId),
    })
}

/// Where a new epic goes unless it names a project: the run's issue's project when it carries
/// the requirement, else the first project made for or routed to it.
async fn default_project(app: &App, scope: RunScope, r: &Requirement) -> Result<Option<i64>> {
    if let Some(own) = scope.issue_id
        && let Some(i) = get_issue(&app.pool, own).await?
        && i.requirement_id == Some(r.id)
        && Some(i.id) != r.intake_issue_id
    {
        return Ok(Some(i.project_id.0));
    }
    Ok(sqlx::query_scalar(
        "SELECT min(id) FROM projects WHERE intake = 0 AND (requirement_id = ?1 \
             OR id IN (SELECT project_id FROM issues WHERE requirement_id = ?1))",
    )
    .bind(r.id.0)
    .fetch_one(&app.pool)
    .await?)
}

pub(super) async fn plan_requirement(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let r = requirement(app, scope, int(args, "requirement_id")?).await?;
    let fallback = default_project(app, scope, &r).await?;
    let mut epics = vec![];
    for e in list(args, "epics")? {
        let e = object(e)?;
        let project = int(e, "project_id")?.or(fallback).ok_or_else(|| {
            ToolError::Invalid("project_id is required: the requirement has no project".to_owned())
        })?;
        let mut tasks = vec![];
        for t in list(e, "tasks")? {
            tasks.push(task(object(t)?, None)?);
        }
        epics.push(NewPlanEpic {
            project: ProjectId(project),
            title: required(e, "title", MAX_TITLE)?,
            tasks,
        });
    }
    let mut tasks = vec![];
    for t in list(args, "tasks")? {
        let t = object(t)?;
        let epic = int(t, "epic_id")?
            .ok_or_else(|| ToolError::Invalid("a task needs epic_id".to_owned()))?;
        tasks.push(task(t, Some(EpicId(epic)))?);
    }
    let planned = plan(&app.pool, r.id, scope.agent_id, &epics, &tasks)
        .await
        .map_err(refused)?;
    let mut out = json!({"requirement_id": r.id.0, "key": r.key(),
        "epics": planned.epics.iter().map(|e| e.0).collect::<Vec<_>>(),
        "tasks": planned.tasks.iter().map(|t| t.0).collect::<Vec<_>>(),
        "problems": planned.problems});
    submit(app, scope, &r, args, &mut out).await?;
    Ok(out)
}

/// With `submit: true`, submits the plan into `out.submitted`; `out.state` is the requirement's.
async fn submit(
    app: &App,
    scope: RunScope,
    r: &Requirement,
    args: &JsonObject,
    out: &mut Value,
) -> Result<()> {
    if args.get("submit") == Some(&Value::Bool(true)) {
        let now = app.clock.now();
        out["submitted"] =
            match submit_plan(&app.pool, r.id, scope.agent_id, scope.issue_id, &now).await {
                Ok(Submitted::Approved(v)) => json!({"status": "approved", "version": v}),
                Ok(Submitted::Pending(a)) => {
                    json!({"status": "pending_approval", "approval_id": a.id.0})
                }
                Err(e) => json!({"status": "refused", "reason": refused(e).to_string()}),
            };
    }
    // The ids an agent plans with next: each new task as {id, key, title, state}, and the
    // sprint. Built from the result, so a replayed `apply_plan` carries them too.
    let mut issues = vec![];
    for id in out["tasks"].as_array().into_iter().flatten() {
        if let Some(i) = id.as_i64()
            && let Some(i) = get_issue(&app.pool, IssueId(i)).await?
        {
            issues.push(summary(app, &i).await?);
        }
    }
    out["issues"] = issues.into();
    if let Some(id) = out["sprint_id"].as_i64()
        && let Some(s) = get_sprint(&app.pool, SprintId(id)).await?
    {
        out["sprint"] = json!({"sprint_id": s.id.0, "name": s.name, "state": s.state.as_str()});
    }
    let state = get_requirement(&app.pool, r.id).await?.map(|r| r.state);
    out["state"] = json!(state.map(|s| s.as_str()));
    Ok(())
}

/// A task's repo names.
fn repos(t: &JsonObject) -> Result<Vec<String>> {
    match t.get("repos") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(all)) if all.len() <= MAX_ITEMS => all
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or_else(|| ToolError::Invalid("repos must be names".to_owned())),
        Some(_) => Err(ToolError::Invalid(
            "repos must be a list of names".to_owned(),
        )),
    }
}

/// The plan's sprint: `sprint_id`, or a new one in `project_id` (default `fallback`).
async fn sprint(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
    fallback: Option<i64>,
) -> Result<Option<ApplySprint>> {
    let s = match args.get("sprint") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(s)) => s,
        Some(_) => return Err(ToolError::Invalid("sprint must be an object".to_owned())),
    };
    if let Some(id) = int(s, "sprint_id")? {
        return Ok(Some(ApplySprint::Existing(SprintId(id))));
    }
    let project = planned_project(app, scope, int(s, "project_id")?.or(fallback)).await?;
    Ok(Some(ApplySprint::New(NewSprint {
        project_id: project,
        name: required(s, "name", MAX_TITLE)?.to_owned(),
        goal: text(s, "goal", MAX_TEXT)?.unwrap_or_default().to_owned(),
        state: SprintState::Planned,
        starts_on: Some(required(s, "starts_on", 10)?.to_owned()),
        ends_on: Some(required(s, "ends_on", 10)?.to_owned()),
    })))
}

/// `apply_plan` (E15.18): the whole plan in one transaction; see `store::work::apply_plan`.
pub(super) async fn apply_plan(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let r = requirement(app, scope, int(args, "requirement_id")?).await?;
    let fallback = default_project(app, scope, &r).await?;
    let key = text(args, "idempotency_key", MAX_TITLE)?;
    let mut epics = vec![];
    for e in list(args, "epics")? {
        let e = object(e)?;
        let mut tasks = vec![];
        for t in list(e, "tasks")? {
            let t = object(t)?;
            tasks.push(ApplyTask {
                task: task(t, None)?,
                repos: repos(t)?,
                sprint: t.get("sprint") != Some(&Value::Bool(false)),
            });
        }
        epics.push(match int(e, "epic_id")? {
            Some(id) => ApplyEpic::Existing {
                epic: EpicId(id),
                tasks,
            },
            None => {
                let project = int(e, "project_id")?.or(fallback);
                // The same check as each planning tool's: the agent plans this project.
                ApplyEpic::New {
                    project: planned_project(app, scope, project).await?,
                    title: required(e, "title", MAX_TITLE)?,
                    tasks,
                }
            }
        });
    }
    let sprint = sprint(app, scope, args, fallback).await?;
    let applied = store_apply(
        &app.pool,
        r.id,
        scope.agent_id,
        key,
        &epics,
        sprint.as_ref(),
    )
    .await;
    let mut out = match applied {
        Ok(out) => out,
        Err(ApplyError::Refused(e)) => return Err(refused(e)),
        Err(ApplyError::Invalid(items)) => {
            return Err(ToolError::Invalid(format!(
                "nothing was filed; {} problem(s): {}",
                items.len(),
                items.join("; ")
            )));
        }
    };
    submit(app, scope, &r, args, &mut out).await?;
    Ok(out)
}
