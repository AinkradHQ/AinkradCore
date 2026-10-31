//! The planning tools (E5.4): sprints and estimates, for a project's product owner or team lead,
//! or the company's CEO or CTO (the same check as `list_backlog`). Each is a thin call into the
//! store as the run's agent, so the sprint rules still apply and every change is audited there.
//!
//! Not ported as tools: `assign_issue` (it wakes another agent: a run starting a run),
//! `commit_sprint` and `close_sprint` (they start and end a sprint, or skip its approval under
//! an agent-approval policy). Those stay with the signed client API.

use crate::domain::work::{Issue, IssueId, NewSprint, ProjectId, Sprint, SprintId, SprintState};
use crate::store::exec::RunScope;
use ainkrad_core::audit::AuditActor;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, int, required, text};
use super::tools::{company_issue, next_actor};
use crate::domain::gov::KnowledgeKind;
use ainkrad_core_server::api::App;

use crate::store::work::{
    RetroItem, SprintError, add_to_sprint, estimate_issue as estimate, get_issue as stored_issue,
    get_project, get_sprint, issue_key, may_read_backlog, plan_sprint as plan, propose_retro,
    remove_from_sprint, report_json, retro_items, set_sprint_issues as set_issues,
    sprint_report as report, sprint_review,
};

/// The project `asked` names (default: the run's issue's project), if it is in the run's
/// company and the agent may plan it.
pub(super) async fn planned_project(
    app: &App,
    scope: RunScope,
    asked: Option<i64>,
) -> Result<ProjectId> {
    let pool = &app.pool;
    let required = || ToolError::Invalid("project_id is required".to_owned());
    let project = match (asked, scope.issue_id) {
        (Some(id), _) => ProjectId(id),
        (None, Some(own)) => {
            stored_issue(pool, own)
                .await?
                .ok_or_else(required)?
                .project_id
        }
        (None, None) => return Err(required()),
    };
    match get_project(pool, project).await? {
        Some(p) if p.company_id == scope.company_id => {}
        _ => {
            let why = format!("no project {} in this company", project.0);
            return Err(ToolError::Refused(why));
        }
    }
    if !may_read_backlog(pool, scope.agent_id, project).await? {
        return Err(ToolError::Refused(
            "only the project's product owner or team lead, or the CEO or CTO, reads and \
             plans its backlog"
                .to_owned(),
        ));
    }
    Ok(project)
}

/// Sprint `id`, if the agent may plan its project; another company's looks like none.
async fn sprint(app: &App, scope: RunScope, id: i64) -> Result<Sprint> {
    let refused = || ToolError::Refused(format!("no sprint {id} in this company"));
    let s = get_sprint(&app.pool, SprintId(id))
        .await?
        .ok_or_else(refused)?;
    match get_project(&app.pool, s.project_id).await? {
        Some(p) if p.company_id == scope.company_id => {}
        _ => return Err(refused()),
    }
    planned_project(app, scope, Some(s.project_id.0)).await?;
    Ok(s)
}

/// Issue `id` of the company, if the agent may plan its project.
async fn issue(app: &App, scope: RunScope, id: i64) -> Result<Issue> {
    let i = company_issue(app, scope, id).await?;
    planned_project(app, scope, Some(i.project_id.0)).await?;
    Ok(i)
}

fn need(args: &JsonObject, key: &str) -> Result<i64> {
    int(args, key)?.ok_or_else(|| ToolError::Invalid(format!("{key} is required")))
}

fn sprint_json(s: &Sprint) -> Value {
    json!({"sprint_id": s.id.0, "project_id": s.project_id.0, "name": s.name, "goal": s.goal,
           "state": s.state.as_str(), "starts_on": s.starts_on, "ends_on": s.ends_on})
}

fn refused(e: SprintError) -> ToolError {
    match e {
        SprintError::Db(sqlx::Error::InvalidArgument(why)) => ToolError::Invalid(why),
        SprintError::Db(e) => e.into(),
        e => ToolError::Refused(e.to_string()),
    }
}

async fn issue_json(app: &App, i: &Issue) -> Result<Value> {
    Ok(
        json!({"issue_id": i.id.0, "key": issue_key(&app.pool, i.id).await?,
              "state": i.state.as_str(), "points": i.points,
              "sprint_id": i.sprint_id.map(|s| s.0), "next_actor": next_actor(&i.next_actor)}),
    )
}

/// An agent acts as `system` in the Core's audit; its id rides in the details of the call's row.
fn actor(_: RunScope) -> AuditActor {
    AuditActor::System
}

pub(super) async fn plan_sprint(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let project_id = planned_project(app, scope, int(args, "project_id")?).await?;
    let new = NewSprint {
        project_id,
        name: required(args, "name", MAX_TITLE)?.to_owned(),
        goal: text(args, "goal", MAX_TEXT)?.unwrap_or_default().to_owned(),
        state: SprintState::Planned,
        starts_on: Some(required(args, "starts_on", 10)?.to_owned()),
        ends_on: Some(required(args, "ends_on", 10)?.to_owned()),
    };
    let s = plan(&app.pool, &new, actor(scope)).await.map_err(refused)?;
    Ok(sprint_json(&s))
}

pub(super) async fn sprint_add_issue(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let s = sprint(app, scope, need(args, "sprint_id")?).await?;
    let i = issue(app, scope, need(args, "issue_id")?).await?;
    let added = add_to_sprint(&app.pool, s.id, i.id, actor(scope))
        .await
        .map_err(refused)?;
    issue_json(app, &added).await
}

pub(super) async fn sprint_remove_issue(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let i = issue(app, scope, need(args, "issue_id")?).await?;
    let removed = remove_from_sprint(&app.pool, i.id, actor(scope))
        .await
        .map_err(refused)?;
    issue_json(app, &removed).await
}

/// The most issues one `set_sprint_issues` call names.
const MAX_SPRINT_ISSUES: usize = 200;

/// Makes the planned sprint hold exactly `issue_ids`: the others go back to the backlog, in one
/// transaction (all or nothing).
pub(super) async fn set_sprint_issues(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let s = sprint(app, scope, need(args, "sprint_id")?).await?;
    let ids = match args.get("issue_ids") {
        Some(Value::Array(ids)) if ids.len() <= MAX_SPRINT_ISSUES => ids,
        _ => {
            return Err(ToolError::Invalid(format!(
                "issue_ids must be a list of at most {MAX_SPRINT_ISSUES} issue ids"
            )));
        }
    };
    let mut wanted = vec![];
    for id in ids {
        let id = id
            .as_i64()
            .ok_or_else(|| ToolError::Invalid("issue_ids must be integers".to_owned()))?;
        wanted.push(issue(app, scope, id).await?.id);
    }
    let (added, removed) = set_issues(&app.pool, s.id, &wanted, actor(scope))
        .await
        .map_err(refused)?;
    let ids = |v: Vec<IssueId>| v.into_iter().map(|i| i.0).collect::<Vec<_>>();
    Ok(
        json!({"sprint_id": s.id.0, "issue_ids": ids(wanted), "added": ids(added),
              "removed": ids(removed)}),
    )
}

pub(super) async fn estimate_issue(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let i = issue(app, scope, need(args, "issue_id")?).await?;
    let points = match int(args, "points")? {
        Some(p @ 0..=1000) => Some(p as u32),
        Some(_) => return Err(ToolError::Invalid("points must be 0 to 1000".to_owned())),
        None => None,
    };
    let estimated = estimate(&app.pool, i.id, points, actor(scope))
        .await
        .map_err(refused)?;
    issue_json(app, &estimated).await
}

pub(super) async fn sprint_report(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let s = sprint(app, scope, need(args, "sprint_id")?).await?;
    let r = report(&app.pool, s.id, &app.clock.now())
        .await?
        .ok_or_else(|| ToolError::Refused(format!("no sprint {} in this company", s.id.0)))?;
    let mut v = report_json(&r);
    v["name"] = s.name.into();
    v["goal"] = s.goal.into();
    v["review"] = sprint_review(&app.pool, s.id).await?.unwrap_or(Value::Null);
    v["retro"] = retro_items(&app.pool, s.id)
        .await?
        .iter()
        .map(|k| {
            json!({"id": k.id.0, "kind": k.kind.as_str(), "title": k.title,
                        "status": k.status.as_str()})
        })
        .collect();
    Ok(v)
}

/// The most retro items one call proposes.
const MAX_RETRO_ITEMS: usize = 20;

/// Proposes knowledge entries (decision, landmine or retro) from a closed sprint; they stay
/// proposed until a human accepts or rejects them (E8).
pub(super) async fn propose_retro_items(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let s = sprint(app, scope, need(args, "sprint_id")?).await?;
    let invalid = |why: &str| ToolError::Invalid(why.to_owned());
    let raw = match args.get("items") {
        Some(Value::Array(items)) if (1..=MAX_RETRO_ITEMS).contains(&items.len()) => items,
        _ => {
            return Err(invalid(
                "items must be a list of 1 to 20 {kind, title, body}",
            ));
        }
    };
    let mut items = vec![];
    for item in raw {
        let Value::Object(item) = item else {
            return Err(invalid("each item is an object {kind, title, body}"));
        };
        let kind = match required(item, "kind", MAX_TITLE)?.parse() {
            Ok(k @ (KnowledgeKind::Decision | KnowledgeKind::Landmine | KnowledgeKind::Retro)) => k,
            _ => return Err(invalid("kind must be decision, landmine or retro")),
        };
        items.push(RetroItem {
            kind,
            title: required(item, "title", MAX_TITLE)?.to_owned(),
            body: required(item, "body", MAX_TEXT)?.to_owned(),
        });
    }
    let proposed = propose_retro(&app.pool, s.id, &items, scope.agent_id)
        .await
        .map_err(refused)?;
    let ids: Vec<i64> = proposed.iter().map(|k| k.id.0).collect();
    Ok(json!({"knowledge_entry_ids": ids, "status": "proposed", "sprint_id": s.id.0}))
}
