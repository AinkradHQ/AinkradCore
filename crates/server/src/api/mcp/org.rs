//! The org tools (E6): `org_chart`, read-only, for any agent of the company (with its projects,
//! so the CEO can route a request to an existing one); `route_intake`,
//! for the CEO; `request_hire`, for a product owner, team lead, CTO or CEO.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::auth::RunScope;
use ainkrad_core::org::{AgentStatus, DepartmentId, NewAgent, OrgRole, TeamId};
use ainkrad_core::work::{Actor, ProjectId, ProjectMode};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, int, required, text};
use super::tools::company_issue;
use crate::api::App;
use crate::store::org::{OrgError, get_agent, hire_agent, org_chart as chart};
use crate::store::work::{IntakeError, MAX_ROUTES, Route, route_intake as route};

/// The run's company's org chart: agents, departments, teams and seats, and its projects (not
/// the intake project) with their owning team.
pub(super) async fn org_chart(app: &App, scope: RunScope) -> Result<Value> {
    let mut v = chart(&app.pool, scope.company_id)
        .await?
        .ok_or_else(|| ToolError::Refused("the run's company is gone".to_owned()))?;
    let projects: Vec<(i64, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, key, name, team_id FROM projects WHERE company_id = ? AND intake = 0 \
         ORDER BY id",
    )
    .bind(scope.company_id.0)
    .fetch_all(&app.pool)
    .await?;
    v["projects"] = projects
        .into_iter()
        .map(|(id, key, name, team)| json!({"id": id, "key": key, "name": name, "team_id": team}))
        .collect();
    Ok(v)
}

fn routes(args: &JsonObject) -> Result<Vec<Route>> {
    let invalid = |why: &str| ToolError::Invalid(why.to_owned());
    let Some(Value::Array(raw)) = args.get("routes") else {
        return Err(invalid(
            "routes must be a list of {project_id} or {department_id, name, key}",
        ));
    };
    if !(1..=MAX_ROUTES).contains(&raw.len()) {
        return Err(invalid("routes must hold 1 to 10 departments"));
    }
    let mut routes = vec![];
    for r in raw {
        let Value::Object(r) = r else {
            return Err(invalid(
                "each route is an object {project_id} or {department_id, name, key}",
            ));
        };
        if let Some(project) = int(r, "project_id")? {
            if ["department_id", "team_id", "name", "key", "mode"]
                .iter()
                .any(|k| r.contains_key(*k))
            {
                return Err(invalid(
                    "a route to an existing project gives only project_id",
                ));
            }
            routes.push(Route::Existing(ProjectId(project)));
            continue;
        }
        let department =
            int(r, "department_id")?.ok_or_else(|| invalid("department_id is required"))?;
        let mode = match text(r, "mode", 10)? {
            None => ProjectMode::Scrum,
            Some(m) => m
                .parse()
                .map_err(|_| invalid("mode must be scrum or kanban"))?,
        };
        routes.push(Route::New {
            department: DepartmentId(department),
            team: int(r, "team_id")?.map(TeamId),
            name: required(r, "name", MAX_TITLE)?.to_owned(),
            key: required(r, "key", 10)?.to_owned(),
            mode,
        });
    }
    Ok(routes)
}

/// Routes an intake request (default: the run's issue), as the company's CEO, to existing
/// projects and/or departments (a new project each, owned by its team); each project's product
/// owner gets the kickoff. The request closes; the CEO is out of the loop from there.
pub(super) async fn route_intake(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let ceo = get_agent(&app.pool, scope.agent_id).await?;
    if ceo.map(|a| a.org_role) != Some(OrgRole::Ceo) {
        return Err(ToolError::Refused(
            "only the CEO routes intake requests".to_owned(),
        ));
    }
    let asked = int(args, "issue_id")?.or(scope.issue_id.map(|i| i.0));
    let id = asked.ok_or_else(|| ToolError::Invalid("issue_id is required".to_owned()))?;
    let issue = company_issue(app, scope, id).await?;
    let routes = routes(args)?;
    let routed = match route(&app.pool, issue.id, Actor::Agent(scope.agent_id), &routes).await {
        Ok(r) => r,
        Err(IntakeError::Db(sqlx::Error::InvalidArgument(why))) => {
            return Err(ToolError::Invalid(why));
        }
        Err(e @ IntakeError::BadKey(_)) => return Err(ToolError::Invalid(e.to_string())),
        // Constraint text names tables and columns: logged, not shown to the agent.
        Err(IntakeError::Db(sqlx::Error::Database(d))) => {
            tracing::warn!(
                issue = issue.id.0,
                "route_intake refused by the database: {d}"
            );
            return Err(ToolError::Refused(
                "the routes break a rule of the org (check departments, teams and keys)".to_owned(),
            ));
        }
        Err(IntakeError::Db(e)) => return Err(e.into()),
        Err(e) => return Err(ToolError::Refused(e.to_string())),
    };
    let projects: Vec<Value> = routed
        .iter()
        .map(|r| {
            json!({"project_id": r.project.id.0, "key": r.project.key, "created": r.created,
                   "team_id": r.project.team_id.map(|t| t.0), "kickoff_issue_id": r.kickoff.id.0,
                   "product_owner": r.product_owner.0})
        })
        .collect();
    Ok(json!({"intake_issue_id": issue.id.0, "status": "routed", "projects": projects}))
}

/// The most runner tags a hire asks for.
const MAX_TAGS: usize = 10;

/// Asks a human to hire an agent (E6.4): it is added `pending_approval` with a `hire_agent`
/// approval and never runs until that is approved. For the company's CEO or CTO, or a product
/// owner or team lead of one of its teams.
pub(super) async fn request_hire(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let may: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agents a WHERE a.id = ?1 AND (a.org_role IN ('ceo', 'cto') \
         OR EXISTS (SELECT 1 FROM team_memberships m WHERE m.agent_id = a.id \
             AND m.team_role IN ('product_owner', 'team_lead'))))",
    )
    .bind(scope.agent_id.0)
    .fetch_one(&app.pool)
    .await?;
    if !may {
        return Err(ToolError::Refused(
            "only a product owner, team lead, CTO or CEO requests a hire".to_owned(),
        ));
    }
    let invalid = |why: &str| ToolError::Invalid(why.to_owned());
    let harness = required(args, "harness", 20)?
        .parse()
        .map_err(|_| invalid("harness must be claude, codex, opencode or agy"))?;
    let runner_tags = match args.get("runner_tags") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(tags)) if tags.len() <= MAX_TAGS => tags
            .iter()
            .map(|t| match t.as_str() {
                Some(t) if !t.trim().is_empty() && t.len() <= 50 => Ok(t.trim().to_owned()),
                _ => Err(invalid(
                    "each runner tag is a non-blank string of at most 50 bytes",
                )),
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(invalid("runner_tags must be a list of at most 10 strings")),
    };
    let new = NewAgent {
        company_id: scope.company_id,
        name: required(args, "name", MAX_TITLE)?.trim().to_owned(),
        role: required(args, "role", MAX_TITLE)?.trim().to_owned(),
        org_role: OrgRole::None,
        reports_to: None,
        harness,
        model: text(args, "model", MAX_TITLE)?
            .unwrap_or_default()
            .trim()
            .to_owned(),
        runner_tags,
        status: AgentStatus::PendingApproval,
    };
    let why = required(args, "justification", MAX_TEXT)?;
    let by = AuditActor::Agent(scope.agent_id);
    let now = app.clock.now();
    let hired = hire_agent(&app.pool, &new, Some(scope.agent_id), why, by, &now).await;
    let (agent, approval) = match hired {
        Ok(hired) => hired,
        Err(OrgError::Db(e)) => return Err(e.into()),
        Err(e) => return Err(ToolError::Refused(e.to_string())),
    };
    Ok(json!({"agent_id": agent.id.0, "approval_id": approval.id.0,
              "status": agent.status.as_str()}))
}
