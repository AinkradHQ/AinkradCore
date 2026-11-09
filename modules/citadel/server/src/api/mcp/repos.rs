//! The repo tools (E15.16): which of its project's repos an issue touches. A planner (the
//! project's product owner or team lead) sets them (`set_repos`); an agent that finds it needs
//! another repo mid-task asks (`request_repo`), and the team lead decides (`decide_repo`, #55).

use citadel_core::audit::AuditActor;
use citadel_core::auth::RunScope;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, int, required, text};
use super::plan::planned_project;
use super::tools::{company_issue, target};
use crate::api::App;
use crate::store::work::{decide_repo as decide, request_repo as request, set_issue_repos};

fn refused(e: sqlx::Error) -> ToolError {
    match e {
        sqlx::Error::InvalidArgument(why) => ToolError::Refused(why),
        e => e.into(),
    }
}

/// The issue named by `issue_id`, else the run's own.
async fn issue_of(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<citadel_core::work::Issue> {
    match int(args, "issue_id")? {
        Some(id) => company_issue(app, scope, id).await,
        None => target(app, scope, None).await,
    }
}

pub(super) async fn set_repos(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = issue_of(app, scope, args).await?;
    planned_project(app, scope, Some(issue.project_id.0)).await?;
    let names: Vec<String> = match args.get("repos") {
        Some(Value::Array(all)) => all
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or_else(|| ToolError::Invalid("repos must be names".to_owned()))?,
        _ => return Err(ToolError::Invalid("repos is required".to_owned())),
    };
    let by = AuditActor::Agent(scope.agent_id);
    let now = set_issue_repos(&app.pool, issue.id, &names, by)
        .await
        .map_err(refused)?;
    Ok(json!({"repos": now.iter().map(|r| &r.name).collect::<Vec<_>>()}))
}

pub(super) async fn request_repo(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let repo = required(args, "repo", MAX_TITLE)?;
    let why = required(args, "reason", MAX_TEXT)?;
    request(&app.pool, issue.id, repo, scope.agent_id, why)
        .await
        .map_err(refused)?;
    Ok(json!({"repo": repo, "status": "requested",
              "note": "The team lead decides; you are woken with the answer. Approved, your \
                       next run has the repo's worktree."}))
}

pub(super) async fn decide_repo(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = issue_of(app, scope, args).await?;
    let repo = required(args, "repo", MAX_TITLE)?;
    let approve = match required(args, "verdict", MAX_TITLE)? {
        "approve" => true,
        "reject" => false,
        _ => {
            return Err(ToolError::Invalid(
                "verdict must be approve or reject".to_owned(),
            ));
        }
    };
    let reply = text(args, "reason", MAX_TEXT)?;
    let by = AuditActor::Agent(scope.agent_id);
    decide(&app.pool, issue.id, repo, approve, by, reply)
        .await
        .map_err(refused)?;
    let status = if approve { "approved" } else { "rejected" };
    Ok(json!({"repo": repo, "status": status}))
}
