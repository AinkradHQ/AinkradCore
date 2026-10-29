//! The tool list, the dispatch to each tool, the scope checks they share, and the audit of
//! every call.
//!
//! Scope: a tool reaches the run's own issue, or a subtask of it (`target`). An issue named
//! as a blocker must belong to the run's company (`company_issue`) and is only linked, never
//! changed. An issue the agent may not reach gets the same answer as one that does not exist,
//! so ids cannot be probed.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::auth::RunScope;
use ainkrad_core::work::{Issue, IssueId, NextActor};
use ainkrad_proto::redact::Redactor;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{Result, ToolError};
use super::{artifacts, forge, hub, org, plan, read, repos, requirements, roles, write};
use crate::api::App;
use crate::store::audit;
use crate::store::work::{get_issue, get_project, issue_key};

/// Runs tool `name` for `scope` and audits the call as the run's agent, refused or not.
pub(super) async fn call(
    app: &App,
    scope: RunScope,
    secrets: &Redactor,
    name: &str,
    args: &JsonObject,
) -> Result<Value> {
    let result = match name {
        "get_issue" => read::get_issue(app, scope, args).await,
        "get_context" => read::get_context(app, scope).await,
        "list_backlog" => read::list_backlog(app, scope, args).await,
        "org_chart" => org::org_chart(app, scope).await,
        "route_intake" => org::route_intake(app, scope, args).await,
        "request_hire" => org::request_hire(app, scope, args).await,
        "plan_requirement" => requirements::plan_requirement(app, scope, args).await,
        "apply_plan" => requirements::apply_plan(app, scope, args).await,
        "search_tools" => roles::search_tools(app, scope, args).await,
        "describe_tool" => roles::describe_tool(app, scope, args).await,
        "ask_human" => hub::ask_human(app, scope, args).await,
        "get_artifact" => artifacts::get_artifact(app, scope, args).await,
        "publish_artifact" => artifacts::publish_artifact(app, scope, secrets, args).await,
        "post_to_requirement" => hub::post_to_requirement(app, scope, args).await,
        "comment" => write::comment(app, scope, args).await,
        "transition" => write::transition(app, scope, args).await,
        "create_subtask" => write::create_subtask(app, scope, args).await,
        "report_blocker" => write::report_blocker(app, scope, args).await,
        "open_pr" => forge::open_pr(app, scope, args).await,
        "request_repo" => repos::request_repo(app, scope, args).await,
        "decide_repo" => repos::decide_repo(app, scope, args).await,
        "set_repos" => repos::set_repos(app, scope, args).await,
        "qa_verdict" => forge::qa_verdict(app, scope, args).await,
        "request_approval" => write::request_approval(app, scope, args).await,
        "get_approval" => read::get_approval(app, scope, args).await,
        "propose_knowledge" => write::propose_knowledge(app, scope, args).await,
        "review_knowledge" => write::review_knowledge(app, scope, args).await,
        "plan_sprint" => plan::plan_sprint(app, scope, args).await,
        "sprint_add_issue" => plan::sprint_add_issue(app, scope, args).await,
        "set_sprint_issues" => plan::set_sprint_issues(app, scope, args).await,
        "close_sprint" => plan::close_sprint(app, scope, args).await,
        "sprint_remove_issue" => plan::sprint_remove_issue(app, scope, args).await,
        "estimate_issue" => plan::estimate_issue(app, scope, args).await,
        "assign_issue" => plan::assign_issue(app, scope, args).await,
        "commit_sprint" => plan::commit_sprint(app, scope, args).await,
        "propose_retro_items" => plan::propose_retro_items(app, scope, args).await,
        "sprint_report" => plan::sprint_report(app, scope, args).await,
        _ => Err(ToolError::Invalid("no such tool".to_owned())),
    };
    let known = !matches!(&result, Err(ToolError::Invalid(why)) if why == "no such tool");
    if let Err(ToolError::Failed(detail)) = &result {
        tracing::error!(tool = name, run = scope.run_id.0, %detail, "tool failed");
    }
    let event = NewAuditEvent {
        actor: AuditActor::Agent(scope.agent_id),
        // Only known names reach the log; anything else an agent sends is `mcp.unknown_tool`.
        action: format!("mcp.{}", if known { name } else { "unknown_tool" }),
        entity: scope.issue_id.map(|i| AuditEntity {
            kind: "issue".to_owned(),
            id: i.0,
        }),
        company_id: Some(scope.company_id),
        run_id: Some(scope.run_id),
        details: json!({"ok": result.is_ok(),
                        "error": result.as_ref().err().map(ToString::to_string)})
        .to_string(),
    };
    // ponytail: appended after the tool's own transaction, so a crash in between loses this
    // row (the write's own audit, e.g. `issue.<state>`, still stands). One transaction per call
    // is the upgrade if the trail must be exact.
    if let Err(e) = audit::append(&app.pool, &event).await {
        tracing::error!(tool = name, run = scope.run_id.0, error = %e, "auditing a tool call failed");
    }
    result
}

/// The run's own issue, or the subtask of it `asked` names.
pub(super) async fn target(app: &App, scope: RunScope, asked: Option<i64>) -> Result<Issue> {
    let own = scope
        .issue_id
        .ok_or_else(|| ToolError::Refused("this run has no issue".to_owned()))?;
    let id = asked.map_or(own, IssueId);
    match get_issue(&app.pool, id).await? {
        Some(issue) if issue.id == own || issue.parent_id == Some(own) => Ok(issue),
        _ => Err(ToolError::Refused(format!(
            "issue {} is not this run's issue or one of its subtasks",
            id.0
        ))),
    }
}

/// Like `target`, for reading: also any issue of the run's own requirement.
pub(super) async fn readable(app: &App, scope: RunScope, asked: Option<i64>) -> Result<Issue> {
    let own = scope
        .issue_id
        .ok_or_else(|| ToolError::Refused("this run has no issue".to_owned()))?;
    let id = asked.map_or(own, IssueId);
    let mine = get_issue(&app.pool, own).await?;
    match (get_issue(&app.pool, id).await?, mine) {
        (Some(issue), Some(mine))
            if issue.id == own
                || issue.parent_id == Some(own)
                || (mine.requirement_id.is_some()
                    && issue.requirement_id == mine.requirement_id) =>
        {
            Ok(issue)
        }
        _ => Err(ToolError::Refused(format!(
            "issue {} is not this run's issue, one of its subtasks or on its requirement",
            id.0
        ))),
    }
}

/// Issue `id`, if it belongs to the run's company.
pub(super) async fn company_issue(app: &App, scope: RunScope, id: i64) -> Result<Issue> {
    let refused = || ToolError::Refused(format!("no issue {id} in this company"));
    let issue = get_issue(&app.pool, IssueId(id))
        .await?
        .ok_or_else(refused)?;
    match get_project(&app.pool, issue.project_id).await? {
        Some(p) if p.company_id == scope.company_id => Ok(issue),
        _ => Err(refused()),
    }
}

/// `{id, key, title, state}` of an issue.
pub(super) async fn summary(app: &App, issue: &Issue) -> Result<Value> {
    Ok(
        json!({"id": issue.id.0, "key": issue_key(&app.pool, issue.id).await?,
              "title": issue.title, "state": issue.state.as_str()}),
    )
}

/// A next actor as JSON: `{"agent": id}`, `{"user": id}`, `{"timer": at}` or `null`.
pub(super) fn next_actor(next: &Option<NextActor>) -> Value {
    match next {
        Some(NextActor::Agent(a)) => json!({"agent": a.0}),
        Some(NextActor::Human(u)) => json!({"user": u.0}),
        Some(NextActor::Timer(at)) => json!({"timer": at}),
        None => Value::Null,
    }
}
