//! The dispatch to each tool, the scope checks they share and the audit of every call.
//!
//! The tool list is a fixed allow-list: a name that is not in it is refused (`mcp.unknown_tool`).
//! Scope: a tool reaches the run's own issue, or a subtask of it (`target`). An issue named as a
//! blocker must belong to the run's company (`company_issue`) and is only linked, never changed.
//! An issue the agent may not reach gets the same answer as one that does not exist, so ids
//! cannot be probed. Each call counts against the run's `mcp.max_calls_per_run` in the statement
//! that checks it.

use ainkrad_core::audit::AuditActor;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{Result, ToolError};
use super::{read, write};
use crate::domain::work::{Issue, IssueId, NextActor};
use crate::store::audit::{self, Event};
use crate::store::exec::RunScope;
use crate::store::work::{get_issue, get_project, issue_key};
use ainkrad_core_server::api::App;

/// Every tool a run may call. Nothing else is dispatched.
pub(super) const TOOLS: &[&str] = &[
    "get_issue",
    "get_context",
    "comment",
    "transition",
    "create_subtask",
    "report_blocker",
    "request_approval",
    "get_approval",
];

/// Counts one call for the run, refusing past the cap.
async fn count(app: &App, scope: RunScope) -> Result<()> {
    let max = crate::settings::value(&app.pool, "mcp.max_calls_per_run").await?;
    let counted: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_runs SET mcp_calls = mcp_calls + 1 WHERE id = ? AND mcp_calls < ? \
         RETURNING mcp_calls",
    )
    .bind(scope.run_id.0)
    .bind(max)
    .fetch_optional(&app.pool)
    .await?;
    counted.map(drop).ok_or_else(|| {
        ToolError::Refused(format!(
            "this run has used its {max} tool calls (mcp.max_calls_per_run)"
        ))
    })
}

/// Counts one issue or approval created by the run, refusing past `mcp.max_creates_per_run`
/// (B-M4: a poisoned issue cannot fan out into other agents' prompts without bound).
pub(super) async fn count_create(app: &App, scope: RunScope) -> Result<()> {
    let max = crate::settings::value(&app.pool, "mcp.max_creates_per_run").await?;
    let counted: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_runs SET mcp_creates = mcp_creates + 1 WHERE id = ? AND mcp_creates < ? \
         RETURNING mcp_creates",
    )
    .bind(scope.run_id.0)
    .bind(max)
    .fetch_optional(&app.pool)
    .await?;
    counted.map(drop).ok_or_else(|| {
        ToolError::Refused(format!(
            "this run has created {max} issues and approvals (mcp.max_creates_per_run)"
        ))
    })
}

/// Whether the run already has an `mcp.unknown_tool` row (a failed read counts as yes: no row).
async fn unknown_audited(app: &App, scope: RunScope) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM audit_events WHERE action = 'citadel.mcp.unknown_tool' \
         AND json_extract(details, '$.run_id') = ?)",
    )
    .bind(scope.run_id.0)
    .fetch_one(&app.pool)
    .await
    .unwrap_or(true)
}

/// `args` with every string run through the Core's redactor (keys of known shapes included).
fn redacted(args: &JsonObject) -> JsonObject {
    let mut v = Value::Object(args.clone());
    ainkrad_proto::redact::Redactor::new().json(&mut v);
    match v {
        Value::Object(o) => o,
        _ => JsonObject::new(),
    }
}

/// Runs tool `name` for `scope` and audits the call as the run's agent, refused or not.
pub(super) async fn call(
    app: &App,
    scope: RunScope,
    name: &str,
    args: &JsonObject,
) -> Result<Value> {
    let known = TOOLS.contains(&name);
    // Nothing an agent writes is stored as it sent it: a key it holds or a shape of one is
    // redacted before it reaches an issue, a comment or an approval (B-M2).
    let args = &redacted(args);
    // Every name counts, an unknown one too: the cap bounds what a run can make the Core do.
    let result = if let Err(e) = count(app, scope).await {
        Err(e)
    } else if !known {
        Err(ToolError::Invalid("no such tool".to_owned()))
    } else {
        match name {
            "get_issue" => read::get_issue(app, scope, args).await,
            "get_context" => read::get_context(app, scope).await,
            "get_approval" => read::get_approval(app, scope, args).await,
            "comment" => write::comment(app, scope, args).await,
            "transition" => write::transition(app, scope, args).await,
            "create_subtask" => write::create_subtask(app, scope, args).await,
            "report_blocker" => write::report_blocker(app, scope, args).await,
            "request_approval" => write::request_approval(app, scope, args).await,
            _ => Err(ToolError::Invalid("no such tool".to_owned())),
        }
    };
    if let Err(ToolError::Failed(detail)) = &result {
        tracing::error!(tool = name, run = scope.run_id.0, %detail, "tool failed");
    }
    // Only known names reach the audit; anything else an agent sends is `mcp.unknown_tool`,
    // written once per run (the first), so a loop of junk names cannot grow the trail.
    if !known && unknown_audited(app, scope).await {
        tracing::warn!(run = scope.run_id.0, "unknown tool name (already audited)");
        return result;
    }
    let action = format!("mcp.{}", if known { name } else { "unknown_tool" });
    let mut event = Event::new(AuditActor::System, &action)
        .company(scope.company_id.0)
        .run(scope.run_id.0)
        .details(json!({"agent_id": scope.agent_id.0, "ok": result.is_ok(),
                        "error": result.as_ref().err().map(ToString::to_string)}));
    if let Some(i) = scope.issue_id {
        event = event.entity("issue", i.0);
    }
    // ponytail: appended after the tool's own transaction, so a crash in between loses this row
    // (the write's own audit, e.g. `issue.<state>`, still stands). One transaction per call is
    // the upgrade if the trail must be exact.
    let audited = async {
        let mut tx = ainkrad_core_server::store::begin_write(&app.pool).await?;
        audit::append(&mut tx, event).await?;
        tx.commit().await
    };
    if let Err(e) = audited.await {
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
