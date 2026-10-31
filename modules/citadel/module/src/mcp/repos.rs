//! `request_repo` (E15.16): an agent that finds it needs another repo of its project mid-task
//! asks. It never grants itself the repo: the team lead decides, through the signed client API.
//! Not ported as tools: `set_repos` and `decide_repo` (they widen what a run may touch).

use crate::store::exec::RunScope;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, required};
use super::tools::{reserve, target};
use crate::store::work::request_repo as request;
use ainkrad_core_server::api::App;

fn refused(e: sqlx::Error) -> ToolError {
    match e {
        sqlx::Error::InvalidArgument(why) => ToolError::Refused(why),
        e => e.into(),
    }
}

pub(super) async fn request_repo(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let repo = required(args, "repo", MAX_TITLE)?;
    let why = required(args, "reason", MAX_TEXT)?;
    reserve(
        app,
        scope,
        "repo_request",
        1,
        "mcp.max_repo_requests_per_run",
    )
    .await?;
    request(&app.pool, issue.id, repo, scope.agent_id, why)
        .await
        .map_err(refused)?;
    Ok(json!({"repo": repo, "status": "requested",
              "note": "The team lead decides; you are woken with the answer. Approved, your \
                       next run has the repo's worktree."}))
}
