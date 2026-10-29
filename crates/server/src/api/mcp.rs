//! The Citadel MCP server (E4.2, decision #24): the only way an agent reads and changes Citadel.
//! Served at `/mcp/v1` over Streamable HTTP by the official SDK (`rmcp`), stateless: each POST
//! stands alone, so every tool call is checked against the run token it carries, and nothing
//! of a session outlives the request. Replies are plain JSON.
//!
//! The gate in `api` has already checked the Host, Origin and query string, and turned the
//! `Authorization: Bearer <run token>` into a `RunScope` (401 on an unknown, expired or revoked
//! token, or a run that is not running). The tools (`tools`) reach the run's issue and that
//! issue's subtasks, and nothing else; each call is audited as the run's agent.
//!
//! The run's `citadel` CLI (E15.18) reaches the same tools through `/mcp/v1/call/<op>`
//! (`cli`), behind the same gate.
//!
//! Unlike Paperclip, where agents learned a REST API from a skill and held broad API keys, an
//! agent here is handed a typed tool list and a token that dies with its run.

use std::sync::Arc;

use ainkrad_core::auth::RunScope;
use axum::http::request::Parts;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};

use super::App;

mod args;
mod artifacts;
mod cli;
mod defs;
mod forge;
mod hub;
mod org;
mod plan;
mod read;
mod repos;
mod requirements;
mod roles;
mod tools;
mod write;

#[cfg(test)]
mod tests;

const INSTRUCTIONS: &str = "Citadel tracks the issue you are working on. Read it with \
    get_issue, your project's knowledge and skills with get_context, and your company's \
    org with org_chart. Report progress with \
    comment, and move the issue with transition (start, submit_for_review, block, done) while \
    you are its next actor. You can only reach your run's issue and its subtasks; a product \
    owner, team lead, CEO or CTO can also read a project's backlog with list_backlog and plan \
    its sprints: plan_sprint, sprint_add_issue, sprint_remove_issue, estimate_issue, \
    assign_issue, commit_sprint, sprint_report and propose_retro_items. The CEO routes intake \
    requests with route_intake: to an existing project when the request is about one (org_chart \
    lists the company's projects), else to departments as new projects. A request is a requirement: its planners file its \
    epics and tasks and submit the plan with plan_requirement, and no dev work on it starts \
    until that plan is approved. Ask the admin something only a person can answer with \
    ask_human: the answer comes back to you; the requirement's owner writes in its thread with \
    post_to_requirement. Publish a report, file or screenshot for the admin with \
    publish_artifact. A product owner, team lead, CTO or CEO asks a \
    human to hire an agent with request_hire. Ask a human to approve something with \
    request_approval; you are woken with the decision and its reply, and get_approval reads \
    it. On a project with a forge, ask for your issue's pull request with open_pr (title, body, \
    and the repo when the issue touches several: one worktree and one PR each); ask for another \
    repo with request_repo, which its team lead decides with decide_repo. A PR opens from your \
    branch when your run ends, and done then goes to QA, whose \
    qa_verdict (pass or fail) asks the owner to merge or sends it back. Propose what others should know (a decision, landmine, state, or a new project spec) \
    with propose_knowledge; a team lead reviews proposals (get_context lists them) with \
    review_knowledge. Your tool list holds your role's tools; search_tools finds any other \
    and describe_tool reads its arguments (each tool still checks your permission). A planner \
    files a whole plan in one call with apply_plan: epics, tasks with estimates, assignees and \
    repos, a sprint for them, and the submit.";

pub(super) use cli::call as cli_call;

/// The run's secrets the server knows (its token), redacted from what its agent publishes. No
/// `Debug`: it holds the token.
#[derive(Clone)]
pub(super) struct RunSecrets(pub Arc<ainkrad_proto::redact::Redactor>);

/// The run the request's token belongs to (set by the gate).
fn run_scope(context: &RequestContext<RoleServer>) -> Result<RunScope, ErrorData> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<RunScope>())
        .copied()
        .ok_or_else(|| ErrorData::internal_error("no run scope on the request", None))
}

/// One request's handler: the app, and nothing per agent (the scope comes with each request).
#[derive(Clone)]
pub(super) struct Citadel {
    app: App,
}

/// The `/mcp/v1` service. The gate runs before it, so its own Host and Origin checks are off.
pub(super) fn service(app: App) -> StreamableHttpService<Citadel, NeverSessionManager> {
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .disable_allowed_hosts()
        .disable_allowed_origins();
    StreamableHttpService::new(
        move || Ok(Citadel { app: app.clone() }),
        Arc::new(NeverSessionManager::default()),
        config,
    )
}

impl ServerHandler for Citadel {
    fn get_info(&self) -> ServerConfig {
        let capabilities = ServerCapabilities::builder().enable_tools().build();
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("citadel", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let scope = run_scope(&context)?;
        let tools = roles::listed(&self.app, scope).await.map_err(|e| {
            tracing::error!(run = scope.run_id.0, error = %e, "listing tools failed");
            ErrorData::internal_error("listing tools failed", None)
        })?;
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let parts = context.extensions.get::<Parts>();
        let scope = run_scope(&context)?;
        let secrets = parts
            .and_then(|parts| parts.extensions.get::<RunSecrets>())
            .map(|s| s.0.clone())
            .unwrap_or_default();
        let args = request.arguments.unwrap_or_default();
        let result = match tools::call(&self.app, scope, &secrets, &request.name, &args).await {
            Ok(value) => CallToolResult::success(vec![ContentBlock::text(value.to_string())]),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(e.to_string())]),
        };
        Ok(result.into())
    }
}
