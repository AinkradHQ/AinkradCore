//! The Citadel MCP server (S8): the only way an agent in a run reads and changes Citadel. A token
//! route of the module (`Module::token_routes`), served at `/token/citadel/v1/mcp` behind the
//! Core's token gate (`ainkrad_core_server::gateway::token`: host, no origin or cookie, no query,
//! body cap, lockout, rate limit) and authenticated by the run's token alone, never a device
//! signature. Stateless Streamable HTTP over the official SDK (`rmcp`): every POST stands alone
//! and is checked against the run it names, so a token that dies with its run stops working at
//! once.
//!
//! - [`verify`]: the Core hands the bearer to `Module::verify_token`; a live, unrevoked,
//!   unexpired token of a running run becomes a [`RunScope`] (one run, its agent, issue, company)
//!   the tools read from.
//! - [`credentials`]: at every launch of one of the module's sessions the run gets a fresh token,
//!   delivered by the Core's credential channel (memory only, one redemption by the session's
//!   runner), when `mcp.enabled` is on. Not stored in the session row, transcript, events, audit
//!   or logs.
//! - the tools (`tools`): a run's own issue and its subtasks, in its company, nothing else.
//!   No tool decides an approval, touches a secret or credential, or controls a run: those stay
//!   behind the signed client API with a step-up.

use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::module::{Credential, TokenGrant, TokenPrincipal, TokenRoute, Zeroizing};
use ainkrad_core_server::store::agents::Session;
use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::{MethodRouter, post};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};

use crate::domain::work::RunId;
use crate::store::exec::{RunScope, authorize_run_token, issue_run_token};

mod args;
mod defs;
mod read;
mod tools;
mod write;

/// The variable the Core delivers the token under, and the runner recognises it by.
pub const RUN_TOKEN_VAR: &str = "CITADEL_RUN_TOKEN";

/// The largest request body: a tool call's arguments (a comment is at most 32 KiB of text).
pub const MAX_BODY: usize = 256 * 1024;

/// The module's token routes, the whole of its unsigned surface.
pub const ROUTES: &[TokenRoute] = &[TokenRoute {
    method: "POST",
    template: "/mcp",
    max_body: MAX_BODY,
}];

/// The handler of a declared route.
pub fn handler(method: &str, template: &str) -> Option<MethodRouter<App>> {
    match (method, template) {
        ("POST", "/mcp") => Some(post(serve)),
        _ => None,
    }
}

async fn serve(State(app): State<App>, req: Request) -> Response {
    service(app).handle(req).await.map(axum::body::Body::new)
}

/// `Module::verify_token`: the run scope of a live token, else nothing (the gate answers one 401).
pub async fn verify(app: &App, token: &str) -> Option<TokenGrant> {
    // `mcp.enabled` is a kill switch: off refuses every token already issued, at once.
    match crate::settings::value(&app.pool, "mcp.enabled").await {
        Ok(0) => {
            tracing::warn!(why = "mcp is off", "run token refused");
            return None;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(why = %e, "run token refused");
            return None;
        }
    }
    match authorize_run_token(&app.pool, token, &app.clock.now()).await {
        Ok(scope) => Some(TokenGrant {
            key: format!("run:{}", scope.run_id.0),
            principal: Arc::new(scope),
        }),
        Err(e) => {
            // Never the token: only why.
            tracing::warn!(why = %e, "run token refused");
            None
        }
    }
}

/// `Module::credentials`: a fresh token for the run behind `session`, when MCP is on.
pub async fn credentials(app: &App, session: &Session) -> Result<Vec<Credential>, String> {
    if crate::settings::value(&app.pool, "mcp.enabled")
        .await
        .map_err(|e| e.to_string())?
        == 0
    {
        return Ok(Vec::new());
    }
    let run = session
        .owner_ref
        .as_deref()
        .and_then(|r| r.strip_prefix("run:"))
        .and_then(|n| n.parse::<i64>().ok())
        .map(RunId)
        .ok_or("the session names no run")?;
    // A run's session is the one that is recorded for it, when one is (not yet, at its first start).
    let recorded: Option<Option<String>> =
        sqlx::query_scalar("SELECT session_id FROM citadel_runs WHERE id = ?")
            .bind(run.0)
            .fetch_optional(&app.pool)
            .await
            .map_err(|e| e.to_string())?;
    match recorded {
        Some(None) => {}
        Some(Some(id)) if id == session.id => {}
        _ => return Err("the session is not this run's".into()),
    }
    let token = issue_run_token(&app.pool, run, &app.clock.now())
        .await
        .map_err(|e| e.to_string())?;
    Ok(vec![Credential {
        var: RUN_TOKEN_VAR.to_owned(),
        value: Zeroizing::new(token.expose().to_owned()),
    }])
}

const INSTRUCTIONS: &str = "Citadel tracks the issue you are working on. Read it with \
    get_issue and its project with get_context. Report progress with comment, and move the issue \
    with transition (start, submit_for_review, block, done) while you are its next actor. You can \
    only reach your run's issue and its subtasks: create_subtask splits work, report_blocker links \
    what blocks you. Ask a human to approve something with request_approval; get_approval reads \
    the decision.";

/// The run the request's token belongs to (set by the Core's gate).
fn run_scope(context: &RequestContext<RoleServer>) -> Result<RunScope, ErrorData> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<TokenPrincipal>())
        .and_then(|p| p.0.downcast_ref::<RunScope>())
        .copied()
        .ok_or_else(|| ErrorData::internal_error("no run scope on the request", None))
}

/// One request's handler: the app, and nothing per agent (the scope comes with each request).
#[derive(Clone)]
struct Citadel {
    app: App,
}

/// The service. The Core's gate has already checked Host, Origin and the token, so the SDK's own
/// checks are off.
fn service(app: App) -> StreamableHttpService<Citadel, NeverSessionManager> {
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
        run_scope(&context)?;
        Ok(ListToolsResult::with_all_items(defs::list()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let scope = run_scope(&context)?;
        let args = request.arguments.unwrap_or_default();
        let result = match tools::call(&self.app, scope, &request.name, &args).await {
            Ok(value) => CallToolResult::success(vec![ContentBlock::text(value.to_string())]),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(e.to_string())]),
        };
        Ok(result.into())
    }
}
