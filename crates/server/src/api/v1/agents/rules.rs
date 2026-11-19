//! "Always for this project" (E14): the rules a person made with `decideAgentApproval`'s `always`,
//! listed and removed per project. What a rule may be is `agents::rules` (the positive allowlist).

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;

use super::types::ApprovalRule;
use super::{ApiError, ApiResult, Caller, Session, store};
use crate::agents;
use crate::api::App;
use crate::api::v1::types::ts;

fn not_allowed(why: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "rule_not_allowed", why)
}

fn project_id(s: &str) -> Result<i64, ApiError> {
    s.parse::<u64>()
        .ok()
        .and_then(|n| i64::try_from(n).ok())
        .ok_or_else(|| ApiError::not_found("no such project"))
}

/// The rule `(project, tool, pattern)` an "always" on request `request` of `s` would store, or 400
/// `rule_not_allowed`. Nothing is written.
pub(super) async fn derived(
    app: &App,
    s: &Session,
    request: &str,
) -> Result<(i64, String, String), ApiError> {
    let Some(project) = s.project_id else {
        return Err(not_allowed(
            "only a session of a project can allow a call for it",
        ));
    };
    let Some(entry) = store::approval_request(&app.pool, &s.id, request).await? else {
        return Err(not_allowed("no such request to derive a rule from"));
    };
    let tool = entry["tool"].as_str().unwrap_or_default();
    let (tool, pattern) =
        agents::rules::derive(tool, &entry["input"], s.folder.as_deref()).map_err(not_allowed)?;
    Ok((project, tool, pattern))
}

#[utoipa::path(get, path = "/api/v1/projects/{id}/approval-rules",
    operation_id = "listApprovalRules", tag = "agents",
    params(("id" = String, Path, description = "The project's id")),
    responses((status = 200, description = "The \"always for this project\" rules, oldest first: \
        what `decideAgentApproval` with `always` stored. Each covers later matching tool calls of \
        every session of the project, which the Core approves itself (audited \
        `agent.approval_auto`). 404 for no such project", body = Vec<ApprovalRule>)))]
pub async fn list(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Vec<ApprovalRule>> {
    let id = project_id(&id)?;
    let mut conn = app.pool.acquire().await?;
    crate::store::projects::get(&mut conn, id).await?;
    drop(conn);
    let rules = crate::store::approval_rules::list(&app.pool, id).await?;
    Ok(Json(rules.into_iter().map(shown).collect()))
}

fn shown(r: crate::store::approval_rules::Rule) -> ApprovalRule {
    ApprovalRule {
        id: r.id,
        tool: r.tool,
        pattern: r.pattern,
        created_at: ts(&r.created_at),
    }
}

#[utoipa::path(delete, path = "/api/v1/projects/{id}/approval-rules/{rule}",
    operation_id = "deleteApprovalRule", tag = "agents",
    params(("id" = String, Path, description = "The project's id"),
        ("rule" = String, Path, description = "The rule's id")),
    responses((status = 200, description = "The rule is removed (audited \
        `agent.approval_rule_removed`): later calls of its kind ask again. Returns the rules left. \
        404 for no such project or rule", body = Vec<ApprovalRule>)))]
pub async fn delete(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, rule)): Path<(String, String)>,
) -> ApiResult<Vec<ApprovalRule>> {
    let (id, rule) = (project_id(&id)?, rule.parse::<i64>().unwrap_or(-1));
    let gone = crate::store::approval_rules::delete(&app.pool, id, rule, &me.device.id).await?;
    if !gone {
        return Err(ApiError::not_found("no such approval rule"));
    }
    list(State(app), Path(id.to_string())).await
}
