//! Role-scoped tools (E15.18 step 1, decision #59): a run's `tools/list` holds only its agent's
//! role's tools, so its harness does not load every definition into context before the first
//! turn. The rest are found with `search_tools` and read with `describe_tool`.
//!
//! Only the list is scoped. A call to a tool outside it goes through as before, where each tool
//! checks its own permissions (planner, team lead, QA reviewer, CEO), so scoping never grants
//! or takes away anything. `mcp.role_scoped_tools` = 0 (server, company or project) lists every
//! tool again.
//!
//! An agent's roles: the CEO or CTO (its org role), a product owner or team lead (a seat on any
//! team), QA (its job title), else a developer. One agent may hold several; it gets the union.

use ainkrad_core::auth::RunScope;
use ainkrad_core::settings::Key;
use rmcp::model::{JsonObject, Tool};
use serde_json::{Value, json};

use super::args::{MAX_TITLE, Result, ToolError, required, text};
use super::defs;
use crate::api::App;

/// Every run's tools, whatever its role.
const COMMON: &[&str] = &[
    "get_issue",
    "get_context",
    "comment",
    "transition",
    "create_subtask",
    "report_blocker",
    "ask_human",
    "publish_artifact",
    "get_artifact",
    "request_approval",
    "get_approval",
    "propose_knowledge",
    "search_tools",
    "describe_tool",
];

const DEV: &[&str] = &["open_pr", "request_repo"];
const QA: &[&str] = &["qa_verdict"];
/// A product owner's or team lead's planning tools.
const PLANNER: &[&str] = &[
    "org_chart",
    "list_backlog",
    "plan_requirement",
    "apply_plan",
    "plan_sprint",
    "sprint_add_issue",
    "sprint_remove_issue",
    "set_sprint_issues",
    "estimate_issue",
    "assign_issue",
    "commit_sprint",
    "close_sprint",
    "sprint_report",
    "propose_retro_items",
    "set_repos",
    "post_to_requirement",
    "request_hire",
];
const LEAD: &[&str] = &["decide_repo", "review_knowledge"];
const CEO: &[&str] = &[
    "org_chart",
    "route_intake",
    "request_hire",
    "post_to_requirement",
    "list_backlog",
    "plan_requirement",
    "apply_plan",
    "sprint_report",
];
const CTO: &[&str] = &[
    "org_chart",
    "request_hire",
    "post_to_requirement",
    "list_backlog",
    "plan_requirement",
    "apply_plan",
    "plan_sprint",
    "sprint_add_issue",
    "estimate_issue",
    "assign_issue",
    "set_repos",
    "sprint_report",
];

/// The names of the tools `agent`'s roles list.
async fn role_tools(app: &App, scope: RunScope) -> Result<Vec<&'static str>> {
    let (org_role, title, seats): (String, String, Option<String>) = sqlx::query_as(
        "SELECT a.org_role, lower(a.role), (SELECT group_concat(team_role) FROM \
         team_memberships WHERE agent_id = a.id) FROM agents a WHERE a.id = ?",
    )
    .bind(scope.agent_id.0)
    .fetch_optional(&app.pool)
    .await?
    .unwrap_or_default();
    let seats = seats.unwrap_or_default();
    let seat = |s: &str| seats.split(',').any(|x| x == s);
    let mut sets: Vec<&[&str]> = vec![COMMON];
    match org_role.as_str() {
        "ceo" => sets.push(CEO),
        "cto" => sets.push(CTO),
        _ => {}
    }
    if seat("product_owner") || seat("team_lead") {
        sets.push(PLANNER);
    }
    if seat("team_lead") {
        sets.push(LEAD);
    }
    if title == "qa" {
        sets.push(QA);
    }
    if sets.len() == 1 {
        sets.push(DEV);
    }
    Ok(sets.concat())
}

/// Whether the run's list is scoped (`mcp.role_scoped_tools`, read at its issue's project).
async fn scoped(app: &App, scope: RunScope) -> Result<bool> {
    let mut conn = app.pool.acquire().await?;
    let at =
        crate::store::settings::run_scope_in(&mut conn, scope.issue_id, scope.agent_id).await?;
    let on = crate::store::settings::value_in(&mut conn, Key::McpRoleScopedTools, at).await?;
    Ok(on != 0)
}

/// The run's `tools/list`: its roles' tools, in the order of `defs::list`, or all of them.
pub(super) async fn listed(app: &App, scope: RunScope) -> Result<Vec<Tool>> {
    let all = defs::list();
    if !scoped(app, scope).await? {
        return Ok(all);
    }
    let names = role_tools(app, scope).await?;
    Ok(all
        .into_iter()
        .filter(|t| names.contains(&t.name.as_ref()))
        .collect())
}

/// A description's first sentence.
fn summary(t: &Tool) -> String {
    let d = t.description.as_deref().unwrap_or_default();
    let end = d.find(". ").map_or(d.len(), |i| i + 1);
    d[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

fn in_list(listed: &[Tool], name: &str) -> bool {
    listed.iter().any(|t| t.name == name)
}

/// `search_tools {query}`: the tools whose name or description holds the query's words, best
/// first, at most 10, each with whether the run's list has it.
pub(super) async fn search_tools(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let query = text(args, "query", MAX_TITLE)?
        .unwrap_or_default()
        .to_lowercase();
    let words: Vec<&str> = query.split_whitespace().collect();
    let listed = listed(app, scope).await?;
    let mut hits: Vec<(usize, Tool)> = defs::list()
        .into_iter()
        .map(|t| {
            let hay = format!(
                "{} {}",
                t.name,
                t.description.as_deref().unwrap_or_default()
            )
            .to_lowercase()
            .replace('_', " ");
            let score = words.iter().filter(|w| hay.contains(*w)).count();
            (score, t)
        })
        .filter(|(score, _)| words.is_empty() || *score > 0)
        .collect();
    hits.sort_by_key(|h| std::cmp::Reverse(h.0));
    let tools: Vec<Value> = hits
        .iter()
        .take(10)
        .map(|(_, t)| {
            json!({"name": t.name, "summary": summary(t), "listed": in_list(&listed, &t.name)})
        })
        .collect();
    Ok(json!({"tools": tools,
              "note": "describe_tool {name} gives one's arguments; any tool can be called, \
                       and each checks your permission"}))
}

/// `describe_tool {name}`: one tool's description and input schema.
pub(super) async fn describe_tool(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let name = required(args, "name", MAX_TITLE)?;
    let t = defs::list()
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| ToolError::Invalid(format!("no tool {name:?}; search_tools finds one")))?;
    let listed = in_list(&listed(app, scope).await?, name);
    Ok(json!({"name": t.name, "description": t.description,
              "input_schema": Value::Object((*t.input_schema).clone()), "listed": listed}))
}

/// A JSON schema as a short type: `int`, `str`, `bool`, `a|b`, `[T]`, `{a:T, b?:T}`.
fn short(schema: &Value) -> String {
    if let Some(choices) = schema["enum"].as_array() {
        let names: Vec<&str> = choices.iter().filter_map(Value::as_str).collect();
        return names.join("|");
    }
    match schema["type"].as_str() {
        Some("integer") => "int".to_owned(),
        Some("string") => "str".to_owned(),
        Some("boolean") => "bool".to_owned(),
        Some("array") => format!("[{}]", short(&schema["items"])),
        Some("object") => format!("{{{}}}", fields(schema)),
        _ => "any".to_owned(),
    }
}

/// An object schema's fields, `name:T`, optional ones `name?:T`.
fn fields(schema: &Value) -> String {
    let required: Vec<&str> = schema["required"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    schema["properties"]
        .as_object()
        .map(|props| {
            props
                .iter()
                .map(|(k, v)| {
                    let opt = if required.contains(&k.as_str()) {
                        ""
                    } else {
                        "?"
                    };
                    format!("{k}{opt}:{}", short(v))
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// The run's operations as one compact line each: `{"get_issue": "(issue_id?:int, …) Read …"}`.
pub(super) async fn schema(app: &App, scope: RunScope) -> Result<Value> {
    let ops: serde_json::Map<String, Value> = listed(app, scope)
        .await?
        .iter()
        .map(|t| {
            let args = fields(&Value::Object((*t.input_schema).clone()));
            (
                t.name.to_string(),
                json!(format!("({args}) {}", summary(t))),
            )
        })
        .collect();
    Ok(Value::Object(ops))
}
