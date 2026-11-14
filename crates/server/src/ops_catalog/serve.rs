//! `ainkrad.search` on the `agent.tools` channel: listed beside the connection tools, answered by
//! the Core from the session's own row (its creator device's scopes, read on every call).

use ainkrad_proto::v2::{ConnTool, MAX_ARGS_BYTES, ToolCall, ToolResult};
use serde_json::{Value, json};

use crate::api::App;
use crate::store::connections::access;

pub const SEARCH: &str = "ainkrad.search";

/// The tool entry the runner lists to the harness as `ainkrad_search`.
pub fn search_tool() -> ConnTool {
    ConnTool {
        name: SEARCH.to_owned(),
        description: "Search the operations of Ainkrad (sessions, audit, health and more) by \
                      words. Returns typed definitions of the best matches."
            .to_owned(),
        write: false,
        input_schema: Some(json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 200},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20}
            },
            "required": ["query"],
            "additionalProperties": false
        })),
    }
}

fn refuse(id: String, code: &str, message: &str) -> ToolResult {
    ToolResult {
        approval: None,
        id,
        ok: false,
        result: None,
        code: Some(code.to_owned()),
        message: Some(message.to_owned()),
    }
}

/// A session's principal: its creator device with its scopes NARROWED, read now.
pub struct Principal {
    pub device: crate::store::gov::Device,
    /// The device's current scopes without `admin`: a session is never granted it.
    pub scopes: Vec<String>,
}

/// The principal of `session`: its creator device as it is NOW, or `None` when the session is
/// unknown or the device is revoked, pending, locked or gone.
pub async fn session_principal(
    pool: &sqlx::SqlitePool,
    session: &str,
) -> Result<Option<Principal>, sqlx::Error> {
    let by: Option<String> =
        sqlx::query_scalar("SELECT created_by FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(pool)
            .await?;
    let Some(by) = by else { return Ok(None) };
    let Some(mut device) = crate::store::gov::get_device(pool, &by)
        .await?
        .filter(|d| d.usable())
    else {
        return Ok(None);
    };
    device.scopes.retain(|s| s != "admin");
    Ok(Some(Principal {
        scopes: device.scopes.clone(),
        device,
    }))
}

/// The scopes of the device that created `session`, now, never `admin` (none if it is revoked
/// or gone).
pub async fn session_scopes(
    pool: &sqlx::SqlitePool,
    session: &str,
) -> Result<Vec<String>, sqlx::Error> {
    Ok(session_principal(pool, session)
        .await?
        .map(|p| p.scopes)
        .unwrap_or_default())
}

/// Answers one `ainkrad.search` call from `runner` for `session`.
pub async fn search_call(app: &App, runner: &str, session: &str, call: &ToolCall) -> ToolResult {
    let id = call.id.clone();
    match access::load(&app.pool, session).await {
        Ok(Some(a)) if a.live && a.runner == runner => {}
        Ok(_) => return refuse(id, "unknown_session", "no live session of yours"),
        Err(_) => return refuse(id, "unavailable", "try again"),
    }
    let query = call.args["query"].as_str().filter(|q| q.len() <= 200);
    let limit = match &call.args["limit"] {
        Value::Null => Some(None),
        v => v.as_u64().and_then(|n| usize::try_from(n).ok()).map(Some),
    };
    let (Some(query), Some(limit)) = (query, limit) else {
        return refuse(id, "bad_args", "query is a string, limit a number");
    };
    if call.args.to_string().len() > MAX_ARGS_BYTES {
        return refuse(id, "bad_args", "arguments too large");
    }
    let Ok(mut scopes) = session_scopes(&app.pool, session).await else {
        return refuse(id, "unavailable", "try again");
    };
    // E5: this session's connection operations are searched beside the contract's.
    scopes.push(super::conn::GROUP.to_owned());
    let cat = super::conn::merged(app, session).await;
    let answer = super::search(&cat, &scopes, query, limit);
    ToolResult {
        approval: None,
        id,
        ok: true,
        result: Some(answer),
        code: None,
        message: None,
    }
}
