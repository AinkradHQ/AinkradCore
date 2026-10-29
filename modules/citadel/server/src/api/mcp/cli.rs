//! The run-scoped `citadel` CLI's route (E15.18 step 3, decision #59): `POST /mcp/v1/call/<op>`
//! with the operation's arguments as JSON, answered with its result as JSON. The runner puts a
//! small script on every run's `PATH` that posts here (`ainkrad_runner`'s `harness::cli`).
//!
//! Behind the same gate as `/mcp/v1` (a live run token, never in the URL), and every operation
//! is one of the run's MCP tools, through `tools::call`: the same scope and permission checks,
//! the same redaction of what it publishes, the same `mcp.<tool>` audit. Two more:
//!
//! - `schema`: the run's operations (its role's tools), one compact line each;
//! - `batch`: `[{"op", "args"}, …]` (or `{"ops": […]}`) run in order, stopping at the first
//!   failure, each audited as its own call; at most `cli.max_batch_ops`. Not a transaction:
//!   `apply_plan` is the one that files a plan all or nothing.
//!
//! A refusal is 403, bad arguments 400, a server failure 500, each `{"error": "…"}`; a batch
//! that stops is 400 with the results so far and `{"failed": {index, op, error}}`.

use citadel_core::auth::RunScope;
use citadel_core::settings::Key;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::ToolError;
use super::{RunSecrets, roles, tools};
use crate::api::App;

fn status(e: &ToolError) -> StatusCode {
    match e {
        ToolError::Refused(_) => StatusCode::FORBIDDEN,
        ToolError::Invalid(_) => StatusCode::BAD_REQUEST,
        ToolError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn failed(e: &ToolError) -> Response {
    (status(e), Json(json!({"error": e.to_string()}))).into_response()
}

fn invalid(why: &str) -> Response {
    failed(&ToolError::Invalid(why.to_owned()))
}

/// `body` as JSON; empty is `{}`.
fn parse(body: &[u8]) -> Result<Value, String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(json!({}));
    }
    serde_json::from_slice(body).map_err(|e| format!("the body is not JSON: {e}"))
}

/// An operation's arguments: an object, or nothing.
fn object(v: Value) -> Result<JsonObject, String> {
    match v {
        Value::Object(o) => Ok(o),
        Value::Null => Ok(JsonObject::new()),
        _ => Err("the arguments must be a JSON object".to_owned()),
    }
}

pub(in crate::api) async fn call(
    State(app): State<App>,
    Extension(scope): Extension<RunScope>,
    Extension(secrets): Extension<RunSecrets>,
    Path(op): Path<String>,
    body: Bytes,
) -> Response {
    let body = match parse(&body) {
        Ok(v) => v,
        Err(why) => return invalid(&why),
    };
    match op.as_str() {
        "schema" => match roles::schema(&app, scope).await {
            Ok(v) => Json(v).into_response(),
            Err(e) => failed(&e),
        },
        "batch" => batch(&app, scope, &secrets, body).await,
        _ => {
            let args = match object(body) {
                Ok(args) => args,
                Err(why) => return invalid(&why),
            };
            match tools::call(&app, scope, &secrets.0, &op, &args).await {
                Ok(v) => Json(v).into_response(),
                Err(e) => failed(&e),
            }
        }
    }
}

async fn batch(app: &App, scope: RunScope, secrets: &RunSecrets, body: Value) -> Response {
    let ops = match body {
        Value::Array(ops) => ops,
        Value::Object(mut o) => match o.remove("ops") {
            Some(Value::Array(ops)) => ops,
            _ => return invalid("a batch is [{\"op\", \"args\"}, …] or {\"ops\": […]}"),
        },
        _ => return invalid("a batch is [{\"op\", \"args\"}, …] or {\"ops\": […]}"),
    };
    let max = {
        let mut conn = match app.pool.acquire().await {
            Ok(c) => c,
            Err(e) => return failed(&e.into()),
        };
        let at = crate::store::settings::run_scope_in(&mut conn, scope.issue_id, scope.agent_id);
        match at.await {
            Ok(at) => crate::store::settings::value_in(&mut conn, Key::CliMaxBatchOps, at).await,
            Err(e) => Err(e),
        }
    };
    let max = match max {
        Ok(max) => max as usize,
        Err(e) => return failed(&e.into()),
    };
    if ops.len() > max {
        let why = format!("{} operations; a batch runs at most {max}", ops.len());
        return invalid(&why);
    }
    let mut results = vec![];
    for (index, item) in ops.into_iter().enumerate() {
        let (op, args) = match item {
            Value::Object(mut o) => (o.remove("op"), o.remove("args").unwrap_or(Value::Null)),
            _ => (None, Value::Null),
        };
        let op = match op {
            Some(Value::String(op)) if !matches!(op.as_str(), "batch" | "schema") => op,
            _ => {
                let why = "each item is {\"op\": \"<tool>\", \"args\": {…}}";
                return stopped(results, index, Value::Null, &ToolError::Invalid(why.into()));
            }
        };
        let result = match object(args) {
            Ok(args) => tools::call(app, scope, &secrets.0, &op, &args).await,
            Err(why) => Err(ToolError::Invalid(why)),
        };
        match result {
            Ok(v) => results.push(v),
            Err(e) => return stopped(results, index, json!(op), &e),
        }
    }
    Json(json!({"results": results})).into_response()
}

fn stopped(results: Vec<Value>, index: usize, op: Value, e: &ToolError) -> Response {
    let body = json!({"results": results,
                      "failed": {"index": index, "op": op, "error": e.to_string()}});
    let code = match status(e) {
        StatusCode::INTERNAL_SERVER_ERROR => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (code, Json(body)).into_response()
}
