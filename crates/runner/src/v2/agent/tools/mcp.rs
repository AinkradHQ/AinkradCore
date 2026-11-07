//! The harness-facing face of the connection tools: Model Context Protocol (JSON-RPC 2.0) over
//! one POST body, enough for `initialize`, `ping`, `tools/list` and `tools/call`. [`handle`] is
//! pure over [`Tools`]: it takes a request body and gives a response body (or none, for a
//! notification), so the socket that serves it (the sandbox's MCP route) stays a thin transport.
//!
//! Tool names are the operations with `.` as `_` (`github_get_issue`): clients accept only
//! `[A-Za-z0-9_-]`. A call's text is the Core's answer as JSON; a refusal is an `isError` result
//! with the plain code and sentence, never a JSON-RPC error, so the model reads it and adapts.

use serde_json::{Value, json};

use super::Tools;

const PROTOCOL: &str = "2025-03-26";

fn mcp_name(op: &str) -> String {
    op.replace('.', "_")
}

fn error(id: Value, code: i64, message: &str) -> Vec<u8> {
    let v = json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
    v.to_string().into_bytes()
}

fn result(id: Value, result: Value) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
        .to_string()
        .into_bytes()
}

fn text(ok: bool, body: &Value) -> Value {
    json!({"content": [{"type": "text", "text": body.to_string()}], "isError": !ok})
}

/// The response to one request body for `session`; `None` for a notification.
pub async fn handle(tools: &Tools, session: &str, body: &[u8]) -> Option<Vec<u8>> {
    let Ok(req) = serde_json::from_slice::<Value>(body) else {
        return Some(error(Value::Null, -32700, "parse error"));
    };
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return Some(error(Value::Null, -32600, "invalid request"));
    };
    let Some(id) = req.get("id").cloned() else {
        return None; // a notification is not answered
    };
    match method {
        "initialize" => {
            let asked = req["params"]["protocolVersion"]
                .as_str()
                .unwrap_or(PROTOCOL);
            Some(result(
                id,
                json!({"protocolVersion": asked, "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ainkrad-connections", "version": "1"}}),
            ))
        }
        "ping" => Some(result(id, json!({}))),
        "tools/list" => {
            let list: Vec<Value> = tools
                .list(session)
                .iter()
                .map(|t| {
                    json!({"name": mcp_name(&t.name), "description": t.description,
                        "inputSchema": {"type": "object", "additionalProperties": true}})
                })
                .collect();
            Some(result(id, json!({"tools": list})))
        }
        "tools/call" => {
            let p = &req["params"];
            let Some(name) = p["name"].as_str() else {
                return Some(error(id, -32602, "a tool call names a tool"));
            };
            let args = match p.get("arguments") {
                None | Some(Value::Null) => json!({}),
                Some(a @ Value::Object(_)) => a.clone(),
                Some(_) => return Some(error(id, -32602, "arguments are an object")),
            };
            let listed = tools.list(session);
            let Some(op) = listed.iter().find(|t| mcp_name(&t.name) == name) else {
                let body =
                    json!({"code": "unknown_tool", "message": "no such tool in this session"});
                return Some(result(id, text(false, &body)));
            };
            let r = tools.call(session, &op.name, args).await;
            let body = match (&r.result, r.ok) {
                (Some(v), true) => v.clone(),
                _ => json!({"code": r.code, "message": r.message}),
            };
            Some(result(id, text(r.ok, &body)))
        }
        _ => Some(error(id, -32601, "method not found")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use ainkrad_proto::v2::{ConnTool, ToolResult, ToolsPoll};

    use super::*;

    async fn ask(t: &Tools, body: Value) -> Value {
        let out = handle(t, "as_a", body.to_string().as_bytes())
            .await
            .unwrap();
        serde_json::from_slice(&out).unwrap()
    }

    fn poll(after: u64, results: Vec<ToolResult>, tools: Option<Vec<ConnTool>>) -> ToolsPoll {
        ToolsPoll {
            session: "as_a".to_owned(),
            after,
            wait_ms: Some(200),
            results,
            tools,
        }
    }

    #[tokio::test]
    async fn lists_calls_and_refuses_in_the_models_own_terms() {
        let t = Arc::new(Tools::default());
        let list = vec![ConnTool {
            name: "github.get_issue".to_owned(),
            description: "Read an issue".to_owned(),
            write: false,
        }];
        t.poll(&poll(0, vec![], Some(list)), Duration::from_millis(200))
            .await;
        let init = ask(
            &t,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        )
        .await;
        assert!(init["result"]["capabilities"]["tools"].is_object());
        assert!(
            handle(
                &t,
                "as_a",
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .await
            .is_none()
        );
        let l = ask(
            &t,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        )
        .await;
        assert_eq!(l["result"]["tools"][0]["name"], "github_get_issue");
        // An unknown tool is a refusal the model reads, not a protocol error.
        let u = ask(
            &t,
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "github_drop_repo", "arguments": {}}}),
        )
        .await;
        assert_eq!(u["result"]["isError"], true);
        assert!(
            u["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("unknown_tool")
        );
        // A real call is answered by the Core's result.
        let call = {
            let t = t.clone();
            tokio::spawn(async move {
                ask(&t, json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "github_get_issue", "arguments": {"repo": "o/r", "number": 1}}})).await
            })
        };
        let batch = t
            .poll(&poll(0, vec![], None), Duration::from_millis(500))
            .await;
        assert_eq!(batch.calls[0].tool, "github.get_issue");
        assert_eq!(batch.calls[0].args["repo"], "o/r");
        let answer = ToolResult {
            id: batch.calls[0].id.clone(),
            ok: true,
            result: Some(json!({"title": "x"})),
            code: None,
            message: None,
        };
        t.poll(&poll(1, vec![answer], None), Duration::from_millis(50))
            .await;
        let r = call.await.unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("\"title\":\"x\"")
        );
        let bad = ask(&t, json!({"jsonrpc": "2.0", "id": 5, "method": "nope"})).await;
        assert_eq!(bad["error"]["code"], -32601);
        let junk = handle(&t, "as_a", b"not json").await.unwrap();
        assert!(String::from_utf8_lossy(&junk).contains("-32700"));
    }
}
