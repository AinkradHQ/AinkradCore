//! The harness-facing face of the connection tools: Model Context Protocol (JSON-RPC 2.0) over
//! one POST body, enough for `initialize`, `ping`, `tools/list` and `tools/call`. [`handle`] is
//! pure over [`Tools`]: it takes a request body and gives a response body (or none, for a
//! notification), so the socket that serves it (the sandbox's MCP route) stays a thin transport.
//!
//! Tool names are the operations with `.` as `_` (`github_get_issue`): clients accept only
//! `[A-Za-z0-9_-]`. A call's text is the Core's answer as JSON; a refusal is an `isError` result
//! with the plain code and sentence, never a JSON-RPC error, so the model reads it and adapts.

use serde_json::{Value, json};

use ainkrad_proto::v2::ConnTool;

use super::Tools;

/// The Core's search operation (listed to the harness as `ainkrad_search`), and the script tool
/// the shim adds beside it (`ainkrad_run`, served by E3).
const SEARCH: &str = "ainkrad.search";
const RUN: &str = "ainkrad.run";
/// Listed by the Core for the runner's own use, never shown to the harness.
const HIDDEN: [&str; 2] = ["ainkrad.call", "ainkrad.schema"];

/// The most bytes of tool entries one `tools/list` answer carries.
pub const MAX_LIST_BYTES: usize = 256 * 1024;

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
    // One request per line: a batch is not served (the 2025-06-18 protocol dropped it).
    if req.is_array() {
        return Some(error(Value::Null, -32600, "batches are not supported"));
    }
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        // A reply to a request this side never made is not answered either.
        if req.get("result").is_some() || req.get("error").is_some() {
            return None;
        }
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
                json!({"protocolVersion": asked, "capabilities": {"tools": {"listChanged": true}},
                    "serverInfo": {"name": "ainkrad-connections", "version": "1"}}),
            ))
        }
        "ping" => Some(result(id, json!({}))),
        "tools/list" => {
            // The whole answer is bounded: past `MAX_LIST_BYTES` the rest of the tools are left out
            // and the answer says so (`_meta`), not sent as an ever bigger message.
            let mut list: Vec<Value> = Vec::new();
            let (mut size, mut omitted) = (0, 0);
            let all = tools.list(session);
            // Code Mode: a session the Core offers `ainkrad_search` also lists `ainkrad_run`.
            let run = all.iter().any(|t| t.name == SEARCH).then(|| ConnTool {
                name: RUN.to_owned(),
                description: "Run a short script against Ainkrad's operations; search first \
                              with ainkrad_search."
                    .to_owned(),
                write: false,
                input_schema: Some(json!({"type": "object",
                    "properties": {"code": {"type": "string"}}, "required": ["code"],
                    "additionalProperties": false})),
            });
            // The Core's internal tools (`ainkrad.call`, `ainkrad.schema`) are for the script engine
            // and the CLI, not for the harness's own list.
            let shown = all
                .into_iter()
                .filter(|t| !HIDDEN.contains(&t.name.as_str()));
            for t in shown.chain(run) {
                let schema = t
                    .input_schema
                    .clone()
                    .unwrap_or_else(|| json!({"type": "object", "additionalProperties": true}));
                let one = json!({"name": mcp_name(&t.name), "description": t.description,
                    "inputSchema": schema});
                size += one.to_string().len();
                if size > MAX_LIST_BYTES {
                    omitted += 1;
                } else {
                    list.push(one);
                }
            }
            let mut answer = json!({"tools": list});
            if omitted > 0 {
                answer["_meta"] = json!({"truncated": true, "omitted": omitted});
            }
            Some(result(id, answer))
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
            if name == mcp_name(RUN) && listed.iter().any(|t| t.name == SEARCH) {
                let body = json!({"code": "not_available",
                    "message": "ainkrad_run is not available yet; use ainkrad_search"});
                return Some(result(id, text(false, &body)));
            }
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

    /// 64 tools of 16 KiB schemas do not make a 1 MiB answer: the answer is cut, and says so.
    #[tokio::test]
    async fn a_list_over_the_cap_is_cut_and_says_so() {
        let t = Tools::default();
        let fat = |i: usize| ConnTool {
            name: format!("github.op_{i}"),
            description: "d".to_owned(),
            write: false,
            input_schema: Some(json!({"type": "object",
                "description": "x".repeat(ainkrad_proto::v2::MAX_SCHEMA_BYTES - 200)})),
        };
        let list: Vec<ConnTool> = (0..64).map(fat).collect();
        t.poll(&poll(0, vec![], Some(list)), Duration::from_millis(50))
            .await;
        let l = ask(
            &t,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
        let n = l["result"]["tools"].as_array().unwrap().len();
        assert!(n > 0 && n < 64, "{n}");
        assert_eq!(l["result"]["_meta"]["truncated"], true);
        assert_eq!(l["result"]["_meta"]["omitted"], 64 - n);
        assert!(l.to_string().len() < MAX_LIST_BYTES + 4096);
    }

    /// A schema that is not an object schema is not passed on: the tool is listed open.
    #[tokio::test]
    async fn a_schema_that_is_not_an_object_schema_is_not_passed_on() {
        let t = Tools::default();
        let odd = |name: &str, schema: Value| ConnTool {
            name: name.to_owned(),
            description: "d".to_owned(),
            write: false,
            input_schema: Some(schema),
        };
        let list = vec![
            odd("github.a", json!("not a schema")),
            odd("github.b", json!({"type": "string"})),
            odd("github.c", json!({"type": "object", "properties": {}})),
        ];
        t.poll(&poll(0, vec![], Some(list)), Duration::from_millis(50))
            .await;
        let l = ask(
            &t,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
        let schemas: Vec<&Value> = l["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| &t["inputSchema"])
            .collect();
        assert_eq!(schemas[0]["additionalProperties"], true);
        assert_eq!(schemas[1]["additionalProperties"], true);
        assert_eq!(schemas[2]["properties"], json!({}));
    }

    /// A session the Core offers `ainkrad.search` lists `ainkrad_search` and `ainkrad_run`;
    /// without it neither shows, and a call of `ainkrad_run` is a plain refusal for now.
    #[tokio::test]
    async fn code_mode_tools_show_only_with_the_search_tool() {
        let names = |l: &Value| -> Vec<String> {
            l["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_owned())
                .collect()
        };
        let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let t = Tools::default();
        assert!(names(&ask(&t, list.clone()).await).is_empty());
        let search = ConnTool {
            name: "ainkrad.search".to_owned(),
            description: "d".to_owned(),
            write: false,
            input_schema: None,
        };
        t.poll(
            &poll(0, vec![], Some(vec![search])),
            Duration::from_millis(50),
        )
        .await;
        assert_eq!(
            names(&ask(&t, list).await),
            ["ainkrad_search", "ainkrad_run"]
        );
        let r = ask(
            &t,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "ainkrad_run", "arguments": {"code": "1"}}}),
        )
        .await;
        assert_eq!(r["result"]["isError"], true);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("not_available")
        );
    }

    #[tokio::test]
    async fn lists_calls_and_refuses_in_the_models_own_terms() {
        let t = Arc::new(Tools::default());
        let list = vec![ConnTool {
            name: "github.get_issue".to_owned(),
            description: "Read an issue".to_owned(),
            write: false,
            input_schema: Some(
                json!({"type": "object", "properties": {"repo": {"type": "string"}},
                "required": ["repo"], "additionalProperties": false}),
            ),
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
        assert_eq!(
            l["result"]["tools"][0]["inputSchema"]["required"][0], "repo",
            "the Core's schema is what the harness sees"
        );
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
