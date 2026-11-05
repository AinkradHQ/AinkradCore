//! Which tools a request may carry (KAN-435 G6, threat T6): an allowlist, on every wire.
//!
//! A tool the provider runs on its own side (web search, a code interpreter, image generation,
//! file search over a vector store, Gemini grounding, maps, URL context, an MCP connector) is a
//! second route out of the sandbox, and some spend or read what the gateway cannot see. A name
//! list of those would age with every release, so only the tools the harness itself runs pass:
//!
//! - a `function`, `custom` or `local_shell` tool (the OpenAI wires; the model emits a call and the
//!   harness executes it), and a `namespace` of such tools, nested to a bounded depth;
//! - an Anthropic custom tool: no `type`, with a `name` and an `input_schema`;
//! - a Gemini tool object that holds only `functionDeclarations`.
//!
//! Anything else is refused, including a tool whose `type` is not a string. Only `tools` lists are
//! walked, never a tool's schema, so a parameter named `web_search` is not a tool.

use serde::Deserialize;
use serde_json::{Map, Value};

const MAX_DEPTH: usize = 8;
const TYPES: [&str; 4] = ["function", "custom", "local_shell", "namespace"];
const DECLARATIONS: [&str; 2] = ["functionDeclarations", "function_declarations"];

#[derive(Deserialize)]
struct Body {
    tools: Option<Value>,
}

fn all_ok(tools: &Value, depth: usize) -> bool {
    match tools {
        Value::Array(list) => list.iter().all(|t| one_ok(t, depth)),
        one => one_ok(one, depth),
    }
}

fn one_ok(tool: &Value, depth: usize) -> bool {
    let Value::Object(m) = tool else { return false };
    if depth > MAX_DEPTH {
        return false;
    }
    match m.get("type") {
        Some(Value::String(ty)) if TYPES.contains(&ty.as_str()) => match m.get("tools") {
            None => true,
            Some(inner) => ty == "namespace" && all_ok(inner, depth + 1),
        },
        Some(_) => false,
        None => untyped_ok(m),
    }
}

fn untyped_ok(m: &Map<String, Value>) -> bool {
    if DECLARATIONS.iter().any(|k| m.contains_key(*k)) {
        return m.keys().all(|k| DECLARATIONS.contains(&k.as_str()));
    }
    m.get("name").is_some_and(Value::is_string)
        && m.get("input_schema").is_some_and(Value::is_object)
}

/// Whether the request body names a tool that is not allowed. A body that is not readable here
/// is left to the checks that already refused it.
pub(super) fn refusal(body: &[u8]) -> bool {
    serde_json::from_slice::<Body>(body)
        .ok()
        .and_then(|b| b.tools)
        .is_some_and(|t| !t.is_null() && !all_ok(&t, 0))
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn a_tool_the_provider_runs_is_refused_whatever_it_is_called() {
        for body in [
            // OpenAI: code interpreter, image generation, file search, web search, computer use, MCP.
            r#"{"tools":[{"type":"code_interpreter","container":{"type":"auto"}}]}"#,
            r#"{"tools":[{"type":"image_generation"}]}"#,
            r#"{"tools":[{"type":"file_search","vector_store_ids":["vs_1"]}]}"#,
            r#"{"tools":[{"type":"web_search"}]}"#,
            r#"{"tools":[{"type":"web_search_preview_2025_03_11"}]}"#,
            r#"{"tools":[{"type":"computer_use_preview"}]}"#,
            r#"{"tools":[{"type":"mcp","server_url":"u"}]}"#,
            // Anthropic: server tools, the MCP toolset, a typed tool the harness does not run.
            r#"{"tools":[{"type":"web_search_20250305","name":"web_search"}]}"#,
            r#"{"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}"#,
            r#"{"tools":[{"type":"mcp_toolset","mcp_server_name":"n"}]}"#,
            // Gemini: grounding, maps, URL context, code execution, retrieval, mixed with declarations.
            r#"{"tools":[{"googleMaps":{}}]}"#,
            r#"{"tools":[{"googleSearch":{}}]}"#,
            r#"{"tools":[{"urlContext":{}}]}"#,
            r#"{"tools":[{"codeExecution":{}}]}"#,
            r#"{"tools":[{"fileSearch":{"fileSearchStoreNames":["s"]}}]}"#,
            r#"{"tools":[{"functionDeclarations":[],"googleMaps":{}}]}"#,
            r#"{"tools":{"google_search":{}}}"#,
            // Typeless and nameless, a non-string type, and a null in a list.
            r#"{"tools":[{"description":"x"}]}"#,
            r#"{"tools":[{"type":null,"name":"n","input_schema":{}}]}"#,
            r#"{"tools":[{"type":1}]}"#,
            r#"{"tools":[null]}"#,
            // One bad tool among good ones.
            r#"{"tools":[{"type":"function","name":"f"},{"type":"image_generation"}]}"#,
        ] {
            assert!(refusal(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn a_tool_nested_in_a_namespace_is_held_to_the_same_list_at_any_depth() {
        for body in [
            r#"{"tools":[{"type":"namespace","name":"n","tools":[{"type":"web_search"}]}]}"#,
            r#"{"tools":[{"type":"namespace","tools":[{"type":"function","name":"f"},{"type":"code_interpreter"}]}]}"#,
            r#"{"tools":[{"type":"namespace","tools":[{"type":"namespace","tools":[{"googleSearch":{}}]}]}]}"#,
            // Only a namespace holds tools.
            r#"{"tools":[{"type":"function","name":"f","tools":[{"type":"function","name":"g"}]}]}"#,
        ] {
            assert!(refusal(body.as_bytes()), "{body}");
        }
        let mut deep = r#"{"type":"function","name":"f"}"#.to_owned();
        for _ in 0..20 {
            deep = format!(r#"{{"type":"namespace","tools":[{deep}]}}"#);
        }
        assert!(refusal(format!(r#"{{"tools":[{deep}]}}"#).as_bytes()));
    }

    #[test]
    fn the_harnesses_own_tools_pass() {
        for body in [
            r#"{"model":"m"}"#,
            r#"{"tools":null}"#,
            r#"{"tools":[]}"#,
            r#"{"tools":[{"type":"function","name":"web_search_helper","description":"mcp","parameters":{"properties":{"mcp_server":{},"tools":[{"type":"web_search"}]}}}]}"#,
            r#"{"tools":[{"type":"custom","name":"apply_patch"}]}"#,
            r#"{"tools":[{"type":"local_shell"}]}"#,
            r#"{"tools":[{"type":"namespace","name":"n","tools":[{"type":"function","name":"f"}]}]}"#,
            // Anthropic custom tools, as Claude Code sends them.
            r#"{"tools":[{"name":"Bash","description":"x","input_schema":{"type":"object"}}]}"#,
            r#"{"tools":[{"name":"T","description":"x","input_schema":{},"defer_loading":true}]}"#,
            r#"{"tools":[{"type":"custom","name":"c","input_schema":{}}]}"#,
            // Gemini declarations, either spelling.
            r#"{"tools":[{"functionDeclarations":[{"name":"f"}]}]}"#,
            r#"{"tools":[{"function_declarations":[{"name":"f"}]}]}"#,
        ] {
            assert!(!refusal(body.as_bytes()), "{body}");
        }
    }
}
