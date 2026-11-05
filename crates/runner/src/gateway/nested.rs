//! Provider-side tools nested inside a tool (KAN-435 G6, threat T6). `probe` checks the keys and
//! `type` of each top-level tool; Codex's `namespace` tool carries its own `tools` list, so a
//! `web_search` or `mcp` tool could sit there. The same check is applied down every `tools` list.
//! Only `tools` lists are walked, never a tool's schema, so a function that has a parameter named
//! `mcp_server` is not caught. Nesting deeper than [`MAX_DEPTH`] is refused.

use serde::Deserialize;
use serde_json::Value;

use super::probe::reaches_network;

const MAX_DEPTH: usize = 8;

#[derive(Deserialize)]
struct Body {
    tools: Option<Value>,
}

/// Whether some tool, at any depth of `tools` lists, reaches the network (or the lists nest past
/// the limit, which is not read further).
fn bad(tools: &Value, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return true;
    }
    let list: &[Value] = match tools {
        Value::Array(a) => a,
        one => std::slice::from_ref(one),
    };
    list.iter().any(|t| {
        let Value::Object(m) = t else { return false };
        let own = m.iter().any(|(k, v)| {
            reaches_network(k) || (k == "type" && v.as_str().is_some_and(reaches_network))
        });
        own || m.get("tools").is_some_and(|inner| bad(inner, depth + 1))
    })
}

/// Whether the request body has such a tool. A body that is not readable here is left to the
/// checks that already refused or passed it.
pub(super) fn refusal(body: &[u8]) -> bool {
    serde_json::from_slice::<Body>(body)
        .ok()
        .and_then(|b| b.tools)
        .is_some_and(|t| bad(&t, 0))
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn a_network_tool_nested_in_a_tool_is_refused_at_any_depth() {
        for body in [
            r#"{"tools":[{"type":"namespace","name":"n","tools":[{"type":"web_search"}]}]}"#,
            r#"{"tools":[{"type":"namespace","tools":[{"type":"function","name":"f"},{"type":"mcp","server_url":"u"}]}]}"#,
            r#"{"tools":[{"type":"namespace","tools":[{"type":"namespace","tools":[{"googleSearch":{}}]}]}]}"#,
            r#"{"tools":{"type":"namespace","tools":{"type":"web_fetch_20250910"}}}"#,
        ] {
            assert!(refusal(body.as_bytes()), "{body}");
        }
        // Nested without end is refused, not walked to the stack's limit.
        let mut deep = r#"{"type":"web_search"}"#.to_owned();
        for _ in 0..20 {
            deep = format!(r#"{{"type":"namespace","tools":[{deep}]}}"#);
        }
        assert!(refusal(format!(r#"{{"tools":[{deep}]}}"#).as_bytes()));
    }

    #[test]
    fn ordinary_nested_tools_and_schemas_that_mention_the_words_pass() {
        for body in [
            r#"{"model":"m"}"#,
            r#"{"tools":[]}"#,
            r#"{"tools":[{"type":"namespace","name":"multi_agent_v1","tools":[{"type":"function","name":"spawn","parameters":{"properties":{"mcp_server":{}}}}]}]}"#,
            r#"{"tools":[{"type":"function","name":"f","parameters":{"tools":[{"type":"web_search"}]}}]}"#,
            r#"{"tools":null}"#,
        ] {
            assert!(!refusal(body.as_bytes()), "{body}");
        }
    }
}
