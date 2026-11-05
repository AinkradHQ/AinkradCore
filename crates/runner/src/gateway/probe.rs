//! What the gateway reads out of a request body and its beta header before anything is sent
//! (KAN-435, threat T6): the model, the output cap the reservation is priced from, and whether
//! the request asks the provider's own servers to reach the network for the agent.
//!
//! The gateway is the agent's only route, and a provider-side tool is a second route: a request
//! that carries a server-side web search, web fetch, URL context or MCP connector makes the
//! provider fetch what the agent names, which is the egress the sandbox denies. Those requests
//! are refused. The check is by the tool's `type` and its keys, normalised (case, `_` and `-`
//! ignored), because the providers spell them differently (`web_search_20250305`, `googleSearch`
//! and `google_search`, `urlContext` and `url_context`, `mcp`, `mcp_toolset`).
//!
//! The body is read through a derived struct, so a duplicated key is refused outright: what is
//! checked here is what the upstream reads.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A field whose presence is the finding, whatever it holds (even `null`).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(d).map(|_| true)
}

#[derive(Deserialize)]
pub(super) struct Probe {
    pub model: Option<String>,
    max_tokens: Option<Value>,
    max_output_tokens: Option<Value>,
    max_completion_tokens: Option<Value>,
    #[serde(alias = "generationConfig")]
    generation_config: Option<Value>,
    tools: Option<Value>,
    #[serde(default, alias = "mcpServers", deserialize_with = "present")]
    mcp_servers: bool,
    #[serde(default, alias = "webSearchOptions", deserialize_with = "present")]
    web_search_options: bool,
}

/// The output cap assumed for a request that names none: the running cut-off, not this, is what
/// bounds a stream, so the hold is large enough to be honest and small enough to be usable.
// ponytail: one default for every model; read it from the price book when a model needs more.
pub(super) const DEFAULT_MAX_OUTPUT: u64 = 32_768;

fn normal(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// A tool name or key that gives the provider network reach on the agent's behalf.
fn reaches_network(s: &str) -> bool {
    let s = normal(s);
    ["websearch", "webfetch", "urlcontext", "googlesearch", "mcp"]
        .iter()
        .any(|w| s.contains(w))
}

impl Probe {
    /// The cap on the reply's output tokens the request asks for, the largest of the spellings.
    pub(super) fn max_output(&self) -> u64 {
        let gen_cfg = self.generation_config.as_ref().and_then(|g| {
            g.get("maxOutputTokens")
                .or_else(|| g.get("max_output_tokens"))
        });
        [
            self.max_tokens.as_ref(),
            self.max_output_tokens.as_ref(),
            self.max_completion_tokens.as_ref(),
            gen_cfg,
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .max()
        .unwrap_or(DEFAULT_MAX_OUTPUT)
    }

    /// Why the request may not be sent: it asks the provider to reach the network.
    pub(super) fn network_tool(&self) -> Option<&'static str> {
        if self.mcp_servers || self.web_search_options {
            return Some("tool_not_allowed");
        }
        let tools = self.tools.as_ref()?;
        let list: &[Value] = match tools {
            Value::Array(a) => a,
            one => std::slice::from_ref(one),
        };
        let bad = |t: &Value| {
            let Value::Object(m) = t else { return false };
            m.iter().any(|(k, v)| {
                reaches_network(k) || (k == "type" && v.as_str().is_some_and(reaches_network))
            })
        };
        list.iter().any(bad).then_some("tool_not_allowed")
    }
}

/// The `anthropic-beta` values the gateway passes. A beta feature that is not here is dropped
/// from the header (the request goes without it): several betas give the provider reach the
/// agent does not have (MCP connector, web fetch, code execution, the files API), so the list
/// is a short allowlist in code, not a pass-through. Extend it when a harness's smoke run shows
/// one it needs.
const BETAS: [&str; 8] = [
    "claude-code-20250219",
    "interleaved-thinking-2025-05-14",
    "fine-grained-tool-streaming-2025-05-14",
    "context-management-2025-06-27",
    "extended-cache-ttl-2025-04-11",
    "token-efficient-tools-2025-02-19",
    "output-128k-2025-02-19",
    "context-1m-2025-08-07",
];

/// `value` of an `anthropic-beta` header cut down to the allowlisted betas; `None` when none is.
pub(super) fn betas(value: &str) -> Option<String> {
    let kept: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|b| BETAS.contains(b))
        .collect();
    (!kept.is_empty()).then(|| kept.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(body: &str) -> Result<Probe, serde_json::Error> {
        serde_json::from_str(body)
    }

    #[test]
    fn the_output_cap_is_the_largest_spelling_or_the_default() {
        for (body, want) in [
            (r#"{"model":"m","max_tokens":100}"#, 100),
            (r#"{"max_output_tokens":7,"max_completion_tokens":9}"#, 9),
            (r#"{"generationConfig":{"maxOutputTokens":55}}"#, 55),
            (r#"{"generation_config":{"max_output_tokens":56}}"#, 56),
            (r#"{"max_tokens":"lots"}"#, DEFAULT_MAX_OUTPUT),
            (r#"{"model":"m"}"#, DEFAULT_MAX_OUTPUT),
        ] {
            assert_eq!(probe(body).unwrap().max_output(), want, "{body}");
        }
    }

    #[test]
    fn a_duplicate_key_is_refused_so_what_is_checked_is_what_is_read() {
        for body in [
            r#"{"model":"a","model":"b"}"#,
            r#"{"max_tokens":1,"max_tokens":2}"#,
            r#"{"generationConfig":{},"generation_config":{}}"#,
            r#"{"mcp_servers":[],"mcp_servers":[]}"#,
        ] {
            assert!(probe(body).is_err(), "{body}");
        }
    }

    #[test]
    fn server_side_tools_that_reach_the_network_are_refused_in_every_spelling() {
        for body in [
            // Anthropic: the MCP connector, server web search and fetch, the toolset.
            r#"{"mcp_servers":[{"type":"url","url":"u","name":"n"}]}"#,
            r#"{"mcp_servers":null}"#,
            r#"{"tools":[{"type":"web_search_20250305","name":"web_search"}]}"#,
            r#"{"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}"#,
            r#"{"tools":[{"type":"mcp_toolset","mcp_server_name":"n"}]}"#,
            // OpenAI: remote MCP, web search, the chat-completions search option.
            r#"{"tools":[{"type":"mcp","server_url":"u"}]}"#,
            r#"{"tools":[{"type":"web_search"}]}"#,
            r#"{"tools":[{"type":"web_search_preview_2025_03_11"}]}"#,
            r#"{"web_search_options":{}}"#,
            r#"{"webSearchOptions":{}}"#,
            // Gemini: URL context and search grounding, both spellings, and the older retrieval.
            r#"{"tools":[{"url_context":{}}]}"#,
            r#"{"tools":[{"urlContext":{}}]}"#,
            r#"{"tools":[{"google_search":{}}]}"#,
            r#"{"tools":[{"googleSearch":{}}]}"#,
            r#"{"tools":[{"googleSearchRetrieval":{}}]}"#,
            r#"{"tools":{"google_search":{}}}"#,
            // A function tool next to one does not hide it.
            r#"{"tools":[{"type":"function","name":"f"},{"type":"web_search"}]}"#,
        ] {
            assert_eq!(
                probe(body).unwrap().network_tool(),
                Some("tool_not_allowed"),
                "{body}"
            );
        }
    }

    #[test]
    fn the_agents_own_tools_pass() {
        for body in [
            r#"{"model":"m"}"#,
            r#"{"tools":[]}"#,
            r#"{"tools":[{"type":"function","name":"web_search_helper","description":"mcp"}]}"#,
            r#"{"tools":[{"name":"read","input_schema":{"type":"object"}}]}"#,
            r#"{"tools":[{"functionDeclarations":[{"name":"f"}]}]}"#,
            r#"{"tools":[{"type":"custom","name":"bash"}]}"#,
        ] {
            assert_eq!(probe(body).unwrap().network_tool(), None, "{body}");
        }
    }

    #[test]
    fn only_allowlisted_betas_are_passed() {
        assert_eq!(
            betas("claude-code-20250219, mcp-client-2025-04-04,context-1m-2025-08-07").as_deref(),
            Some("claude-code-20250219,context-1m-2025-08-07")
        );
        assert_eq!(
            betas("web-fetch-2025-09-10, code-execution-2025-05-22"),
            None
        );
        assert_eq!(betas(""), None);
    }
}
