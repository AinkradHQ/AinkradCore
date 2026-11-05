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
//! A duplicated JSON key at any depth is refused outright ([`Strict`]), so what is checked here is
//! what the upstream reads, whichever of two copies it would take.
//!
//! Also refused, because a reply's size is then not bounded by the output cap the reservation is
//! priced from: more than one candidate (`n`, `candidateCount`), and a Responses `background`
//! run (the provider works on after the gateway has stopped counting).

use std::collections::HashSet;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Reads a JSON document and fails on the first object that names a key twice, at any depth. Keys
/// are compared as decoded, so `"model"` and `"\u006dodel"` are the same key.
struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with no repeated key")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Strict)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(A::Error::custom("a key is repeated"));
            }
            map.next_value_seed(Strict)?;
        }
        Ok(())
    }
}

/// A field whose presence is the finding, whatever it holds (even `null`).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(d).map(|_| true)
}

#[derive(Deserialize)]
pub(super) struct Probe {
    pub model: Option<String>,
    stream: Option<Value>,
    n: Option<Value>,
    background: Option<Value>,
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
///
/// Also refused: provider-side tools the gateway can neither check against the grant nor price,
/// when unsure by name: the advisor (a second model run by the provider), code execution and the
/// server-side tool search.
fn reaches_network(s: &str) -> bool {
    let s = normal(s);
    [
        "websearch",
        "webfetch",
        "urlcontext",
        "googlesearch",
        "mcp",
        "advisor",
        "codeexecution",
        "toolsearchtool",
    ]
    .iter()
    .any(|w| s.contains(w))
}

impl Probe {
    /// The cap on the reply's output tokens the request names, the largest of the spellings.
    pub(super) fn max_output(&self) -> Option<u64> {
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
    }

    /// The output cap the reservation is priced from, or `None` when the request must be refused:
    /// a reply that is not streamed is bounded by nothing but this cap, so a request that names
    /// none is not given one. A streamed reply is bounded by the running cut-off as well, so it
    /// is held at [`DEFAULT_MAX_OUTPUT`].
    pub(super) fn output_cap(&self, route_streams: bool) -> Option<u64> {
        let streams = route_streams || self.stream.as_ref().and_then(Value::as_bool) == Some(true);
        self.max_output().or(streams.then_some(DEFAULT_MAX_OUTPUT))
    }

    /// Why the request may not be sent, as a code: it asks the provider to reach the network, to
    /// answer with more than one candidate, or to carry on in the background.
    pub(super) fn refusal(&self) -> Option<&'static str> {
        // One candidate or none named: absent, null or the integer 1. `2.0` and `"2"` are refused.
        let not_one = |v: Option<&Value>| match v {
            None | Some(Value::Null) => false,
            Some(v) => v.as_u64() != Some(1),
        };
        let gen_cfg = |k: &str| self.generation_config.as_ref().and_then(|g| g.get(k));
        let background = !matches!(
            self.background,
            None | Some(Value::Null | Value::Bool(false))
        );
        if not_one(self.n.as_ref())
            || not_one(gen_cfg("candidateCount"))
            || not_one(gen_cfg("candidate_count"))
            || background
        {
            return Some("param_not_allowed");
        }
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

/// Reads a request body: an object, no key repeated at any depth, and the fields the gateway
/// checks.
pub(super) fn parse(body: &[u8]) -> Result<Probe, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(body);
    Strict.deserialize(&mut de)?;
    de.end()?;
    serde_json::from_slice(body)
}

/// The body with `maxOutputTokens` set to [`DEFAULT_MAX_OUTPUT`] in its generation config (made
/// if absent), for a Gemini request that names no cap and is not streamed: the cap is the one the
/// reservation holds, so the reply cannot outrun it. `None` when the config is not an object.
pub(super) fn with_default_cap(body: &[u8]) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(body).ok()?;
    let m = v.as_object_mut()?;
    let (key, name) = if m.contains_key("generation_config") {
        ("generation_config", "max_output_tokens")
    } else {
        ("generationConfig", "maxOutputTokens")
    };
    let cfg = m
        .entry(key)
        .or_insert_with(|| Value::Object(Default::default()));
    if cfg.is_null() {
        *cfg = Value::Object(Default::default());
    }
    cfg.as_object_mut()?
        .insert(name.to_owned(), DEFAULT_MAX_OUTPUT.into());
    serde_json::to_vec(&v).ok()
}

/// The `anthropic-beta` values the gateway passes. A beta feature that is not here is dropped
/// from the header (the request goes without it): several betas give the provider reach the
/// agent does not have (MCP connector, web fetch, code execution, the files API), so the list
/// is a short allowlist in code, not a pass-through. Extend it when a harness's smoke run shows
/// one it needs.
const BETAS: [&str; 15] = [
    // What Claude Code 2.1.318 sends on an API-key turn (read from a request to a local listener,
    // 2026-11-05), less `advisor-tool-2026-03-01`: it only matters when the advisor tool is in the
    // request, and that tool is refused. None of these gives the provider network reach.
    "claude-code-20250219",
    "interleaved-thinking-2025-05-14",
    "context-management-2025-06-27",
    "per-turn-control-2026-07-01",
    "mid-conversation-tool-changes-2026-07-01",
    "inline-tools-2026-09-15",
    "thinking-token-count-2026-05-13",
    "advanced-tool-use-2025-11-20",
    "effort-2025-11-24",
    // Added from the adapter-mode run of 2.1.318 (2026-11-05); it only changes how thinking is shown.
    "thinking-display-updates-2026-08-18",
    // Older ones a harness may still send.
    "fine-grained-tool-streaming-2025-05-14",
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
    use serde_json::json;

    fn probe(body: &str) -> Result<Probe, serde_json::Error> {
        parse(body.as_bytes())
    }

    #[test]
    fn the_output_cap_is_the_largest_spelling_and_a_streamed_request_without_one_is_held_at_the_default()
     {
        for (body, want) in [
            (r#"{"model":"m","max_tokens":100}"#, Some(100)),
            (
                r#"{"max_output_tokens":7,"max_completion_tokens":9}"#,
                Some(9),
            ),
            (r#"{"generationConfig":{"maxOutputTokens":55}}"#, Some(55)),
            (
                r#"{"generation_config":{"max_output_tokens":56}}"#,
                Some(56),
            ),
            (r#"{"max_tokens":"lots"}"#, None),
            (r#"{"model":"m"}"#, None),
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
            // Provider-side tools the gateway can neither check nor price.
            r#"{"tools":[{"type":"advisor_20260301","name":"advisor","model":"x"}]}"#,
            r#"{"tools":[{"type":"code_execution_20250825","name":"code_execution"}]}"#,
            r#"{"tools":[{"type":"tool_search_tool_regex_20251119","name":"tool_search"}]}"#,
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
                probe(body).unwrap().refusal(),
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
            assert_eq!(probe(body).unwrap().refusal(), None, "{body}");
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
        assert_eq!(
            betas("claude-code-20250219,advisor-tool-2026-03-01").as_deref(),
            Some("claude-code-20250219")
        );
        assert_eq!(betas(""), None);
    }

    #[test]
    fn a_reply_that_is_not_streamed_must_name_its_cap_and_a_streamed_one_gets_the_default() {
        let none = probe(r#"{"model":"m"}"#).unwrap();
        assert_eq!(
            none.output_cap(false),
            None,
            "not streamed, no cap: refused"
        );
        assert_eq!(
            none.output_cap(true),
            Some(DEFAULT_MAX_OUTPUT),
            "the route streams"
        );
        let body = probe(r#"{"model":"m","stream":true}"#).unwrap();
        assert_eq!(body.output_cap(false), Some(DEFAULT_MAX_OUTPUT));
        let off = probe(r#"{"model":"m","stream":false}"#).unwrap();
        assert_eq!(off.output_cap(false), None);
        assert_eq!(
            probe(r#"{"max_tokens":9}"#).unwrap().output_cap(false),
            Some(9)
        );
    }

    #[test]
    fn more_than_one_candidate_and_background_runs_are_refused() {
        for body in [
            r#"{"n":2}"#,
            r#"{"generationConfig":{"candidateCount":3}}"#,
            r#"{"generation_config":{"candidate_count":2}}"#,
            r#"{"background":true}"#,
            r#"{"background":"true"}"#,
            r#"{"n":2.0}"#,
            r#"{"n":"2"}"#,
            r#"{"generationConfig":{"candidateCount":1,"candidate_count":2}}"#,
            r#"{"generationConfig":{"candidateCount":"1"}}"#,
        ] {
            assert_eq!(
                probe(body).unwrap().refusal(),
                Some("param_not_allowed"),
                "{body}"
            );
        }
        for body in [
            r#"{"n":1}"#,
            r#"{"generationConfig":{"candidateCount":1}}"#,
            r#"{"n":null}"#,
            r#"{"background":false}"#,
            r#"{"background":null}"#,
        ] {
            assert_eq!(probe(body).unwrap().refusal(), None, "{body}");
        }
    }

    #[test]
    fn a_repeated_key_at_any_depth_is_refused_even_where_a_checked_field_hides() {
        for body in [
            r#"{"tools":[{"type":"web_search_20250305","type":"function"}]}"#,
            r#"{"tools":[{"type":"function","type":"web_search"}]}"#,
            r#"{"a":{"b":[{"c":1,"c":2}]}}"#,
            r#"{"generationConfig":{"candidateCount":1,"candidateCount":9}}"#,
            r#"{"m\u006fdel":"a","model":"b"}"#,
        ] {
            assert!(probe(body).is_err(), "{body}");
        }
        // Repeats in different objects are not repeats; trailing junk is refused.
        assert!(probe(r#"{"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]}"#).is_ok());
        assert!(probe(r#"{"a":1} x"#).is_err());
    }

    #[test]
    fn a_gemini_request_without_a_cap_is_given_the_default_in_its_own_spelling() {
        let cap = |body: &str| {
            let v: Value =
                serde_json::from_slice(&with_default_cap(body.as_bytes()).unwrap()).unwrap();
            v
        };
        assert_eq!(
            cap("{}")["generationConfig"]["maxOutputTokens"],
            DEFAULT_MAX_OUTPUT
        );
        assert_eq!(
            cap(r#"{"generation_config":{"temperature":1}}"#)["generation_config"]["max_output_tokens"],
            DEFAULT_MAX_OUTPUT
        );
        let kept = cap(r#"{"contents":[1],"generationConfig":{"temperature":1}}"#);
        assert_eq!(kept["generationConfig"]["temperature"], 1);
        assert_eq!(kept["contents"], json!([1]));
        assert!(with_default_cap(br#"{"generationConfig":"x"}"#).is_none());
        // What comes out names a cap.
        let body = with_default_cap(b"{}").unwrap();
        assert!(parse(&body).unwrap().output_cap(false).is_some());
    }
}
