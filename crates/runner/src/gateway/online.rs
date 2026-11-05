//! OpenRouter's server-side web search (KAN-435 G7, threat T6): a request that makes the provider
//! search the web for the agent is a second route out of the sandbox, and one whose cost the
//! gateway cannot see. OpenRouter has two spellings, both refused on every wire:
//!
//! - the model suffix `:online` (`vendor/model:online`), on `model` and on every entry of `models`
//!   (the fallback list);
//! - the `web` plugin: `"plugins": [{"id": "web"}]`. `plugins` that is not a list of objects is
//!   refused too, since this check cannot tell what it names.
//!
//! The model allowlist already refuses an id that was not granted; this holds even if a price book
//! lists one, and names the reason. (The Core refuses `:online` ids at the price book too.)

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Body {
    model: Option<Value>,
    models: Option<Value>,
    plugins: Option<Value>,
}

fn online(model: &Value) -> bool {
    model
        .as_str()
        .is_some_and(|m| m.to_ascii_lowercase().ends_with(":online"))
}

fn web(plugin: &Value) -> bool {
    match plugin {
        Value::Object(o) => o
            .get("id")
            .is_none_or(|id| id.as_str().is_none_or(|i| i.eq_ignore_ascii_case("web"))),
        _ => true,
    }
}

/// Whether the request asks the provider for a web search. A body that is not readable here is
/// left to the checks that already refused it.
pub(super) fn refusal(body: &[u8]) -> bool {
    let Ok(b) = serde_json::from_slice::<Body>(body) else {
        return false;
    };
    b.model.as_ref().is_some_and(online)
        || b.models
            .as_ref()
            .is_some_and(|m| m.as_array().is_some_and(|l| l.iter().any(online)))
        || b.plugins.as_ref().is_some_and(|p| match p {
            Value::Null => false,
            Value::Array(list) => list.iter().any(web),
            _ => true,
        })
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn the_web_plugin_and_the_online_suffix_are_refused() {
        for body in [
            r#"{"model":"vendor/m:online"}"#,
            r#"{"model":"vendor/m:ONLINE"}"#,
            r#"{"model":"a","models":["b","vendor/m:online"]}"#,
            r#"{"model":"a","plugins":[{"id":"web"}]}"#,
            r#"{"model":"a","plugins":[{"id":"web","max_results":3}]}"#,
            r#"{"model":"a","plugins":[{"id":"WEB"}]}"#,
            r#"{"model":"a","plugins":[{"id":"file-parser"},{"id":"web"}]}"#,
            // Not a shape this can read: refused, not guessed.
            r#"{"model":"a","plugins":{"id":"file-parser"}}"#,
            r#"{"model":"a","plugins":["web"]}"#,
            r#"{"model":"a","plugins":[{"name":"web"}]}"#,
            r#"{"model":"a","plugins":[{"id":7}]}"#,
        ] {
            assert!(refusal(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn an_ordinary_request_passes() {
        for body in [
            r#"{"model":"vendor/m"}"#,
            r#"{"model":"vendor/m:floor","models":["vendor/n"]}"#,
            r#"{"model":"a","plugins":null}"#,
            r#"{"model":"a","plugins":[]}"#,
            r#"{"model":"a","plugins":[{"id":"file-parser"}]}"#,
            r#"{"model":"online"}"#,
            r#"{"model":"m:online-x"}"#,
            r#"{"model":"a","messages":[{"role":"user","content":"use plugins web :online"}]}"#,
        ] {
            assert!(!refusal(body.as_bytes()), "{body}");
        }
    }
}
