//! OpenRouter's routing and server-side extras (KAN-435 G7, threat T6). A request that makes the
//! provider search the web for the agent is a second route out of the sandbox, and one whose cost
//! the gateway cannot see; a fallback list of models is a way round the model allowlist. All are
//! refused on every wire:
//!
//! - the model suffix `:online` (`vendor/model:online`), on `model` and on every entry of `models`;
//! - any `plugins` at all (OpenRouter's `web` plugin searches the web; the others change what the
//!   provider does with the request, and none of the three harnesses sends one). The allowlist is
//!   empty, as `tools.rs` allows only the harness's own tools;
//! - a `models` fallback list naming a model that was not granted: the allowlist checks `model`
//!   only, and the provider would route to the others.
//!
//! The Core refuses `:online` ids at the price book too, so a grant never carries one.

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

/// Whether the request asks the provider for a web search or any plugin. A body that is not
/// readable here is left to the checks that already refused it.
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
            Value::Array(list) => !list.is_empty(),
            _ => true,
        })
}

/// Whether the request's `models` fallback list names a model outside `allowed` (or is not a list
/// of names). An absent list, `null` and an empty list name none.
pub(super) fn unlisted(body: &[u8], allowed: &[String]) -> bool {
    let Ok(b) = serde_json::from_slice::<Body>(body) else {
        return false;
    };
    match b.models {
        None | Some(Value::Null) => false,
        Some(Value::Array(list)) => list
            .iter()
            .any(|m| m.as_str().is_none_or(|m| !allowed.iter().any(|a| a == m))),
        Some(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::{refusal, unlisted};

    #[test]
    fn plugins_and_the_online_suffix_are_refused() {
        for body in [
            r#"{"model":"vendor/m:online"}"#,
            r#"{"model":"vendor/m:ONLINE"}"#,
            r#"{"model":"a","models":["b","vendor/m:online"]}"#,
            r#"{"model":"a","plugins":[{"id":"web"}]}"#,
            r#"{"model":"a","plugins":[{"id":"web","max_results":3}]}"#,
            r#"{"model":"a","plugins":[{"id":"file-parser"}]}"#,
            r#"{"model":"a","plugins":{"id":"file-parser"}}"#,
            r#"{"model":"a","plugins":["web"]}"#,
            r#"{"model":"a","plugins":7}"#,
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
            r#"{"model":"online"}"#,
            r#"{"model":"m:online-x"}"#,
            r#"{"model":"a","messages":[{"role":"user","content":"use plugins web :online"}]}"#,
        ] {
            assert!(!refusal(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn a_fallback_list_may_name_only_granted_models() {
        let granted = ["vendor/a".to_owned(), "vendor/b".to_owned()];
        for body in [
            r#"{"model":"vendor/a","models":["vendor/a","vendor/c"]}"#,
            r#"{"model":"vendor/a","models":["vendor/c"]}"#,
            r#"{"model":"vendor/a","models":[7]}"#,
            r#"{"model":"vendor/a","models":"vendor/b"}"#,
        ] {
            assert!(unlisted(body.as_bytes(), &granted), "{body}");
        }
        for body in [
            r#"{"model":"vendor/a"}"#,
            r#"{"model":"vendor/a","models":null}"#,
            r#"{"model":"vendor/a","models":[]}"#,
            r#"{"model":"vendor/a","models":["vendor/b","vendor/a"]}"#,
        ] {
            assert!(!unlisted(body.as_bytes(), &granted), "{body}");
        }
    }
}
