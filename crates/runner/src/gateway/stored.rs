//! OpenAI Responses requests that read or leave state the provider holds (KAN-435 G6, threat T6).
//!
//! The reservation is priced from the request body. A body that names stored context instead of
//! carrying it is cheap to send and costly to run: `previous_response_id` and `conversation`
//! continue a stored thread, `prompt` is a stored prompt template, and an input item that is a
//! bare reference (`item_reference`, or an item with no `type` and no `role`, such as `{"id": ..}`
//! or `{"type": null, "id": ..}`) pulls one stored item in. All are refused.
//!
//! Stored items can only exist if something stored them, and `store` defaults to true, so the
//! agent could make them itself. A request is therefore refused unless it says `"store": false`
//! (Codex 0.166.0 does, in every request of `codex app-server`). A refusal is a 403 before
//! anything is dialled, so it spends nothing.

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A field whose value, when it is not `null`, is the finding.
#[derive(Deserialize)]
struct Stored {
    previous_response_id: Option<IgnoredAny>,
    conversation: Option<IgnoredAny>,
    prompt: Option<IgnoredAny>,
    /// Anything but the literal `false`, `null` and absent included, is refused.
    store: Option<Value>,
    #[serde(default, deserialize_with = "has_item_reference")]
    input: bool,
}

/// Whether `item` pulls a stored item in: an `item_reference`, or an item with neither a `type`
/// nor a `role` (the shapes the provider resolves by `id`).
fn is_reference(item: &Value) -> bool {
    let typed = item.get("type").is_some_and(|t| !t.is_null());
    item.get("type").and_then(Value::as_str) == Some("item_reference")
        || (!typed && item.get("role").is_none())
}

/// Whether the `input` list has an item that is a bare reference to stored state. Items are read one at a time, so a large
/// input is never held whole. A string input (also valid) and any other shape hold none.
fn has_item_reference<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = bool;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a Responses input")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
            let mut found = false;
            while let Some(item) = seq.next_element::<Value>()? {
                found |= is_reference(&item);
            }
            Ok(found)
        }

        fn visit_str<E>(self, _: &str) -> Result<bool, E> {
            Ok(false)
        }

        fn visit_unit<E>(self) -> Result<bool, E> {
            Ok(false)
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(false)
        }

        fn visit_bool<E>(self, _: bool) -> Result<bool, E> {
            Ok(false)
        }

        fn visit_i64<E>(self, _: i64) -> Result<bool, E> {
            Ok(false)
        }

        fn visit_u64<E>(self, _: u64) -> Result<bool, E> {
            Ok(false)
        }

        fn visit_f64<E>(self, _: f64) -> Result<bool, E> {
            Ok(false)
        }
    }
    d.deserialize_any(V)
}

/// The refusal code when the Responses body `body` (an object, already parsed once) reads stored
/// state; `None` when it does not. A body that cannot be read here is refused too, so what is
/// checked is what the upstream reads.
pub(super) fn refusal(body: &[u8]) -> Option<&'static str> {
    let Ok(s) = serde_json::from_slice::<Stored>(body) else {
        return Some("bad_json");
    };
    let stored = s.previous_response_id.is_some()
        || s.conversation.is_some()
        || s.prompt.is_some()
        || s.store != Some(Value::Bool(false))
        || s.input;
    stored.then_some("param_not_allowed")
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn a_request_that_continues_or_pulls_in_stored_state_is_refused() {
        for body in [
            r#"{"model":"m","store":false,"previous_response_id":"resp_1"}"#,
            r#"{"model":"m","store":false,"conversation":"conv_1"}"#,
            r#"{"model":"m","store":false,"conversation":{"id":"conv_1"}}"#,
            r#"{"model":"m","store":false,"prompt":{"id":"pmpt_1"}}"#,
            r#"{"model":"m","store":false,"input":[{"type":"item_reference","id":"msg_1"}]}"#,
            r#"{"model":"m","store":false,"input":[{"role":"user","content":"x"},{"type":"item_reference","id":"rs_1"}]}"#,
            // A reference with no `type`, or a null one, and no `role`.
            r#"{"model":"m","store":false,"input":[{"id":"msg_1"}]}"#,
            r#"{"model":"m","store":false,"input":[{"type":null,"id":"msg_1"}]}"#,
            r#"{"model":"m","store":false,"input":[{"kind":"item_reference"}]}"#,
            r#"{"model":"m","store":false,"input":[{"role":"user","content":"x"},{"id":"rs_1"}]}"#,
        ] {
            assert_eq!(
                refusal(body.as_bytes()),
                Some("param_not_allowed"),
                "{body}"
            );
        }
    }

    #[test]
    fn a_request_that_does_not_say_store_false_is_refused() {
        for body in [
            // Omitted (the provider's default is to store), true, null, and not a boolean.
            r#"{"model":"m","input":"hi"}"#,
            r#"{"model":"m","store":true,"input":"hi"}"#,
            r#"{"model":"m","store":null,"input":"hi"}"#,
            r#"{"model":"m","store":"false","input":"hi"}"#,
            r#"{"model":"m","store":0,"input":"hi"}"#,
        ] {
            assert_eq!(
                refusal(body.as_bytes()),
                Some("param_not_allowed"),
                "{body}"
            );
        }
    }

    #[test]
    fn what_codex_sends_and_other_ordinary_bodies_pass() {
        for body in [
            r#"{"model":"m","stream":true,"store":false,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}"#,
            r#"{"model":"m","store":false,"input":"hi"}"#,
            r#"{"model":"m","store":false,"input":[]}"#,
            r#"{"model":"m","store":false,"previous_response_id":null,"conversation":null,"prompt":null}"#,
            // Items with a role (typed or not), and a typed item that is not a reference.
            r#"{"model":"m","store":false,"input":[{"role":"user","content":"x"}]}"#,
            r#"{"model":"m","store":false,"input":[{"type":"function_call_output","call_id":"c","output":"o"}]}"#,
            r#"{"model":"m","store":false,"input":[{"type":"message","content":"item_reference"}]}"#,
        ] {
            assert_eq!(refusal(body.as_bytes()), None, "{body}");
        }
    }
}
