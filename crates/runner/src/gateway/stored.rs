//! OpenAI Responses requests that read state the provider holds (KAN-435 G6, threat T6).
//!
//! The reservation is priced from the request body. A body that names stored context instead of
//! carrying it is cheap to send and costly to run: `previous_response_id` and `conversation`
//! continue a stored thread, `prompt` is a stored prompt template, and an `item_reference` input
//! item pulls one stored item in. All four are refused. Codex does not send them: it sends the
//! whole input with `store: false` over HTTP (Codex 0.166.0, `supports_websockets = false`; the
//! websocket transport is what continues a response by id, and the gateway refuses the upgrade).
//! A refusal is a 403 before anything is dialled, so it spends nothing.

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// A field whose value, when it is not `null`, is the finding.
#[derive(Deserialize)]
struct Stored {
    previous_response_id: Option<IgnoredAny>,
    conversation: Option<IgnoredAny>,
    prompt: Option<IgnoredAny>,
    #[serde(default, deserialize_with = "has_item_reference")]
    input: bool,
}

/// Whether the `input` list has an `item_reference` item. Items are read one at a time, so a large
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
                found |= item.get("type").and_then(Value::as_str) == Some("item_reference");
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
        || s.input;
    stored.then_some("param_not_allowed")
}

#[cfg(test)]
mod tests {
    use super::refusal;

    #[test]
    fn a_request_that_continues_or_pulls_in_stored_state_is_refused() {
        for body in [
            r#"{"model":"m","previous_response_id":"resp_1"}"#,
            r#"{"model":"m","conversation":"conv_1"}"#,
            r#"{"model":"m","conversation":{"id":"conv_1"}}"#,
            r#"{"model":"m","prompt":{"id":"pmpt_1"}}"#,
            r#"{"model":"m","input":[{"type":"item_reference","id":"msg_1"}]}"#,
            r#"{"model":"m","input":[{"role":"user","content":"x"},{"type":"item_reference","id":"rs_1"}]}"#,
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
            r#"{"model":"m","input":"hi"}"#,
            r#"{"model":"m","input":[]}"#,
            r#"{"model":"m","previous_response_id":null,"conversation":null,"prompt":null}"#,
            // `item_reference` as text, or under another key, is not an item of that type.
            r#"{"model":"m","input":[{"type":"message","content":"item_reference"}]}"#,
            r#"{"model":"m","input":[{"kind":"item_reference"}]}"#,
            r#"{"model":"m","input":{"type":"item_reference"}}"#,
        ] {
            assert_eq!(refusal(body.as_bytes()), None, "{body}");
        }
    }
}
