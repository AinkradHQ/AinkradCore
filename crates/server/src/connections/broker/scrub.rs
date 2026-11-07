//! What goes back to the harness is cleaned first: the connection's own credential, wherever an
//! upstream echoed it (every string and every key), and anything of a known credential shape
//! (the proto redactor). The adapters already cut the exact token from what they return; this is
//! the broker's own pass, for both kinds, so the guarantee does not rest on an adapter.

use ainkrad_proto::redact::Redactor;
use serde_json::{Map, Value};

const MARK: &str = "[redacted]";

fn clean_text(s: &str, secrets: &[&str], shapes: &Redactor) -> String {
    let mut out = s.to_owned();
    for secret in secrets.iter().filter(|x| !x.is_empty()) {
        if out.contains(secret) {
            out = out.replace(secret, MARK);
        }
    }
    shapes.text(&out)
}

/// `v` with every `secrets` value and every recognised credential shape replaced.
pub fn clean(v: Value, secrets: &[&str], shapes: &Redactor) -> Value {
    match v {
        Value::String(s) => Value::String(clean_text(&s, secrets, shapes)),
        Value::Array(a) => Value::Array(a.into_iter().map(|x| clean(x, secrets, shapes)).collect()),
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, x)| (clean_text(&k, secrets, shapes), clean(x, secrets, shapes)))
                .collect::<Map<_, _>>(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_token_and_credential_shapes_are_cut_from_every_string_and_key() {
        let r = Redactor::new();
        let v = json!({"a": "x c1probe-7f3a9d41e0b2 y", "c1probe-7f3a9d41e0b2": [1, "c1probe-7f3a9d41e0b2"],
            "n": 3, "gh": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"});
        let out = clean(v, &["c1probe-7f3a9d41e0b2"], &r).to_string();
        assert!(!out.contains("c1probe"), "{out}");
        assert!(!out.contains("ghp_abcdef"), "{out}");
        assert!(out.contains("[redacted]") && out.contains("\"n\":3"));
    }
}
