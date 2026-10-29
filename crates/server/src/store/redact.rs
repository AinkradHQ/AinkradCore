//! Redaction at append (E1-10.2, threat model T-EV-2, T-AUD-3): an audit row's `details` and an
//! event's `payload` never hold a secret value. Two passes over the JSON:
//!
//! 1. A value under a key named like a secret is replaced by `[redacted:<key>]`: any word of the
//!    key (split at `_`, `-`, `.` and lower-to-upper case changes) is `secret`, `token`,
//!    `password`, `passwd`, `credential(s)`, `authorization` or `apikey`, or the key ends in a
//!    `key` word after another word (`api_key`, `privateKey`). A bare `key` is left alone: it
//!    names a setting in `setting.set` (and `settings::history` reads it).
//! 2. Every string, keys included, goes through `ainkrad_proto::redact::Redactor`, which masks
//!    known secret shapes (provider keys, `Bearer …`, PEM blocks, …).

use ainkrad_proto::redact::Redactor;
use serde_json::Value;

const SECRET_WORDS: &[&str] = &[
    "secret",
    "secrets",
    "token",
    "password",
    "passwd",
    "credential",
    "credentials",
    "authorization",
    "apikey",
];

/// The lowercase words of a key: `apiKey` and `api_key` are both `api`, `key`.
fn words(key: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut prev_lower = false;
    for c in key.chars() {
        if !c.is_alphanumeric() {
            out.push(String::new());
            prev_lower = false;
            continue;
        }
        if c.is_uppercase() && prev_lower {
            out.push(String::new());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        out.last_mut()
            .expect("never empty")
            .extend(c.to_lowercase());
    }
    out.retain(|w| !w.is_empty());
    out
}

/// Whether a value under `key` is a secret by its name.
fn secret_name(key: &str) -> bool {
    let words = words(key);
    words.iter().any(|w| SECRET_WORDS.contains(&w.as_str()))
        || (words.len() > 1 && words.last().is_some_and(|w| w == "key"))
}

/// Masks `value` in place (both passes).
pub fn json(value: &mut Value) {
    mask_names(value);
    Redactor::new().json(value);
}

fn mask_names(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if secret_name(key) && !v.is_null() {
                    *v = Value::String(format!("[redacted:{key}]"));
                } else {
                    mask_names(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(mask_names),
        _ => {}
    }
}

/// `text` (JSON) with its secrets masked; unchanged when it is not JSON (the store's own check
/// refuses it) or holds no secret.
pub fn text(text: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(text) else {
        return text.to_owned();
    };
    let before = value.clone();
    json(&mut value);
    if value == before {
        text.to_owned()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use ainkrad_proto::redact::PLANTED;
    use serde_json::json;

    use super::*;

    #[test]
    fn secret_names_and_shapes_are_masked_and_the_rest_kept() {
        for key in [
            "token",
            "push_token",
            "apiKey",
            "api_key",
            "private-key",
            "client_secret",
            "Authorization",
            "password",
            "db.credentials",
        ] {
            assert!(secret_name(key), "{key}");
        }
        for key in ["key", "keys", "monkey", "name", "tokens_used", "scope"] {
            assert!(!secret_name(key), "{key}");
        }
        let mut v = json!({"key": "scheduler.tick_secs", "nested": [{"password": "hunter22"}],
                           "note": format!("use {}", PLANTED[0].1), "gone": null, "token": null});
        json(&mut v);
        assert_eq!(v["key"], "scheduler.tick_secs");
        assert_eq!(v["nested"][0]["password"], "[redacted:password]");
        assert_eq!(v["note"], "use [redacted:anthropic_key]");
        assert_eq!(v["token"], Value::Null, "nothing to hide");
        assert_eq!(text("{not json"), "{not json");
        assert_eq!(text(r#"{"b":1, "a":2}"#), r#"{"b":1, "a":2}"#, "untouched");
    }
}
