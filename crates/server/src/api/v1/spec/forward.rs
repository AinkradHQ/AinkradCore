//! Forward compatibility of response bodies: an older client must ignore a field a newer Core adds.
//!
//! schemars/utoipa turn `#[serde(deny_unknown_fields)]` into `additionalProperties: false`, and a
//! generated client (swift-openapi-generator) then refuses a body with one more field. The server's own
//! input check is unchanged; only the PUBLISHED schema of anything a response can reach is opened.
//! A type shared by a request and a response is opened too: the server still rejects unknown request fields.

use std::collections::BTreeSet;

use serde_json::Value;

fn refs(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                match (k.as_str(), v.as_str()) {
                    ("$ref", Some(r)) => {
                        out.insert(r.to_owned());
                    }
                    _ => refs(v, out),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|v| refs(v, out)),
        _ => {}
    }
}

fn open(v: &mut Value) {
    match v {
        Value::Object(o) => {
            if o.get("additionalProperties") == Some(&Value::Bool(false)) {
                o.remove("additionalProperties");
            }
            o.values_mut().for_each(open);
        }
        Value::Array(a) => a.iter_mut().for_each(open),
        _ => {}
    }
}

/// JSON pointers (`#/components/...`) of the schemas and shared responses reachable from any response of `spec`.
pub fn response_schemas(spec: &Value) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    for item in spec["paths"].as_object().into_iter().flatten() {
        for op in item.1.as_object().into_iter().flatten() {
            refs(&op.1["responses"], &mut seen);
        }
    }
    let mut todo: Vec<String> = seen.iter().cloned().collect();
    while let Some(name) = todo.pop() {
        let mut next = BTreeSet::new();
        refs(spec.pointer(&name[1..]).unwrap_or(&Value::Null), &mut next);
        for n in next {
            if seen.insert(n.clone()) {
                todo.push(n);
            }
        }
    }
    seen
}

/// Drops `additionalProperties: false` from every response-reachable schema and inline response body.
pub fn open_responses(spec: &mut Value) {
    for name in response_schemas(spec) {
        if let Some(s) = spec.pointer_mut(&name[1..]) {
            open(s);
        }
    }
    for item in spec["paths"].as_object_mut().into_iter().flatten() {
        for op in item.1.as_object_mut().into_iter().flatten() {
            if let Some(r) = op.1.get_mut("responses") {
                open(r);
            }
        }
    }
}
