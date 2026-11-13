//! The catalogue builder (E1.2): allow-listed operations out of the contract, `$ref`s inlined.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{Allowed, Catalogue, Op, Param, Risk};

/// A resolved schema bigger than this (as JSON text) is listed as an open object, with a warning.
const MAX_SCHEMA_BYTES: usize = 24 * 1024;

fn open() -> Value {
    json!({"type": "object", "additionalProperties": true})
}

/// `v` with every `#/components/schemas/X` reference inlined. A cycle or a reference that is not
/// there becomes `{}` and a warning (`cyclic ref` / `unresolved ref`).
fn resolve(spec: &Value, v: &Value, stack: &mut Vec<String>, warns: &mut Vec<String>) -> Value {
    match v {
        Value::Object(m) => {
            if let Some(r) = m.get("$ref").and_then(Value::as_str) {
                let name = r.strip_prefix("#/components/schemas/").unwrap_or("");
                let Some(target) = spec["components"]["schemas"].get(name) else {
                    warns.push(format!("unresolved ref {r}"));
                    return json!({});
                };
                if stack.iter().any(|s| s == name) {
                    warns.push(format!("cyclic ref {r}"));
                    return json!({});
                }
                stack.push(name.to_owned());
                let out = resolve(spec, target, stack, warns);
                stack.pop();
                return out;
            }
            Value::Object(
                m.iter()
                    .map(|(k, x)| (k.clone(), resolve(spec, x, stack, warns)))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| resolve(spec, x, stack, warns)).collect()),
        other => other.clone(),
    }
}

fn schema(spec: &Value, s: &Value, what: &str, warns: &mut Vec<String>) -> Value {
    let out = resolve(spec, s, &mut Vec::new(), warns);
    if out.to_string().len() > MAX_SCHEMA_BYTES {
        warns.push(format!(
            "{what}: schema over {MAX_SCHEMA_BYTES} bytes, listed open"
        ));
        return open();
    }
    out
}

/// `agent-sessions` is `agent_sessions`; a module's route is its module id.
fn group(path: &str) -> String {
    let mut seg = path.trim_start_matches('/').split('/');
    let first = match seg.next() {
        Some("modules") => seg.next(),
        Some("api") => seg.nth(1),
        other => other,
    };
    first.unwrap_or("core").replace('-', "_")
}

fn json_schema(content: &Value) -> Option<&Value> {
    content
        .get("content")?
        .get("application/json")?
        .get("schema")
}

fn response(op: &Value) -> Option<&Value> {
    let rs = op["responses"].as_object()?;
    let key = ["200", "201"]
        .into_iter()
        .find(|k| rs.contains_key(*k))
        .or_else(|| rs.keys().map(String::as_str).find(|k| k.starts_with('2')))?;
    json_schema(&rs[key])
}

/// The operations of `allow` found in `spec` (the contract as `spec::json_for` prints it). One
/// the contract lacks is left out with a warning (the gate test in this module fails on it).
pub fn build(spec: &Value, allow: &[Allowed]) -> Catalogue {
    let mut found: BTreeMap<&str, (&str, &str, &Value, &Value)> = BTreeMap::new();
    for (path, item) in spec["paths"].as_object().into_iter().flatten() {
        for (method, op) in item.as_object().into_iter().flatten() {
            if let Some(id) = op["operationId"].as_str() {
                found.insert(id, (path, method, op, item));
            }
        }
    }
    let mut cat = Catalogue::default();
    for a in allow {
        let Some(&(path, method, op, item)) = found.get(a.op.as_str()) else {
            cat.warnings
                .push(format!("{}: not in the contract, left out", a.op));
            continue;
        };
        if !super::exposed(path) {
            cat.warnings
                .push(format!("{}: a route no session reaches, left out", a.op));
            continue;
        }
        let w = &mut cat.warnings;
        let mut params = Vec::new();
        // Path-level parameters first; an operation's own of the same name and place wins.
        for p in item["parameters"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(op["parameters"].as_array().into_iter().flatten())
        {
            let (Some(name), Some(loc)) = (p["name"].as_str(), p["in"].as_str()) else {
                continue;
            };
            params.retain(|q: &Param| !(q.name == name && q.location == loc));
            params.push(Param {
                name: name.to_owned(),
                location: loc.to_owned(),
                required: p["required"].as_bool().unwrap_or(false) || loc == "path",
                schema: schema(spec, &p["schema"], &format!("{}.{name}", a.op), w),
            });
        }
        let body = op["requestBody"]
            .get("content")
            .and(json_schema(&op["requestBody"]))
            .map(|s| schema(spec, s, &format!("{} body", a.op), w));
        let response = response(op).map(|s| schema(spec, s, &format!("{} response", a.op), w));
        let risk = a.risk.unwrap_or(if method.eq_ignore_ascii_case("get") {
            Risk::Read
        } else {
            Risk::Risky
        });
        cat.ops.insert(
            a.op.clone(),
            Op {
                id: a.op.clone(),
                group: group(path),
                method: method.to_ascii_uppercase(),
                path: path.to_owned(),
                params,
                body,
                response,
                scope: op["x-ainkrad-scope"].as_str().unwrap_or("admin").to_owned(),
                risk,
                summary: a.summary.clone(),
            },
        );
    }
    cat
}
