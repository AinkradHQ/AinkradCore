//! Argument checking for `ainkrad.call` (E2.2): the script's flat `args` object against the
//! operation's parameters, built into the request target. Invalid arguments never reach a handler.

use serde_json::Value;

use super::Op;

/// The longest path value or query value, in bytes.
const MAX_VALUE: usize = 256;

/// The most bytes of a request body.
const MAX_BODY: usize = 64 * 1024;

/// The deepest body checked; a deeper value is refused.
const MAX_DEPTH: u8 = 8;

/// The request of a call: its target (see [`target`]) and, for an operation with a body, the JSON
/// body from `args.body`, checked against the body schema (types, required, enum, bounds, no
/// unknown field where the schema forbids them).
///
/// # Errors
///
/// As [`target`]; a body missing, over [`MAX_BODY`], or not matching its schema.
pub fn request(op: &Op, args: &Value) -> Result<(String, Option<Vec<u8>>), String> {
    let (rest, body) = match (args, &op.body) {
        (Value::Object(m), Some(_)) => {
            let mut m = m.clone();
            let body = m.remove("body");
            (Value::Object(m), body)
        }
        _ => (args.clone(), None),
    };
    let target = target(op, &rest)?;
    let Some(schema) = &op.body else {
        return Ok((target, None));
    };
    let body = body.filter(|b| !b.is_null()).ok_or("body is required")?;
    value(schema, &body, MAX_DEPTH).map_err(|why| format!("body: {why}"))?;
    let bytes = serde_json::to_vec(&body).map_err(|_| "body is not JSON".to_owned())?;
    if bytes.len() > MAX_BODY {
        return Err("body: too large".to_owned());
    }
    Ok((target, Some(bytes)))
}

/// `v` against `schema` all the way down (objects, arrays, scalars).
fn value(schema: &Value, v: &Value, depth: u8) -> Result<(), &'static str> {
    if depth == 0 {
        return Err("nested too deep");
    }
    check(schema, v)?;
    if let Some(any) = schema["anyOf"]
        .as_array()
        .or_else(|| schema["oneOf"].as_array())
    {
        return any
            .iter()
            .find_map(|s| value(s, v, depth - 1).ok())
            .ok_or("wrong type");
    }
    match v {
        Value::Object(m) => {
            let props = schema["properties"].as_object();
            for r in schema["required"].as_array().into_iter().flatten() {
                if r.as_str().is_some_and(|k| !m.contains_key(k)) {
                    return Err("a required field is missing");
                }
            }
            for (k, x) in m {
                match props.and_then(|p| p.get(k)) {
                    Some(s) => value(s, x, depth - 1)?,
                    None if schema["additionalProperties"] == false => {
                        return Err("an unknown field");
                    }
                    None => {}
                }
            }
        }
        Value::Array(a) => {
            if schema["maxItems"]
                .as_u64()
                .is_some_and(|m| a.len() as u64 > m)
            {
                return Err("too many items");
            }
            if schema["items"].is_object() {
                for x in a {
                    value(&schema["items"], x, depth - 1)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// `args` checked against `op`'s parameters, as the request target (`path?query`).
///
/// # Errors
///
/// A short reason (never an echo of a value): an unknown or missing key, a value of the wrong
/// type, outside the schema's enum or bounds, or a path value that is not one plain segment.
pub fn target(op: &Op, args: &Value) -> Result<String, String> {
    let empty = serde_json::Map::new();
    let given = match args {
        Value::Null => &empty,
        Value::Object(m) => m,
        _ => return Err("args must be an object".to_owned()),
    };
    if let Some(k) = given
        .keys()
        .find(|k| !op.params.iter().any(|p| &p.name == *k))
    {
        return Err(format!("unknown argument {}", short(k)));
    }
    let mut path = op.path.clone();
    let mut query = Vec::new();
    for p in &op.params {
        let Some(v) = given.get(&p.name).filter(|v| !v.is_null()) else {
            if p.required {
                return Err(format!("{} is required", p.name));
            }
            continue;
        };
        if v.is_object() || v.is_array() {
            return Err(format!("{}: not a plain value", p.name));
        }
        check(&p.schema, v).map_err(|why| format!("{}: {why}", p.name))?;
        let text = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if text.len() > MAX_VALUE {
            return Err(format!("{}: too long", p.name));
        }
        match p.location.as_str() {
            "path" => {
                // `.`/`..` are plain bytes but would name another route segment.
                if text.is_empty() || text == "." || text == ".." || !text.bytes().all(plain) {
                    return Err(format!("{}: not a plain id", p.name));
                }
                path = path.replace(&format!("{{{}}}", p.name), &text);
            }
            "query" => query.push(format!("{}={}", p.name, encode(&text))),
            _ => return Err(format!("{}: unsupported parameter place", p.name)),
        }
    }
    if path.contains('{') {
        return Err("a path parameter is missing".to_owned());
    }
    Ok(if query.is_empty() {
        path
    } else {
        format!("{path}?{}", query.join("&"))
    })
}

fn short(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(32)
        .collect()
}

/// A byte that may stand in a path segment unescaped.
fn plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b':')
}

fn encode(s: &str) -> String {
    use std::fmt::Write;
    s.bytes().fold(String::new(), |mut out, b| {
        if plain(b) && b != b':' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    })
}

/// The subset of JSON Schema a parameter uses: `type`, `enum`, bounds, length.
fn check(schema: &Value, v: &Value) -> Result<(), &'static str> {
    if let Some(any) = schema["anyOf"]
        .as_array()
        .or_else(|| schema["oneOf"].as_array())
    {
        return any
            .iter()
            .find_map(|s| check(s, v).ok())
            .ok_or("wrong type");
    }
    let types: Vec<&str> = match &schema["type"] {
        Value::String(t) => vec![t.as_str()],
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !types.is_empty() {
        let fits = |t: &&str| match *t {
            "string" => v.is_string(),
            "integer" => v.is_i64() || v.is_u64(),
            "number" => v.is_number(),
            "boolean" => v.is_boolean(),
            "null" => v.is_null(),
            "object" => v.is_object(),
            "array" => v.is_array(),
            _ => false,
        };
        if !types.iter().any(fits) {
            return Err("wrong type");
        }
    }
    if let Some(e) = schema["enum"].as_array()
        && !e.contains(v)
    {
        return Err("not an allowed value");
    }
    if let (Some(n), Some(min)) = (v.as_f64(), schema["minimum"].as_f64())
        && n < min
    {
        return Err("below the minimum");
    }
    if let (Some(n), Some(max)) = (v.as_f64(), schema["maximum"].as_f64())
        && n > max
    {
        return Err("above the maximum");
    }
    if let Some(s) = v.as_str() {
        let n = s.chars().count() as u64;
        if schema["maxLength"].as_u64().is_some_and(|m| n > m) {
            return Err("too long");
        }
        if schema["minLength"].as_u64().is_some_and(|m| n < m) {
            return Err("too short");
        }
    }
    Ok(())
}
