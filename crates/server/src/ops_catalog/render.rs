//! The typed definition of one operation (E1.3): a short TypeScript-style declaration with its
//! arguments and RETURN type, which is what keeps a script correct. Write-only and
//! `x-ainkrad-secret` fields are never rendered.

use serde_json::Value;

use super::Op;

/// The most bytes a definition may take; a deeper type is cut to `object` until it fits.
const MAX_DEF: usize = 1536;

fn hidden(s: &Value) -> bool {
    s["writeOnly"] == true || s["x-ainkrad-secret"] == true
}

fn key(k: &str) -> String {
    if !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        k.to_owned()
    } else {
        format!("{k:?}")
    }
}

fn join(list: &Value, sep: &str, depth: u8) -> String {
    let mut parts: Vec<String> = Vec::new();
    for s in list.as_array().into_iter().flatten() {
        let t = ts(s, depth);
        if !parts.contains(&t) {
            parts.push(t);
        }
    }
    parts.join(sep)
}

fn object(s: &Value, depth: u8) -> String {
    let props = s["properties"].as_object().filter(|p| !p.is_empty());
    let Some(props) = props else {
        return match &s["additionalProperties"] {
            v @ Value::Object(_) if depth > 0 => format!("Record<string, {}>", ts(v, depth - 1)),
            _ => "object".to_owned(),
        };
    };
    if depth == 0 {
        return "object".to_owned();
    }
    let req: Vec<&str> = s["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let fields: Vec<String> = props
        .iter()
        .filter(|(_, v)| !hidden(v))
        .map(|(k, v)| {
            let opt = if req.contains(&k.as_str()) { "" } else { "?" };
            format!("{}{opt}: {}", key(k), ts(v, depth - 1))
        })
        .collect();
    format!("{{ {} }}", fields.join("; "))
}

fn ts(s: &Value, depth: u8) -> String {
    if let Some(e) = s["enum"].as_array() {
        return e
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(" | ");
    }
    for (k, sep) in [("anyOf", " | "), ("oneOf", " | "), ("allOf", " & ")] {
        if s[k].is_array() {
            return join(&s[k], sep, depth);
        }
    }
    let one = |t: &str| match t {
        "integer" | "number" => "number".to_owned(),
        "string" | "boolean" | "null" => t.to_owned(),
        "array" => {
            let inner = ts(&s["items"], depth.saturating_sub(1));
            if inner.contains([' ', '|', '&']) {
                format!("({inner})[]")
            } else {
                format!("{inner}[]")
            }
        }
        "object" => object(s, depth),
        _ => "unknown".to_owned(),
    };
    match &s["type"] {
        Value::String(t) => one(t),
        Value::Array(ts) => ts
            .iter()
            .filter_map(Value::as_str)
            .map(one)
            .collect::<Vec<_>>()
            .join(" | "),
        _ if s["properties"].is_object() => object(s, depth),
        _ => "unknown".to_owned(),
    }
}

fn args(op: &Op, depth: u8) -> String {
    let mut f: Vec<String> = op
        .params
        .iter()
        .filter(|p| !hidden(&p.schema))
        .map(|p| {
            let opt = if p.required { "" } else { "?" };
            format!("{}{opt}: {}", key(&p.name), ts(&p.schema, depth))
        })
        .collect();
    if let Some(b) = &op.body {
        f.push(format!("body: {}", ts(b, depth)));
    }
    if f.is_empty() {
        String::new()
    } else {
        format!("args: {{ {} }}", f.join("; "))
    }
}

/// `op` as a declaration: a one-line summary, then the call. Under [`MAX_DEF`] bytes where it can
/// be (the nesting is cut until it is).
pub fn render(op: &Op) -> String {
    let summary = op.summary.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    for depth in (1..=5).rev() {
        let ret = op
            .response
            .as_ref()
            .map_or("void".to_owned(), |r| ts(r, depth));
        out = format!(
            "/** {summary} [{}] */\nainkrad.{}.{}({}): {ret}",
            op.risk.as_str(),
            op.group,
            op.id,
            args(op, depth)
        );
        if out.len() <= MAX_DEF {
            break;
        }
    }
    out
}
