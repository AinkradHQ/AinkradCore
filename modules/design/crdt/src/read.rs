//! Reading a yrs document back as the model's types, strictly. Whatever a peer wrote is untrusted: a node must be
//! exactly the shape below, a prop value must be plain JSON (no nested shared type, no sub-document, no buffer), and
//! anything else is an error, never skipped. Every read is bounded by the size of what was stored.
//!
//! The node entry (`nodes[<id>]`, a map):
//!   `type`  string                 a `NodeType`
//!   `order` string                 fractional index; its own register, so a rebalance never touches a move
//!   `move`  {p, c, f}              ONE register for the whole move: parent `p`, Lamport clock `c`, previous parent
//!                                  `f`. One register, so a concurrent move can never win `p` and lose `f`.
//!   `name`  string                 optional
//!   `props` map of JSON values     optional, last writer wins per key
//!   `text`  Y.Text                 optional, text nodes only

use std::collections::HashMap;

use design_model::limits::MAX_NAME_CHARS;
use design_model::{Doc, Meta, Node, NodeType, Token};
use serde_json::{Map, Number as JsonNumber, Value};
use yrs::types::map::MapRef;
use yrs::{Any, GetString, Map as _, Number, Out, ReadTxn};

/// JSON nesting a prop may have (the model's validators are shallower; this stops a deep value being built at all).
const MAX_JSON_DEPTH: usize = 16;
/// The largest integer every JavaScript-compatible peer can hold exactly.
const MAX_SAFE: i64 = (1 << 53) - 1;

pub(crate) type R<T> = Result<T, String>;

fn json(a: &Any, depth: usize) -> R<Value> {
    if depth > MAX_JSON_DEPTH {
        return Err("value nested too deeply".into());
    }
    Ok(match a {
        Any::Null => Value::Null,
        Any::Bool(b) => Value::Bool(*b),
        Any::Number(Number::Int(i)) => Value::Number((*i).into()),
        Any::Number(Number::Float(f)) => {
            Value::Number(JsonNumber::from_f64(*f).ok_or("number is not finite")?)
        }
        Any::String(s) => Value::String(s.to_string()),
        Any::Array(items) => Value::Array(
            items
                .iter()
                .map(|i| json(i, depth + 1))
                .collect::<R<Vec<_>>>()?,
        ),
        Any::Map(m) => Value::Object(
            m.iter()
                .map(|(k, v)| Ok((k.clone(), json(v, depth + 1)?)))
                .collect::<R<Map<_, _>>>()?,
        ),
        Any::Undefined | Any::Buffer(_) => return Err("value is not JSON".into()),
    })
}

fn any(out: Out) -> R<Any> {
    match out {
        Out::Any(a) => Ok(a),
        _ => Err("expected a plain value".into()),
    }
}

fn string(a: Any) -> R<String> {
    match a {
        Any::String(s) => Ok(s.to_string()),
        _ => Err("expected a string".into()),
    }
}

fn opt_string(a: &Any) -> R<Option<String>> {
    match a {
        Any::Null => Ok(None),
        Any::String(s) => Ok(Some(s.to_string())),
        _ => Err("expected a string or null".into()),
    }
}

fn clock(a: &Any) -> R<u64> {
    let n = match a {
        Any::Number(Number::Int(i)) => *i,
        Any::Number(Number::Float(f)) if f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64 => {
            *f as i64
        }
        _ => return Err("clock is not an integer".into()),
    };
    u64::try_from(n)
        .ok()
        .filter(|c| *c <= MAX_SAFE as u64)
        .ok_or_else(|| "clock out of range".into())
}

/// `{p, c, f}`: exactly these keys.
fn read_move(a: &Any) -> R<(Option<String>, u64, Option<String>)> {
    let Any::Map(m) = a else {
        return Err("move is not a map".into());
    };
    if m.len() != 3 {
        return Err("move must be {p, c, f}".into());
    }
    let get = |k: &str| m.get(k).ok_or_else(|| "move must be {p, c, f}".to_string());
    Ok((
        opt_string(get("p")?)?,
        clock(get("c")?)?,
        opt_string(get("f")?)?,
    ))
}

/// One node, or `None` when the id is not in the map.
pub(crate) fn node<T: ReadTxn>(txn: &T, nodes: &MapRef, id: &str) -> R<Option<Node>> {
    let Some(out) = nodes.get(txn, id) else {
        return Ok(None);
    };
    let Out::YMap(m) = out else {
        return Err("node is not a map".into());
    };
    let (mut ty, mut order, mut mv) = (None, None, None);
    let (mut name, mut props, mut text) = (String::new(), Map::new(), None);
    for (k, v) in m.iter(txn) {
        match k {
            "type" => {
                ty = Some(
                    serde_json::from_value::<NodeType>(Value::String(string(any(v)?)?))
                        .map_err(|_| "unknown node type")?,
                )
            }
            "order" => order = Some(string(any(v)?)?),
            "move" => mv = Some(read_move(&any(v)?)?),
            "name" => {
                name = string(any(v)?)?;
                // the model checks the characters; this only keeps a hostile name from being copied around
                if name.len() > MAX_NAME_CHARS * 4 {
                    return Err("name too long".into());
                }
            }
            "props" => {
                let Out::YMap(p) = v else {
                    return Err("props is not a map".into());
                };
                for (pk, pv) in p.iter(txn) {
                    if pk.len() > 64 {
                        return Err("prop key too long".into());
                    }
                    props.insert(pk.to_string(), json(&any(pv)?, 0)?);
                }
            }
            "text" => {
                let Out::YText(t) = v else {
                    return Err("text is not a Y.Text".into());
                };
                text = Some(t.get_string(txn));
            }
            _ => return Err("unknown node field".into()),
        }
    }
    let (Some(ty), Some(order), Some((parent, clock, prev))) = (ty, order, mv) else {
        return Err("node lacks type, order or move".into());
    };
    Ok(Some(Node {
        ty,
        parent,
        order,
        clock,
        prev,
        name,
        props,
        text,
    }))
}

/// `meta`: `system` (string) and `version` (integer), nothing else.
pub(crate) fn meta<T: ReadTxn>(txn: &T, m: &MapRef) -> R<Meta> {
    let mut out = Meta::default();
    for (k, v) in m.iter(txn) {
        match k {
            "system" => out.system = Some(string(any(v)?)?),
            "version" => {
                out.version = u32::try_from(clock(&any(v)?)?).map_err(|_| "version out of range")?
            }
            _ => return Err("unknown meta field".into()),
        }
    }
    Ok(out)
}

/// `tokens`: name -> `{kind, day, night}` as plain JSON; the model's `Token` decides what is acceptable.
pub(crate) fn tokens<T: ReadTxn>(txn: &T, m: &MapRef) -> R<HashMap<String, Token>> {
    let mut out = HashMap::new();
    for (k, v) in m.iter(txn) {
        if k.len() > 64 {
            return Err("token name too long".into());
        }
        let t = serde_json::from_value(json(&any(v)?, 0)?).map_err(|_| "token is malformed")?;
        out.insert(k.to_string(), t);
    }
    Ok(out)
}

pub(crate) fn all<T: ReadTxn>(txn: &T, nodes: &MapRef, meta_m: &MapRef, tok: &MapRef) -> R<Doc> {
    let mut doc = Doc {
        meta: meta(txn, meta_m)?,
        tokens: tokens(txn, tok)?.into_iter().collect(),
        ..Doc::default()
    };
    let ids: Vec<String> = nodes.keys(txn).map(str::to_string).collect();
    for id in ids {
        if let Some(n) = node(txn, nodes, &id)? {
            doc.nodes.insert(id, n);
        }
    }
    Ok(doc)
}
