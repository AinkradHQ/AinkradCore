//! Typed edit ops (T12 shape, used by the inspector and canvas edits through the FFI): a batch is parsed, checked
//! against a model copy of the document with the model's validators, and only then written in one transaction,
//! which is one undo step. A refused batch writes nothing.

use std::collections::BTreeSet;

use design_model::ids::{is_node_id, is_order};
use design_model::limits::MAX_NODES;
use design_model::tree::forest;
use design_model::validate::{self, Cx, name_str, text_str};
use design_model::{Doc, Node, NodeType};
use serde::Deserialize;
use serde_json::{Map as JMap, Value};
use yrs::{Any, In, Map, MapPrelim, Out, Text, TextPrelim, Transact, TransactionMut};

use crate::{Error, LOCAL, Live, json_any};

/// Ops per batch (T12).
pub const MAX_OPS: usize = 200;
pub const MAX_OPS_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    Add {
        id: String,
        #[serde(rename = "type")]
        ty: NodeType,
        parent: Option<String>,
        order: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        props: JMap<String, Value>,
        #[serde(default)]
        text: Option<String>,
    },
    /// `value: null` removes the prop.
    Set {
        id: String,
        key: String,
        value: Value,
    },
    Name {
        id: String,
        name: String,
    },
    Text {
        id: String,
        text: String,
    },
    Move {
        id: String,
        parent: Option<String>,
        order: String,
    },
    /// Removes the node and its whole subtree.
    Delete {
        id: String,
    },
}

/// A JSON array of ops, size- and count-capped.
pub fn parse_ops(json: &[u8]) -> Result<Vec<Op>, Error> {
    if json.len() > MAX_OPS_BYTES {
        return Err(Error::TooLarge);
    }
    let ops: Vec<Op> = serde_json::from_slice(json).map_err(|e| Error::Refused(e.to_string()))?;
    if ops.len() > MAX_OPS {
        return Err(Error::TooLarge);
    }
    Ok(ops)
}

fn refuse(i: usize, msg: impl std::fmt::Display) -> Error {
    Error::Refused(format!("op {i}: {msg}"))
}

fn node<'d>(m: &'d Doc, i: usize, id: &str) -> Result<&'d Node, Error> {
    m.nodes.get(id).ok_or_else(|| refuse(i, "unknown node"))
}

/// Pass 1: apply to the model copy `m`, validating each op against the state the earlier ops left.
fn check(m: &mut Doc, i: usize, op: &Op) -> Result<Planned, Error> {
    Ok(match op {
        Op::Add {
            id,
            ty,
            parent,
            order,
            name,
            props,
            text,
        } => {
            if !is_node_id(id) || m.nodes.contains_key(id) {
                return Err(refuse(i, "bad or existing id"));
            }
            if m.nodes.len() >= MAX_NODES {
                return Err(refuse(i, "too many nodes"));
            }
            match (ty, parent) {
                (NodeType::Page, None) => {}
                (NodeType::Page, Some(_)) | (_, None) => {
                    return Err(refuse(i, "only pages are roots"));
                }
                (_, Some(p)) => {
                    if !node(m, i, p)?.ty.is_container() {
                        return Err(refuse(i, "parent cannot hold children"));
                    }
                }
            }
            if !is_order(order) {
                return Err(refuse(i, "bad order"));
            }
            name_str(name).map_err(|e| refuse(i, e))?;
            match (ty, text) {
                (NodeType::Text, Some(t)) => text_str(t).map_err(|e| refuse(i, e))?,
                (_, Some(_)) => return Err(refuse(i, "text on a non-text node")),
                _ => {}
            }
            if let Some(v) = validate::props(*ty, props, &mut Cx::raw()).first() {
                return Err(refuse(i, format!("{}: {}", v.path, v.msg)));
            }
            let n = Node {
                ty: *ty,
                parent: parent.clone(),
                order: order.clone(),
                clock: m.next_clock(),
                name: name.clone(),
                props: props.clone(),
                text: match ty {
                    NodeType::Text => Some(text.clone().unwrap_or_default()),
                    _ => None,
                },
            };
            m.nodes.insert(id.clone(), n.clone());
            Planned::Add(id.clone(), n)
        }
        Op::Set { id, key, value } => {
            let ty = node(m, i, id)?.ty;
            if !value.is_null() {
                validate::prop(ty, key, value, &mut Cx::raw()).map_err(|e| refuse(i, e))?;
            }
            let props = &mut m
                .nodes
                .get_mut(id)
                .ok_or_else(|| refuse(i, "unknown node"))?
                .props;
            if value.is_null() {
                props.remove(key);
            } else {
                props.insert(key.clone(), value.clone());
            }
            Planned::Set(id.clone(), key.clone(), value.clone())
        }
        Op::Name { id, name } => {
            node(m, i, id)?;
            name_str(name).map_err(|e| refuse(i, e))?;
            Planned::Name(id.clone(), name.clone())
        }
        Op::Text { id, text } => {
            if node(m, i, id)?.ty != NodeType::Text {
                return Err(refuse(i, "not a text node"));
            }
            text_str(text).map_err(|e| refuse(i, e))?;
            Planned::Text(id.clone(), text.clone())
        }
        Op::Move { id, parent, order } => {
            let clock = m.next_clock();
            m.move_node(id, parent.as_deref(), order, clock)
                .map_err(|e| refuse(i, format!("{e:?}")))?;
            Planned::Move(id.clone(), parent.clone(), order.clone(), clock)
        }
        Op::Delete { id } => {
            node(m, i, id)?;
            let kids = forest(m).children;
            let mut gone: BTreeSet<String> = BTreeSet::new();
            let mut stack = vec![id.clone()];
            while let Some(n) = stack.pop() {
                if gone.insert(n.clone()) {
                    stack.extend(kids.get(&n).into_iter().flatten().cloned());
                }
            }
            m.nodes.retain(|k, _| !gone.contains(k));
            Planned::Delete(gone.into_iter().collect())
        }
    })
}

impl Live {
    /// Apply a batch: all ops valid -> one transaction, one undo step; otherwise nothing changes.
    pub fn apply_ops(&mut self, ops: &[Op]) -> Result<(), Error> {
        if ops.len() > MAX_OPS {
            return Err(Error::TooLarge);
        }
        let mut m = self.read();
        let mut plan = Vec::with_capacity(ops.len());
        for (i, op) in ops.iter().enumerate() {
            plan.push(check(&mut m, i, op)?);
        }
        // a commit that trips over a bad pending remote update panics in yrs: reset, do not poison the engine
        self.recover(|l| {
            let mut txn = l.doc().transact_mut_with(LOCAL);
            for p in &plan {
                write(&l.nodes, &mut txn, p);
            }
            drop(txn);
            l.undo.reset();
            Ok(())
        })
    }
}

/// What pass 2 writes for one op, decided in pass 1.
enum Planned {
    Add(String, Node),
    Set(String, String, Value),
    Name(String, String),
    Text(String, String),
    Move(String, Option<String>, String, u64),
    Delete(Vec<String>),
}

fn node_map(nodes: &yrs::MapRef, txn: &TransactionMut, id: &str) -> Option<yrs::MapRef> {
    match nodes.get(txn, id) {
        Some(Out::YMap(m)) => Some(m),
        _ => None,
    }
}

fn parent_any(p: Option<&str>) -> Any {
    p.map_or(Any::Null, Any::from)
}

fn write(nodes: &yrs::MapRef, txn: &mut TransactionMut, p: &Planned) {
    match p {
        Planned::Add(id, n) => {
            let props: MapPrelim = n
                .props
                .iter()
                .map(|(k, v)| (k.as_str(), In::Any(json_any(v))))
                .collect();
            let mut fields: Vec<(&str, In)> = vec![
                (
                    "type",
                    In::Any(json_any(&serde_json::to_value(n.ty).unwrap_or(Value::Null))),
                ),
                ("parent", In::Any(parent_any(n.parent.as_deref()))),
                ("order", In::Any(Any::from(n.order.as_str()))),
                ("clock", In::Any(Any::from(n.clock as f64))),
                ("name", In::Any(Any::from(n.name.as_str()))),
                ("props", In::Map(props)),
            ];
            if let Some(t) = &n.text {
                fields.push(("text", TextPrelim::new(t.as_str()).into()));
            }
            nodes.insert(txn, id.as_str(), fields.into_iter().collect::<MapPrelim>());
        }
        Planned::Set(id, k, v) => {
            let Some(m) = node_map(nodes, txn, id) else {
                return;
            };
            let props = match m.get(txn, "props") {
                Some(Out::YMap(p)) => p,
                _ => m.insert(txn, "props", MapPrelim::default()),
            };
            if v.is_null() {
                props.remove(txn, k);
            } else {
                props.insert(txn, k.as_str(), json_any(v));
            }
        }
        Planned::Name(id, n) => {
            if let Some(m) = node_map(nodes, txn, id) {
                m.insert(txn, "name", n.as_str());
            }
        }
        Planned::Text(id, t) => {
            let Some(m) = node_map(nodes, txn, id) else {
                return;
            };
            match m.get(txn, "text") {
                Some(Out::YText(x)) => {
                    let len = x.len(txn);
                    x.remove_range(txn, 0, len);
                    x.insert(txn, 0, t);
                }
                _ => {
                    m.insert(txn, "text", TextPrelim::new(t.as_str()));
                }
            }
        }
        Planned::Move(id, parent, order, clock) => {
            if let Some(m) = node_map(nodes, txn, id) {
                m.insert(txn, "parent", parent_any(parent.as_deref()));
                m.insert(txn, "order", order.as_str());
                m.insert(txn, "clock", *clock as f64);
            }
        }
        Planned::Delete(ids) => {
            for id in ids {
                nodes.remove(txn, id);
            }
        }
    }
}
