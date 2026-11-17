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

use crate::{Error, LOCAL, Live, MAX_UPDATE_BYTES, json_any};
use yrs::ReadTxn;
use yrs::updates::decoder::Decode;

/// Ops per parsed batch (T12: what an AI or the inspector sends).
pub const MAX_OPS: usize = 200;
/// Ops per engine-made batch (V2-03): a canvas gesture on a large selection is still one batch, one undo step.
pub const MAX_GESTURE_OPS: usize = 4 * MAX_NODES;
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
    /// Apply a parsed batch (at most `MAX_OPS`, T12): all ops valid -> one transaction, one undo step; otherwise
    /// nothing changes.
    pub fn apply_ops(&mut self, ops: &[Op]) -> Result<(), Error> {
        if ops.len() > MAX_OPS {
            return Err(Error::TooLarge);
        }
        let mut m = self.read();
        self.commit(&mut m, ops, MAX_UPDATE_BYTES)
    }

    /// The engine's own canvas gesture (V2-03): up to `MAX_GESTURE_OPS`, so a drag of a large selection is still one
    /// undo step. Validated against `m`, the caller's copy of `read()` (its cached model), which is brought up to date
    /// instead of reading the whole document again. On an error nothing is written and `m` is partly changed: drop
    /// it. Only for batches the engine made itself: anything parsed goes through `apply_ops`.
    pub fn apply_gesture_ops(&mut self, m: &mut Doc, ops: &[Op]) -> Result<(), Error> {
        if ops.len() > MAX_GESTURE_OPS {
            return Err(Error::TooLarge);
        }
        self.commit(m, ops, MAX_UPDATE_BYTES)
    }

    /// Validate, size-check and write one batch. A batch whose update would exceed `budget` is refused
    /// (`TooLarge`): the relay refuses such an update, so it would never sync. A panic inside yrs resets the replica.
    pub(crate) fn commit(&mut self, m: &mut Doc, ops: &[Op], budget: usize) -> Result<(), Error> {
        self.recover(|l| {
            let plan = ops
                .iter()
                .enumerate()
                .map(|(i, op)| check(m, i, op))
                .collect::<Result<Vec<_>, _>>()?;
            if l.update_size(&plan, budget) > budget {
                return Err(Error::TooLarge);
            }
            // a commit that trips over a bad pending remote update panics in yrs: reset, do not poison the engine
            let mut txn = l.doc().transact_mut_with(LOCAL);
            for p in &plan {
                write(&l.nodes, &mut txn, p);
            }
            drop(txn);
            l.undo.reset();
            Ok(())
        })
    }

    /// The bytes `plan`'s update will take, at least as far as `budget` needs: a cheap estimate with a wide margin
    /// (4x the JSON size plus 256 bytes per op) when that is under `budget`, else the exact size from a dry run on a
    /// copy of the document.
    fn update_size(&self, plan: &[Planned], budget: usize) -> usize {
        let est: usize = plan.iter().map(|p| 4 * planned_bytes(p) + 256).sum();
        if est <= budget {
            return est;
        }
        let copy = yrs::Doc::new();
        let nodes = copy.get_or_insert_map("nodes");
        let state = self
            .doc()
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());
        let mut txn = copy.transact_mut();
        let Ok(u) = yrs::Update::decode_v1(&state) else {
            return usize::MAX;
        };
        if txn.apply_update(u).is_err() {
            return usize::MAX;
        }
        drop(txn);
        let mut txn = copy.transact_mut();
        for p in plan {
            write(&nodes, &mut txn, p);
        }
        // a different client id than this replica's: allow for its varint
        txn.encode_update_v1().len() + 64
    }

    /// Write a whole model document (nodes, meta, tokens) as it is, in one transaction outside the undo history:
    /// seeding tests and benches with a generated scene and its design system. Not validated.
    pub fn import(&mut self, d: &Doc) {
        let mut txn = self.doc().transact_mut_with(IMPORT);
        for (id, n) in &d.nodes {
            write(&self.nodes, &mut txn, &Planned::Add(id.clone(), n.clone()));
        }
        if let Some(s) = &d.meta.system {
            self.meta.insert(&mut txn, "system", s.as_str());
        }
        self.meta.insert(&mut txn, "version", d.meta.version as f64);
        for (name, t) in &d.tokens {
            let v = serde_json::to_value(t).unwrap_or(Value::Null);
            self.tokens.insert(&mut txn, name.as_str(), json_any(&v));
        }
    }
}

const IMPORT: &str = "import";

/// JSON-ish size of what one planned op writes.
fn planned_bytes(p: &Planned) -> usize {
    let v = |v: &Value| serde_json::to_vec(v).map_or(0, |b| b.len());
    match p {
        Planned::Add(id, n) => id.len() + serde_json::to_vec(n).map_or(0, |b| b.len()),
        Planned::Set(id, k, x) => id.len() + k.len() + v(x),
        Planned::Name(id, t) | Planned::Text(id, t) => id.len() + t.len(),
        Planned::Move(id, p, o, _) => id.len() + p.as_ref().map_or(0, String::len) + o.len(),
        Planned::Delete(ids) => ids.iter().map(String::len).sum(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "n_aaaaaaaaaaaa";

    fn id(mut i: usize) -> String {
        const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut s = vec![b'b'; 12];
        for c in s.iter_mut().rev() {
            *c = A[i % 32];
            i /= 32;
        }
        format!("n_{}", String::from_utf8(s).unwrap_or_default())
    }

    fn adds(n: usize, text: usize) -> Vec<Op> {
        let mut v = vec![Op::Add {
            id: PAGE.into(),
            ty: NodeType::Page,
            parent: None,
            order: "a".into(),
            name: String::new(),
            props: JMap::new(),
            text: None,
        }];
        for i in 0..n {
            v.push(Op::Add {
                id: id(i + 1),
                ty: NodeType::Text,
                parent: Some(PAGE.into()),
                order: "a".into(),
                name: String::new(),
                props: JMap::new(),
                text: Some("x".repeat(text)),
            });
        }
        v
    }

    #[test]
    fn a_batch_over_the_update_budget_is_refused_and_writes_nothing() {
        let mut l = Live::new();
        let ops = adds(20, 1000);
        // the real update is ~20 KB; the estimate is 4x the JSON: a 40 KB budget needs the exact dry run and passes
        let mut m = l.read();
        assert_eq!(l.commit(&mut m, &ops, 40_000), Ok(()));
        let real = l.outbox(true).len();
        assert!(real > 20_000 && real < 40_000, "{real}");
        // the same batch elsewhere with a 10 KB budget: refused, nothing written, nothing to send
        let mut l = Live::new();
        let mut m = l.read();
        assert_eq!(l.commit(&mut m, &ops, 10_000), Err(Error::TooLarge));
        assert!(l.read().nodes.is_empty());
        assert!(l.outbox(false).is_empty());
        assert!(!l.undo());
    }

    #[test]
    fn gesture_batches_take_more_ops_than_parsed_ones() {
        let mut l = Live::new();
        let ops = adds(MAX_OPS, 1);
        assert_eq!(l.apply_ops(&ops), Err(Error::TooLarge), "201 ops");
        let mut m = l.read();
        assert_eq!(l.apply_gesture_ops(&mut m, &ops), Ok(()));
        assert_eq!(m, l.read(), "the caller's model is brought up to date");
    }

    #[test]
    fn the_outbox_goes_out_in_chunks_under_the_cap_and_rebuilds_the_doc() {
        let mut l = Live::new();
        l.apply_ops(&adds(0, 0)).unwrap();
        for i in 0..6 {
            let op = Op::Add {
                id: id(i + 1),
                ty: NodeType::Text,
                parent: Some(PAGE.into()),
                order: "a".into(),
                name: String::new(),
                props: JMap::new(),
                text: Some("y".repeat(3000)),
            };
            l.apply_ops(&[op]).unwrap();
        }
        let mut peer = Live::new();
        let mut chunks = 0;
        loop {
            let c = l.outbox_under(true, 7_000);
            if c.is_empty() {
                break;
            }
            assert!(c.len() <= 7_000, "{}", c.len());
            // integrated directly: this checks the chunks, not the relay's ordering guard (`apply_remote`)
            let (u, _) = crate::decode::update(&c).unwrap();
            peer.integrate(u).unwrap();
            chunks += 1;
        }
        assert!(chunks >= 3, "{chunks}");
        assert_eq!(peer.read(), l.read());
    }
}
