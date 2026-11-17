//! The live design document (V2-02, T1, T3): one `yrs::Doc` in the T1 layout,
//!
//! ```text
//! nodes:  Map<id, Map{type, parent, order, clock, name, props: Map, text?: Text}>
//! meta:   Map{system, version}
//! tokens: Map<name, {kind, day, night}>          (system docs only)
//! ```
//!
//! read out as a `design_model::Doc`, edited only through typed [`Op`]s that the model's validators check first
//! (all-or-nothing, one transaction, one undo step), with sync bytes in/out (yrs update v1) and presence (yrs
//! awareness). Everything read from the CRDT is treated as hostile: a node with a missing or malformed field is
//! skipped, prop JSON is depth-capped, and the model's resolver bounds the rest.
//!
//! Trust note: yrs decodes, encodes, converts and drops nested values recursively, so nesting is where a hostile
//! update could exhaust the stack (an abort, not a panic). Two guards: every `Any` in a remote update is decoded
//! through `decode` (depth-capped at `MAX_JSON_DEPTH`, no collection longer than the bytes), and a node whose props
//! hold a nested yrs map, array or text (no op writes one) is never read. A panic inside yrs while applying resets the
//! replica (`Error::Reset`) instead of aborting. The Core (V1-03) reuses `apply_remote` and gets the same guards; it
//! must still trial-apply an update before it stores or relays it.

use std::sync::{Arc, Mutex};

use design_model::limits::{MAX_DOC_BYTES, MAX_NODES, MAX_TOKENS};
use design_model::{Doc, Meta, Node, NodeType, Token};
use serde_json::{Map as JMap, Number, Value};
use yrs::undo::{Options as UndoOptions, UndoManager};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Any, Doc as YDoc, GetString, Map, MapRef, Origin, Out, ReadTxn, StateVector, Transact};

mod decode;
mod ops;
mod presence;

pub use ops::{MAX_OPS, MAX_OPS_BYTES, Op, parse_ops};
pub use presence::{ClockFn, MAX_PEERS, MAX_PRESENCE_BYTES, PEER_TTL_MS, Presence};

/// A remote update or a full state: the document cap plus framing room.
pub const MAX_UPDATE_BYTES: usize = MAX_DOC_BYTES + (1 << 20);
/// Prop JSON nesting read out of the CRDT (the validators accept far less).
pub const MAX_JSON_DEPTH: usize = 32;

const LOCAL: &str = "local";
const REMOTE: &str = "remote";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    /// Bytes that do not decode, or yrs refused them.
    Malformed(String),
    /// An op the validators refused; nothing was written.
    Refused(String),
    /// Applying a remote update failed inside yrs; the replica was replaced by an empty one. Resync from the Core
    /// (send the state vector, apply the full diff).
    Reset,
}

pub struct Live {
    presence: Presence,
    nodes: MapRef,
    meta: MapRef,
    tokens: MapRef,
    undo: UndoManager<()>,
    outbox: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Default for Live {
    fn default() -> Self {
        Self::new()
    }
}

impl Live {
    pub fn new() -> Live {
        Live::with_clock(std::sync::Arc::new(presence::system_clock))
    }

    /// `clock` = milliseconds for presence expiry (tests pass a fake one).
    pub fn with_clock(clock: presence::ClockFn) -> Live {
        let doc = YDoc::new();
        let nodes = doc.get_or_insert_map("nodes");
        let meta = doc.get_or_insert_map("meta");
        let tokens = doc.get_or_insert_map("tokens");
        let outbox: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let ob = outbox.clone();
        let remote = Origin::from(REMOTE);
        // Everything this replica did (edits, undo, redo) goes out; what came in does not echo back.
        doc.observe_update_v1("outbox", move |txn, e| {
            if txn.origin() != Some(&remote)
                && let Ok(mut o) = ob.lock()
            {
                o.push(e.update.clone());
            }
        })
        .expect("a fresh doc has no transaction open");
        let mut undo = UndoManager::with_options(UndoOptions::default());
        undo.expand_scope(&doc, &nodes);
        undo.expand_scope(&doc, &meta);
        undo.include_origin(Origin::from(LOCAL));
        Live {
            presence: Presence::new(doc, clock),
            nodes,
            meta,
            tokens,
            undo,
            outbox,
        }
    }

    fn doc(&self) -> &YDoc {
        self.presence.doc()
    }

    /// A remote update (v1) from the Core relay. Not undoable here, never echoed to the outbox.
    pub fn apply_remote(&mut self, update: &[u8]) -> Result<(), Error> {
        if update.len() > MAX_UPDATE_BYTES {
            return Err(Error::TooLarge);
        }
        let u = decode::update(update)?;
        // A panic inside yrs while integrating must not unwind through the open transaction: its drop commits, and a
        // second panic there would abort. The inner catch ends the first panic before the transaction drops; the
        // outer one catches a panic in that commit. Either way the replica may be half-applied, so it is replaced by
        // an empty one and the host resyncs from the Core (local edits not yet sent are lost; the Core has the rest).
        let mut panicked = false;
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut txn = self.doc().transact_mut_with(REMOTE);
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| txn.apply_update(u))) {
                Ok(r) => r.map_err(|e| Error::Malformed(e.to_string())),
                Err(_) => {
                    panicked = true;
                    Err(Error::Reset)
                }
            }
        }));
        match r {
            Ok(r) if !panicked => r,
            _ => {
                self.reset();
                Err(Error::Reset)
            }
        }
    }

    pub fn state_vector(&self) -> Vec<u8> {
        self.doc().transact().state_vector().encode_v1()
    }

    /// Everything this replica has that a peer at state vector `sv` lacks (empty `sv` = the full state).
    pub fn diff(&mut self, sv: &[u8]) -> Result<Vec<u8>, Error> {
        let sv = if sv.is_empty() {
            StateVector::default()
        } else {
            decode::caught(|| StateVector::decode_v1(sv))?
        };
        // yrs re-decodes pending (not yet integrable) remote updates here and panics on some it accepted earlier
        self.recover(|l| Ok(l.doc().transact().encode_state_as_update_v1(&sv)))
    }

    /// Replace a replica yrs left inconsistent by an empty one; the host resyncs from the Core.
    fn reset(&mut self) {
        *self = Live::with_clock(self.presence.clock());
    }

    /// Run `f`; a panic inside yrs resets the replica (`Error::Reset`) instead of reaching the caller.
    pub(crate) fn recover<T>(
        &mut self,
        f: impl FnOnce(&mut Live) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self))) {
            Ok(r) => r,
            Err(_) => {
                self.reset();
                Err(Error::Reset)
            }
        }
    }

    /// Local updates not yet sent, merged into one (empty when there are none). `take` = drain them.
    pub fn outbox(&self, take: bool) -> Vec<u8> {
        let mut o = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
        if o.is_empty() {
            return vec![];
        }
        match yrs::merge_updates_v1(o.iter().map(Vec::as_slice)) {
            Ok(merged) => {
                if take {
                    o.clear();
                }
                merged
            }
            // never send bytes that are not one update: fall back to the oldest one, the rest stay queued
            Err(_) if take => o.remove(0),
            Err(_) => o[0].clone(),
        }
    }

    /// `false` also when yrs failed and the replica was reset (the next sync call reports it).
    pub fn undo(&mut self) -> bool {
        self.recover(|l| Ok(l.undo.undo_blocking()))
            .unwrap_or(false)
    }

    pub fn redo(&mut self) -> bool {
        self.recover(|l| Ok(l.undo.redo_blocking()))
            .unwrap_or(false)
    }

    pub fn presence(&mut self) -> &mut Presence {
        &mut self.presence
    }

    /// The document as the model reads it. Malformed nodes and tokens are left out.
    pub fn read(&self) -> Doc {
        let txn = self.doc().transact();
        let mut doc = Doc::default();
        for (id, v) in self.nodes.iter(&txn).take(MAX_NODES) {
            if let Some(n) = read_node(&txn, v) {
                doc.nodes.insert(id.to_string(), n);
            }
        }
        doc.meta = Meta {
            system: match self.meta.get(&txn, "system") {
                Some(Out::Any(Any::String(s))) => Some(s.to_string()),
                _ => None,
            },
            version: match self.meta.get(&txn, "version") {
                Some(Out::Any(a)) => int(&a).and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
                _ => 0,
            },
        };
        for (name, v) in self.tokens.iter(&txn).take(MAX_TOKENS) {
            let Out::Any(a) = v else { continue };
            if let Some(t) = any_json(&a, 0).and_then(|j| serde_json::from_value::<Token>(j).ok()) {
                doc.tokens.insert(name.to_string(), t);
            }
        }
        doc
    }
}

fn read_node<T: ReadTxn>(txn: &T, v: Out) -> Option<Node> {
    let Out::YMap(m) = v else { return None };
    let s = |k: &str| match m.get(txn, k) {
        Some(Out::Any(Any::String(s))) => Some(s.to_string()),
        _ => None,
    };
    let ty: NodeType = serde_json::from_value(Value::String(s("type")?)).ok()?;
    let parent = match m.get(txn, "parent") {
        Some(Out::Any(Any::String(p))) => Some(p.to_string()),
        Some(Out::Any(Any::Null)) | None => None,
        _ => return None,
    };
    let clock = match m.get(txn, "clock") {
        Some(Out::Any(a)) => u64::try_from(int(&a)?).ok()?,
        _ => 0,
    };
    // Props hold plain values only. A nested yrs map, array or text here (which no op writes) would be read by yrs's
    // recursive `to_json`, and a chain of them, built one small update per level, would exhaust the stack: refuse it.
    let props = match m.get(txn, "props") {
        Some(Out::YMap(p)) => {
            let mut o = JMap::new();
            for (k, v) in p.iter(txn) {
                let Out::Any(a) = v else { return None };
                o.insert(k.to_string(), any_json(&a, 0)?);
            }
            o
        }
        None => JMap::new(),
        _ => return None,
    };
    let text = match m.get(txn, "text") {
        Some(Out::YText(t)) => Some(t.get_string(txn)),
        _ => None,
    };
    Some(Node {
        ty,
        parent,
        order: s("order")?,
        clock,
        name: s("name").unwrap_or_default(),
        props,
        text,
    })
}

/// An integral number (yrs keeps JSON integers that went through a float as floats).
fn int(a: &Any) -> Option<i64> {
    match a {
        Any::Number(yrs::Number::Int(i)) => Some(*i),
        Any::Number(yrs::Number::Float(f)) if f.fract() == 0.0 && f.abs() < 9.0e15 => {
            Some(*f as i64)
        }
        _ => None,
    }
}

/// `Any` -> JSON, refusing nesting deeper than `MAX_JSON_DEPTH` and non-finite numbers.
fn any_json(a: &Any, depth: usize) -> Option<Value> {
    if depth > MAX_JSON_DEPTH {
        return None;
    }
    Some(match a {
        Any::Null | Any::Undefined => Value::Null,
        Any::Bool(b) => Value::Bool(*b),
        Any::Number(yrs::Number::Int(i)) => Value::Number((*i).into()),
        Any::Number(yrs::Number::Float(f)) => Value::Number(Number::from_f64(*f)?),
        Any::String(s) => Value::String(s.to_string()),
        Any::Buffer(_) => return None,
        Any::Array(xs) => Value::Array(
            xs.iter()
                .map(|x| any_json(x, depth + 1))
                .collect::<Option<_>>()?,
        ),
        Any::Map(m) => Value::Object(
            m.iter()
                .map(|(k, v)| Some((k.clone(), any_json(v, depth + 1)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

/// JSON -> `Any` (the value already passed the validators, so its depth is small).
fn json_any(v: &Value) -> Any {
    serde_json::from_value(v.clone()).unwrap_or(Any::Null)
}
