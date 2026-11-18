//! Local edits on a `Replica` in the registers `read` expects (from `design-crdt`). Used by the Core's typed ops
//! (V1-04) and the tests; the App engine writes the same registers through `ops`.
//! A move goes through the model's own `Doc::move_node` (leaf parent, cycle, order and clock checks), so the rules
//! live in one place; the result is then written as the `move` and `order` registers.

use design_model::ids::is_order;
use design_model::tree::MoveError;
use design_model::{Doc as Model, NodeType};
use serde_json::Value;
use yrs::types::map::MapRef;
use yrs::types::text::TextPrelim;
use yrs::{Any, Map as _, MapPrelim, Number, Out, Text as _, TransactionMut};

use crate::read;

pub struct Editor<'a, 'd> {
    txn: &'a mut TransactionMut<'d>,
    nodes: &'a MapRef,
    meta: &'a MapRef,
    tokens: &'a MapRef,
    top: &'a mut u64,
}

fn any(v: &Value) -> Any {
    match v {
        Value::Null => Any::Null,
        Value::Bool(b) => Any::Bool(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Any::Number(Number::Int(i)),
            None => Any::Number(Number::Float(n.as_f64().unwrap_or(0.0))),
        },
        Value::String(s) => Any::String(s.as_str().into()),
        Value::Array(a) => Any::Array(a.iter().map(any).collect::<Vec<_>>().into()),
        Value::Object(m) => Any::Map(
            m.iter()
                .map(|(k, v)| (k.clone(), any(v)))
                .collect::<std::collections::HashMap<_, _>>()
                .into(),
        ),
    }
}

impl<'a, 'd> Editor<'a, 'd> {
    pub(crate) fn new(
        txn: &'a mut TransactionMut<'d>,
        nodes: &'a MapRef,
        meta: &'a MapRef,
        tokens: &'a MapRef,
        top: &'a mut u64,
    ) -> Self {
        Self {
            txn,
            nodes,
            meta,
            tokens,
            top,
        }
    }

    fn model(&self) -> Model {
        read::all(&*self.txn, self.nodes, self.meta, self.tokens).unwrap_or_default()
    }

    fn node_map(&self, id: &str) -> Option<MapRef> {
        match self.nodes.get(&*self.txn, id) {
            Some(Out::YMap(m)) => Some(m),
            _ => None,
        }
    }

    /// A new node under `parent` (a page has none). `props` is a JSON object, `text` for text nodes.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_node(
        &mut self,
        id: &str,
        ty: NodeType,
        parent: Option<&str>,
        order: &str,
        name: &str,
        props: &Value,
        text: Option<&str>,
    ) {
        *self.top += 1;
        let ty = serde_json::to_value(ty).unwrap_or_default();
        let m = self.nodes.insert(self.txn, id, MapPrelim::default());
        m.insert(self.txn, "type", any(&ty));
        m.insert(self.txn, "order", order);
        m.insert(self.txn, "name", name);
        m.insert(self.txn, "move", read::move_any(parent, *self.top, None));
        let p = m.insert(self.txn, "props", MapPrelim::default());
        for (k, v) in props.as_object().into_iter().flatten() {
            p.insert(self.txn, k.as_str(), any(v));
        }
        if let Some(t) = text {
            m.insert(self.txn, "text", TextPrelim::new(t));
        }
    }

    /// Move a node (and its order). Refused as the model refuses a local move.
    pub fn move_node(
        &mut self,
        id: &str,
        parent: Option<&str>,
        order: &str,
    ) -> Result<(), MoveError> {
        let mut m = self.model();
        let clock = m.next_clock();
        m.move_node(id, parent, order, clock)?;
        let n = &m.nodes[id];
        *self.top = (*self.top).max(clock);
        let nm = self.node_map(id).ok_or(MoveError::UnknownNode)?;
        nm.insert(
            self.txn,
            "move",
            read::move_any(n.parent.as_deref(), n.clock, n.prev.as_deref()),
        );
        nm.insert(self.txn, "order", order);
        Ok(())
    }

    /// Only the order register: reordering among siblings.
    pub fn set_order(&mut self, id: &str, order: &str) -> bool {
        match (is_order(order), self.node_map(id)) {
            (true, Some(nm)) => {
                nm.insert(self.txn, "order", order);
                true
            }
            _ => false,
        }
    }

    /// Renumber `parent`'s children; writes only their order registers.
    pub fn rebalance(&mut self, parent: &str) -> Result<usize, MoveError> {
        let before = self.model();
        let mut after = before.clone();
        let n = after.rebalance_children(parent)?;
        for (id, node) in &after.nodes {
            if before.nodes[id].order != node.order
                && let Some(nm) = self.node_map(id)
            {
                nm.insert(self.txn, "order", node.order.as_str());
            }
        }
        Ok(n)
    }

    /// Set a prop (`None` removes it).
    pub fn set_prop(&mut self, id: &str, key: &str, value: Option<&Value>) -> bool {
        let Some(nm) = self.node_map(id) else {
            return false;
        };
        let Some(Out::YMap(p)) = nm.get(&*self.txn, "props") else {
            return false;
        };
        match value {
            Some(v) => {
                p.insert(self.txn, key, any(v));
            }
            None => {
                p.remove(self.txn, key);
            }
        }
        true
    }

    pub fn insert_text(&mut self, id: &str, at: u32, chunk: &str) -> bool {
        let Some(nm) = self.node_map(id) else {
            return false;
        };
        let Some(Out::YText(t)) = nm.get(&*self.txn, "text") else {
            return false;
        };
        t.insert(self.txn, at, chunk);
        true
    }

    /// Write a move clock the document would never produce, to forge a hostile update in tests.
    #[doc(hidden)]
    pub fn set_clock_unchecked(&mut self, id: &str, clock: u64) {
        if let Some(nm) = self.node_map(id) {
            nm.insert(
                self.txn,
                "move",
                read::move_any(Some("n_pageaaaaaaaa"), clock, None),
            );
        }
    }

    pub fn remove_node(&mut self, id: &str) {
        self.nodes.remove(self.txn, id);
    }

    pub fn set_token(&mut self, name: &str, token: &Value) {
        self.tokens.insert(self.txn, name, any(token));
    }
}
