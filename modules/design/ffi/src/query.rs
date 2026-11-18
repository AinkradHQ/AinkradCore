//! Layers and token queries and select-by-id (V2-07), for the App's layers panel and token pickers. Safe code only:
//! the ABI wrappers (and every pointer check) are in `ffi.rs`.

use serde_json::{Value, json};

use crate::codes::*;
use crate::host::Host;

impl Host {
    /// `[{id, type, parent, order, name, hidden}]` for every node (parent = effective parent after cycle cuts).
    pub fn tree_json(&mut self) -> Vec<u8> {
        self.model();
        let (Some(m), Some(t)) = (&self.model, &self.tree) else {
            return b"[]".to_vec();
        };
        let all: Vec<Value> = m
            .nodes
            .iter()
            .map(|(id, n)| {
                let hidden = n.props.get("visible").and_then(Value::as_bool) == Some(false);
                json!({"id": id, "type": n.ty, "parent": t.parent.get(id), "order": n.order,
                       "name": n.name, "hidden": hidden})
            })
            .collect();
        Value::Array(all).to_string().into_bytes()
    }

    /// `[{name, kind}]` of the design system's tokens.
    pub fn tokens_json(&self) -> Vec<u8> {
        let sys = self.system.read();
        let all: Vec<Value> = sys
            .tokens
            .iter()
            .map(|(name, t)| json!({"name": name, "kind": t.kind}))
            .collect();
        Value::Array(all).to_string().into_bytes()
    }

    /// Replace the selection with the ids in `json` (a JSON array of strings); all or nothing.
    pub fn select(&mut self, json: &[u8]) -> Result<(), i32> {
        let ids: Vec<String> = serde_json::from_slice(json).map_err(|_| DE_ERR_INVALID)?;
        if ids.len() > DE_MAX_SELECT_IDS {
            return Err(DE_ERR_TOO_LARGE);
        }
        if ids.iter().any(|i| i.len() > DE_MAX_ID_BYTES) {
            return Err(DE_ERR_TOO_LARGE);
        }
        self.text_end()?;
        self.cancel();
        self.refresh();
        let m = self.model();
        if !ids.iter().all(|i| m.nodes.contains_key(i)) {
            return Err(DE_ERR_INVALID);
        }
        let mut sel: Vec<String> = Vec::with_capacity(ids.len());
        for i in ids {
            if !sel.contains(&i) {
                sel.push(i);
            }
        }
        self.selection = sel;
        self.hover = None;
        self.refresh();
        Ok(())
    }
}
