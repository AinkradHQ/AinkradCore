//! Layers and token queries and select-by-id (V2-07), for the App's layers panel and token pickers. Safe code only:
//! the ABI wrappers (and every pointer check) are in `ffi.rs`.

use design_model::ids::{is_node_id, is_token_name};
use design_model::{NodeType, validate};
use serde::Serialize;
use serde_json::Value;

use crate::codes::*;
use crate::host::Host;

impl Host {
    /// `[{id, type, parent, order, name, hidden, locked, rotation}]` for every node (parent = effective parent after cycle cuts).
    /// Ids that are not valid node ids are left out.
    pub fn tree_json(&mut self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Row<'a> {
            id: &'a str,
            #[serde(rename = "type")]
            ty: &'a NodeType,
            parent: Option<&'a String>,
            order: &'a str,
            name: &'a str,
            hidden: bool,
            locked: bool,
            rotation: f64,
        }
        self.model();
        let (Some(m), Some(t)) = (&self.model, &self.tree) else {
            return b"[]".to_vec();
        };
        let all: Vec<Row> = m
            .nodes
            .iter()
            .filter(|(id, _)| is_node_id(id))
            .map(|(id, n)| Row {
                id,
                ty: &n.ty,
                parent: t.parent.get(id),
                order: &n.order,
                name: &n.name,
                hidden: n.props.get("visible").and_then(Value::as_bool) == Some(false),
                locked: n.props.get("locked").and_then(Value::as_bool) == Some(true),
                rotation: n
                    .props
                    .get("rotation")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
            })
            .collect();
        serde_json::to_vec(&all).unwrap_or_else(|_| b"[]".to_vec())
    }

    /// `[{name, kind}]` of the design system's tokens; a token that would not resolve is left out.
    pub fn tokens_json(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Row<'a> {
            name: &'a str,
            kind: &'a design_model::TokenKind,
        }
        let sys = self.system.read();
        let all: Vec<Row> = sys
            .tokens
            .iter()
            .filter(|(n, t)| is_token_name(n) && validate::token(t).is_ok())
            .map(|(name, t)| Row {
                name,
                kind: &t.kind,
            })
            .collect();
        serde_json::to_vec(&all).unwrap_or_else(|_| b"[]".to_vec())
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
        // validate before any side effect: a refused call changes nothing
        self.refresh();
        let m = self.model();
        if !ids.iter().all(|i| m.nodes.contains_key(i)) {
            return Err(DE_ERR_INVALID);
        }
        self.text_end()?;
        self.cancel();
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
