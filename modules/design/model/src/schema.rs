//! The stored shape (T1). `Doc` is what a CRDT document reads out as; props stay an open JSON map because the CRDT
//! merges them per key, and `validate` decides which keys and values are in the schema.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::limits::MAX_DOC_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    Page,
    Frame,
    Text,
    Rect,
    Ellipse,
    Image,
    Vector,
    Component,
    Instance,
}

impl NodeType {
    /// Leaf types cannot hold children (an instance's children come from its component).
    pub fn is_container(self) -> bool {
        matches!(self, Self::Page | Self::Frame | Self::Component)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Color,
    Space,
    Radius,
    Size,
    Type,
    Shadow,
    Material,
}

/// A token: one literal per theme. Values never contain token refs, so token resolution cannot cycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub kind: TokenKind,
    pub day: Value,
    pub night: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// The one design system (`dd_...`) this design names (T11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default)]
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    #[serde(rename = "type")]
    pub ty: NodeType,
    /// `None` only for pages; anything else without a live parent is "detached" (see `tree`).
    pub parent: Option<String>,
    /// Fractional index among siblings (`ids::is_order`).
    pub order: String,
    /// Lamport clock of the last move of this node (parent + order); breaks move cycles (`tree`).
    #[serde(default)]
    pub clock: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub props: Map<String, Value>,
    /// Text nodes only (a `Y.Text` in the CRDT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Doc {
    #[serde(default)]
    pub meta: Meta,
    #[serde(default)]
    pub nodes: BTreeMap<String, Node>,
    /// System docs only (a design's own tokens are ignored, T11).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tokens: BTreeMap<String, Token>,
}

impl Doc {
    /// Parse untrusted JSON: size-capped, unknown fields refused. Does not validate values (`validate::doc`).
    pub fn from_json(bytes: &[u8]) -> Result<Doc, String> {
        if bytes.len() > MAX_DOC_BYTES {
            return Err("document too large".into());
        }
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }
}
