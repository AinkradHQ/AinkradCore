//! The Design document model (T1, T11). Pure Rust: no I/O, no Skia, no CRDT engine.
//!
//! A document is a flat node map; every node holds `parent` + a fractional-index `order` + the Lamport `clock` of its
//! last move, and its props are an open JSON map (last-writer-wins per prop in the CRDT). Everything that reads a
//! document treats it as hostile: validators refuse out-of-schema values, the forest builder breaks parent cycles
//! deterministically, and the resolver is bounded in depth and size.

pub mod ids;
pub mod lint;
pub mod resolve;
pub mod schema;
pub mod svgpath;
pub mod tree;
pub mod validate;

pub use lint::{Finding, Severity, lint};
pub use resolve::{Diagnostic, Resolved, ResolvedNode, Theme, resolve};
pub use schema::{Doc, Meta, Node, NodeType, Token, TokenKind};
pub use tree::{Forest, MoveError, MoveRecord};
pub use validate::Violation;

/// Hard limits (T14 for the doc, the rest are this crate's). Every loop and recursion is bounded by one of them.
pub mod limits {
    /// A whole document, as JSON text.
    pub const MAX_DOC_BYTES: usize = 32 * 1024 * 1024;
    pub const MAX_NODES: usize = 20_000;
    pub const MAX_TOKENS: usize = 5_000;
    /// Tree depth (page = 0) the resolver descends; deeper nodes are cut with a diagnostic.
    pub const MAX_DEPTH: usize = 64;
    /// Nested instance expansions (instance in a component in an instance ...).
    pub const MAX_INSTANCE_DEPTH: usize = 16;
    /// Nodes in a resolved tree; instances can multiply the node count, so this is the real bound.
    pub const MAX_RESOLVED_NODES: usize = 50_000;
    /// Bytes of names, text, ids and prop JSON in a resolved tree. The node cap alone is not enough: one instance
    /// of a component holding a 100 000-character text, expanded 500 times, is 50 MB from a 100 KB document.
    pub const MAX_RESOLVED_BYTES: usize = 64 * 1024 * 1024;
    /// How far above the document's highest clock a move may be (a hostile u64::MAX clock would pin a node forever).
    pub const MAX_CLOCK_JUMP: u64 = 1 << 20;
    pub const MAX_NAME_CHARS: usize = 100;
    pub const MAX_TEXT_CHARS: usize = 100_000;
    pub const MAX_OVERRIDES: usize = 256;
    pub const MAX_PATH_BYTES: usize = 65_536;
    pub const MAX_PATH_SEGMENTS: usize = 10_000;
    pub const MAX_ORDER_LEN: usize = 32;
    /// Violations / findings a single validation run reports (the rest are dropped, a count is kept).
    pub const MAX_REPORTED: usize = 100;
    /// Coordinates and lengths: finite and within this magnitude.
    pub const MAX_COORD: f64 = 1.0e6;
}
