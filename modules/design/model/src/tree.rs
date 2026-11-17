//! The tree view of the flat node map, and moves (T1).
//!
//! Local moves refuse to create a cycle. Concurrent moves can still cross (A under B on one device, B under A on
//! another), and the merged state then holds a parent cycle. `forest` breaks every such cycle deterministically from
//! the state alone, so every replica reads the same tree: in each cycle the node whose move has the highest
//! `(clock, id)` (the latest move) loses its parent link and surfaces as a detached root with its subtree; the
//! earlier moves are kept. (The plan words this "keep the move with the lower Lamport clock".)

use std::collections::BTreeMap;

use crate::ids::is_order;
use crate::schema::{Doc, Node};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forest {
    /// Roots of type `page`, by `(order, id)`.
    pub pages: Vec<String>,
    /// Every other root: no parent, a parent that does not exist, or the cut node of a broken cycle.
    pub detached: Vec<String>,
    /// Children by `(order, id)`.
    pub children: BTreeMap<String, Vec<String>>,
    /// Nodes whose parent link was cut to break a cycle.
    pub broken: Vec<String>,
}

pub fn forest(doc: &Doc) -> Forest {
    let mut eff: BTreeMap<&str, Option<&str>> = doc
        .nodes
        .iter()
        .map(|(id, n)| {
            (
                id.as_str(),
                n.parent.as_deref().filter(|p| doc.nodes.contains_key(*p)),
            )
        })
        .collect();
    let mut broken = vec![];
    // 0 = new, 1 = on the current walk, 2 = done. Each node has one parent, so a walk meets at most one cycle.
    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    let ids: Vec<&str> = eff.keys().copied().collect();
    for start in ids {
        if state.contains_key(start) {
            continue;
        }
        let mut path: Vec<&str> = vec![];
        let mut cur = Some(start);
        while let Some(c) = cur {
            match state.get(c).copied().unwrap_or(0) {
                0 => {
                    state.insert(c, 1);
                    path.push(c);
                    cur = eff[c];
                }
                1 => {
                    let pos = path.iter().position(|p| *p == c).unwrap_or(0);
                    let victim = path[pos..]
                        .iter()
                        .copied()
                        .max_by_key(|id| (doc.nodes[*id].clock, *id))
                        .unwrap_or(c);
                    eff.insert(victim, None);
                    broken.push(victim.to_string());
                    break;
                }
                _ => break,
            }
        }
        for p in path {
            state.insert(p, 2);
        }
    }
    broken.sort();
    let mut f = Forest {
        broken,
        ..Forest::default()
    };
    let mut order: Vec<&str> = eff.keys().copied().collect();
    order.sort_by(|a, b| (&doc.nodes[*a].order, a).cmp(&(&doc.nodes[*b].order, b)));
    for id in order {
        match eff[id] {
            Some(p) => f
                .children
                .entry(p.to_string())
                .or_default()
                .push(id.to_string()),
            None if doc.nodes[id].ty == crate::schema::NodeType::Page => {
                f.pages.push(id.to_string())
            }
            None => f.detached.push(id.to_string()),
        }
    }
    f
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveRecord {
    pub parent: Option<String>,
    pub order: String,
    pub clock: u64,
}

impl MoveRecord {
    /// Last-writer-wins key: the clock, then the contents so equal clocks still agree on one winner.
    fn key(&self) -> (u64, &Option<String>, &str) {
        (self.clock, &self.parent, &self.order)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveError {
    UnknownNode,
    UnknownParent,
    /// The new parent is the node itself or one of its descendants.
    Cycle,
    /// The new parent is a text/rect/ellipse/image/vector/instance node.
    LeafParent,
    /// Only pages are roots, and a page never moves under a node.
    NoParent,
    BadOrder,
    /// Local moves must carry a clock above the node's last move (`Doc::next_clock`).
    StaleClock,
}

impl Doc {
    /// A clock above every move seen so far.
    pub fn next_clock(&self) -> u64 {
        self.nodes
            .values()
            .map(|n| n.clock)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    /// A local move: refused when it would put a node under itself or its descendants. The ancestor walk follows the
    /// stored parent links (bounded by the node count), so it is conservative on a doc that holds an unbroken cycle.
    pub fn move_node(
        &mut self,
        id: &str,
        parent: Option<&str>,
        order: &str,
        clock: u64,
    ) -> Result<(), MoveError> {
        let node = self.nodes.get(id).ok_or(MoveError::UnknownNode)?;
        if !is_order(order) {
            return Err(MoveError::BadOrder);
        }
        if clock <= node.clock {
            return Err(MoveError::StaleClock);
        }
        let is_page = node.ty == crate::schema::NodeType::Page;
        match parent {
            None if !is_page => return Err(MoveError::NoParent),
            Some(_) if is_page => return Err(MoveError::NoParent),
            None => {}
            Some(p) => {
                let pn = self.nodes.get(p).ok_or(MoveError::UnknownParent)?;
                if !pn.ty.is_container() {
                    return Err(MoveError::LeafParent);
                }
                let mut cur = Some(p);
                for _ in 0..=self.nodes.len() {
                    match cur {
                        Some(c) if c == id => return Err(MoveError::Cycle),
                        Some(c) => cur = self.nodes.get(c).and_then(|n: &Node| n.parent.as_deref()),
                        None => break,
                    }
                }
            }
        }
        self.apply_remote_move(
            id,
            MoveRecord {
                parent: parent.map(str::to_string),
                order: order.to_string(),
                clock,
            },
        );
        Ok(())
    }

    /// Merge a move made elsewhere (last writer wins, no cycle check: that is what `forest` is for). Unknown ids and
    /// malformed orders are ignored. Commutative and idempotent.
    pub fn apply_remote_move(&mut self, id: &str, rec: MoveRecord) {
        if !is_order(&rec.order) {
            return;
        }
        if let Some(n) = self.nodes.get_mut(id) {
            let cur = MoveRecord {
                parent: n.parent.clone(),
                order: n.order.clone(),
                clock: n.clock,
            };
            if rec.key() > cur.key() {
                n.parent = rec.parent;
                n.order = rec.order;
                n.clock = rec.clock;
            }
        }
    }
}
