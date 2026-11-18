//! The tree view of the flat node map, and moves (T1).
//!
//! Local moves refuse to create a cycle. Concurrent moves can still cross (A under B on one device, B under A on
//! another), and the merged state then holds a parent cycle. `forest` breaks every such cycle deterministically from
//! the state alone, so every replica reads the same tree: in each cycle the node whose move has the highest
//! `(clock, id)` (the latest move) loses that move; the earlier moves are kept. (The plan words this "keep the move
//! with the lower Lamport clock".) Every move records the parent the node had before it (`Node::prev`), so a losing
//! move is REVERTED: the node goes back under its previous parent, subtree and all. Only when that parent is gone,
//! or going back would close another cycle, does the node surface as a detached root with its subtree.

use std::collections::BTreeMap;

use crate::ids::{is_order, rebalance};
use crate::limits::{MAX_CLOCK_JUMP, MAX_DEPTH};
use crate::schema::{Doc, Node};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forest {
    /// Roots of type `page`, by `(order, id)`.
    pub pages: Vec<String>,
    /// Every other root: no parent, a parent that does not exist, or the cut node of a broken cycle.
    pub detached: Vec<String>,
    /// Children by `(order, id)`.
    pub children: BTreeMap<String, Vec<String>>,
    /// Nodes whose parent link was cut to break a cycle (sorted): the loser of each cycle.
    pub broken: Vec<String>,
    /// The cut nodes that went back under their previous parent (sorted, a subset of `broken`); the others are in
    /// `detached`.
    pub reverted: Vec<String>,
    /// Effective parent of every non-root node (after the cycle cuts).
    pub parent: BTreeMap<String, String>,
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
    // Revert each cut node to its previous parent when that is safe. Sorted order and a check against the forest as
    // it stands make this a pure function of the state, and the check keeps the forest acyclic: the walk up from the
    // old parent is bounded by MAX_DEPTH (deeper is cut by the resolver anyway), so this stays O(cuts * depth).
    let mut reverted = vec![];
    for v in &broken {
        let Some(prev) = doc.nodes[v.as_str()]
            .prev
            .as_deref()
            // only back into a container: a leaf (a hostile `prev`) never gains children
            .filter(|p| doc.nodes.get(*p).is_some_and(|n| n.ty.is_container()))
        else {
            continue;
        };
        let mut cur = Some(prev);
        let mut steps = 0;
        while let Some(c) = cur {
            if c == v || steps > MAX_DEPTH {
                break;
            }
            steps += 1;
            cur = eff[c];
        }
        if cur.is_none()
            && let Some((key, _)) = doc.nodes.get_key_value(v.as_str())
        {
            eff.insert(key.as_str(), Some(prev));
            reverted.push(v.clone());
        }
    }
    let mut f = Forest {
        broken,
        reverted,
        ..Forest::default()
    };
    let mut order: Vec<&str> = eff.keys().copied().collect();
    order.sort_by(|a, b| (&doc.nodes[*a].order, a).cmp(&(&doc.nodes[*b].order, b)));
    for id in order {
        match eff[id] {
            Some(p) => {
                f.parent.insert(id.to_string(), p.to_string());
                f.children
                    .entry(p.to_string())
                    .or_default()
                    .push(id.to_string());
            }
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
    /// The parent before this move (`Node::prev`).
    pub prev: Option<String>,
}

impl MoveRecord {
    /// Last-writer-wins key: the clock, then the contents so equal clocks still agree on one winner.
    fn key(&self) -> (u64, &Option<String>, &str, &Option<String>) {
        (self.clock, &self.parent, &self.order, &self.prev)
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
    /// The clock is more than `MAX_CLOCK_JUMP` above every clock in the document.
    ClockTooHigh,
    /// More siblings than `rebalance` can renumber.
    TooManySiblings,
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
        if clock > self.next_clock().saturating_add(MAX_CLOCK_JUMP) {
            return Err(MoveError::ClockTooHigh);
        }
        let prev = node.parent.clone();
        self.lww(
            id,
            MoveRecord {
                parent: parent.map(str::to_string),
                order: order.to_string(),
                clock,
                prev,
            },
        );
        Ok(())
    }

    /// Merge a move made elsewhere (last writer wins, no cycle check: that is what `forest` is for). Returns `false`,
    /// changing nothing, for an unknown id, a malformed order, or a clock more than `MAX_CLOCK_JUMP` above the highest
    /// clock in the document (a peer sending `u64::MAX` would otherwise pin the node for ever; the sync layer should
    /// treat `false` as a protocol violation). `true` means the record was valid, not that it won. Commutative and
    /// idempotent for valid records. O(nodes); use `apply_remote_moves` for a batch.
    ///
    /// The clock cap makes acceptance depend on the receiver's state, so it is NOT commutative for records that
    /// exceed it: replicas that disagree on the highest clock can disagree on whether to apply one. That is
    /// deliberate (an honest peer never exceeds it), so the sync layer must treat `false` as a protocol violation and
    /// drop the peer, never as a skipped update (`design-crdt` does, and its tests close the connection on one).
    pub fn apply_remote_move(&mut self, id: &str, rec: MoveRecord) -> bool {
        let limit = self.next_clock().saturating_add(MAX_CLOCK_JUMP);
        self.apply_bounded(id, rec, limit)
    }

    /// A batch of remote moves, bound-checked against the clock as it grows; returns how many were valid.
    pub fn apply_remote_moves(
        &mut self,
        moves: impl IntoIterator<Item = (String, MoveRecord)>,
    ) -> usize {
        let mut top = self.next_clock();
        let mut n = 0;
        for (id, rec) in moves {
            let c = rec.clock;
            if self.apply_bounded(&id, rec, top.saturating_add(MAX_CLOCK_JUMP)) {
                top = top.max(c);
                n += 1;
            }
        }
        n
    }

    fn apply_bounded(&mut self, id: &str, rec: MoveRecord, limit: u64) -> bool {
        if !is_order(&rec.order) || rec.clock > limit || !self.nodes.contains_key(id) {
            return false;
        }
        self.lww(id, rec);
        true
    }

    fn lww(&mut self, id: &str, rec: MoveRecord) {
        if let Some(n) = self.nodes.get_mut(id) {
            let cur = MoveRecord {
                parent: n.parent.clone(),
                order: n.order.clone(),
                clock: n.clock,
                prev: n.prev.clone(),
            };
            if rec.key() > cur.key() {
                n.parent = rec.parent;
                n.order = rec.order;
                n.clock = rec.clock;
                n.prev = rec.prev;
            }
        }
    }

    /// Renumber the children of `parent` with evenly spaced orders, keeping their current sequence. Call it when
    /// `ids::between` returns `None` (32-character orders exhausted by repeated inserts at one spot). Returns how
    /// many nodes were renumbered.
    ///
    /// Only the orders change: no parent, clock or `prev` is written, so a concurrent move of one of these children
    /// to another parent is not undone (in the yrs document `order` is its own register, apart from the move
    /// register that holds the parent).
    pub fn rebalance_children(&mut self, parent: &str) -> Result<usize, MoveError> {
        if !self.nodes.contains_key(parent) {
            return Err(MoveError::UnknownParent);
        }
        let kids = forest(self).children.remove(parent).unwrap_or_default();
        let orders = rebalance(kids.len()).ok_or(MoveError::TooManySiblings)?;
        for (id, order) in kids.iter().zip(orders) {
            if let Some(n) = self.nodes.get_mut(id) {
                n.order = order;
            }
        }
        Ok(kids.len())
    }
}
