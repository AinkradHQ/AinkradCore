//! Gesture preview (V2-03): a drag's ops applied to a copy of only the boards they touch in the resolved page, so a
//! drag frame re-lays out one or two artboards instead of re-resolving the document (38 ms at 5 000 nodes). The same
//! ops are written to the document, as one batch, when the gesture ends; the preview never touches the CRDT.
//!
//! Gesture ops are `move` and `set` (literal geometry) and `add` for alt-drag copies, which are cloned from the
//! resolved source (`dups`: new id -> source id) so tokens and instances look the same as the original.
//! A commit (`Host::commit`) patches the cached resolved page the same way.

use std::collections::{HashMap, HashSet};

use design_doc::Op;
use design_model::tree::forest;
use design_model::{Doc, Forest, ResolvedNode};
use serde_json::Value;

use crate::host::Host;

pub struct Patched {
    /// Page-level ids in order after the ops.
    pub order: Vec<String>,
    /// The changed boards (by root id); every other root is the base page's.
    pub boards: HashMap<String, ResolvedNode>,
}

/// The top-level node (child of `page`) that holds doc node `id`.
pub fn board_of(doc: &Doc, page: &str, id: &str) -> Option<String> {
    let mut cur = id;
    for _ in 0..=doc.nodes.len() {
        let p = doc.nodes.get(cur)?.parent.as_deref()?;
        if p == page {
            return Some(cur.to_string());
        }
        cur = p;
    }
    None
}

fn find<'a>(n: &'a ResolvedNode, id: &str) -> Option<&'a ResolvedNode> {
    if n.id == id {
        return Some(n);
    }
    n.children.iter().find_map(|c| find(c, id))
}

fn find_mut<'a>(n: &'a mut ResolvedNode, id: &str) -> Option<&'a mut ResolvedNode> {
    if n.id == id {
        return Some(n);
    }
    n.children.iter_mut().find_map(|c| find_mut(c, id))
}

/// Take `id` out of whichever child list holds it.
fn take(n: &mut ResolvedNode, id: &str) -> Option<ResolvedNode> {
    if let Some(i) = n.children.iter().position(|c| c.id == id) {
        return Some(n.children.remove(i));
    }
    n.children.iter_mut().find_map(|c| take(c, id))
}

/// A resolved copy with every id renamed by `map` (instance-internal ids `inst/child` follow their instance).
fn renamed(n: &ResolvedNode, map: &HashMap<&str, &str>) -> ResolvedNode {
    let id = match n.id.split_once('/') {
        Some((head, rest)) => format!("{}/{rest}", map.get(head).copied().unwrap_or(head)),
        None => map.get(n.id.as_str()).copied().unwrap_or(&n.id).to_string(),
    };
    ResolvedNode {
        id,
        children: n.children.iter().map(|c| renamed(c, map)).collect(),
        ..n.clone()
    }
}

struct Work<'a> {
    doc: &'a Doc,
    page: &'a str,
    base: &'a ResolvedNode,
    order: Vec<String>,
    boards: HashMap<String, ResolvedNode>,
    /// orders and parents set by earlier ops of this batch
    orders: HashMap<String, String>,
    parents: HashMap<String, String>,
}

impl Work<'_> {
    fn order_of(&self, id: &str) -> &str {
        self.orders
            .get(id)
            .or_else(|| self.doc.nodes.get(id).map(|n| &n.order))
            .map_or("", String::as_str)
    }

    fn board(&self, id: &str) -> Option<String> {
        match self.parents.get(id) {
            Some(p) if p == self.page => Some(id.to_string()),
            Some(p) => self.board(&p.clone()),
            None => board_of(self.doc, self.page, id),
        }
    }

    /// Copy board `b` from the base page into the working set (once).
    fn open(&mut self, b: &str) {
        if !self.boards.contains_key(b)
            && let Some(n) = self.base.children.iter().find(|c| c.id == b)
        {
            self.boards.insert(b.to_string(), n.clone());
        }
    }

    fn node_mut(&mut self, id: &str) -> Option<&mut ResolvedNode> {
        let b = self.board(id)?;
        self.open(&b);
        find_mut(self.boards.get_mut(&b)?, id)
    }

    fn detach(&mut self, id: &str) -> Option<ResolvedNode> {
        if let Some(i) = self.order.iter().position(|o| o == id) {
            self.order.remove(i);
            self.open(id);
            return self.boards.remove(id);
        }
        let b = self.board(id)?;
        self.open(&b);
        take(self.boards.get_mut(&b)?, id)
    }

    fn attach(&mut self, n: ResolvedNode, parent: &str, order: &str) {
        let id = n.id.clone();
        self.orders.insert(id.clone(), order.to_string());
        self.parents.insert(id.clone(), parent.to_string());
        if parent == self.page {
            let at = self
                .order
                .iter()
                .position(|o| self.order_of(o) > order)
                .unwrap_or(self.order.len());
            self.order.insert(at, id.clone());
            self.boards.insert(id, n);
            return;
        }
        let orders: Vec<String> = match self.node_mut(parent) {
            Some(p) => p.children.iter().map(|c| c.id.clone()).collect(),
            None => return,
        };
        let at = orders
            .iter()
            .position(|o| self.order_of(o) > order)
            .unwrap_or(orders.len());
        if let Some(p) = self.node_mut(parent) {
            p.children.insert(at, n);
        }
    }
}

fn set_geometry(n: &mut ResolvedNode, key: &str, value: &Value) {
    if value.is_null() {
        n.props.remove(key);
    } else {
        n.props.insert(key.to_string(), value.clone());
    }
}

/// Apply gesture `ops` to the boards of `base` (the resolved page `page`) they touch.
pub fn patch(
    base: &ResolvedNode,
    doc: &Doc,
    ops: &[Op],
    dups: &HashMap<String, String>,
) -> Patched {
    let mut w = Work {
        doc,
        page: &base.id,
        base,
        order: base.children.iter().map(|c| c.id.clone()).collect(),
        boards: HashMap::new(),
        orders: HashMap::new(),
        parents: HashMap::new(),
    };
    let inv: HashMap<&str, &str> = dups.iter().map(|(n, s)| (s.as_str(), n.as_str())).collect();
    let copied: HashSet<&str> = dups.keys().map(String::as_str).collect();
    for op in ops {
        match op {
            Op::Set { id, key, value } => {
                if let Some(n) = w.node_mut(id) {
                    set_geometry(n, key, value);
                }
            }
            // V2-04: a committed splice, or the marked-text preview (the whole composed text)
            Op::Splice { id, at, del, text } => {
                if let Some(n) = w.node_mut(id) {
                    let t = n.text.take().unwrap_or_default();
                    let b = |u: u32| design_doc::byte_of_utf16(&t, u as usize).unwrap_or(t.len());
                    let (a, e) = (b(*at), b(at.saturating_add(*del)).max(b(*at)));
                    n.text = Some([&t[..a], text.as_str(), &t[e..]].concat());
                }
            }
            Op::Text { id, text } => {
                if let Some(n) = w.node_mut(id) {
                    n.text = Some(text.clone());
                }
            }
            Op::Move { id, parent, order } => {
                let Some(p) = parent else { continue };
                if let Some(n) = w.detach(id) {
                    w.attach(n, p, order);
                }
            }
            Op::Add {
                id,
                parent: Some(p),
                order,
                props,
                ..
            } => {
                // a copy's descendants come with its root's clone
                if copied.contains(p.as_str()) {
                    continue;
                }
                let Some(src) = dups.get(id) else { continue };
                let Some(sb) = board_of(doc, &base.id, src) else {
                    continue;
                };
                let found = w.boards.get(&sb).and_then(|b| find(b, src)).or_else(|| {
                    base.children
                        .iter()
                        .find(|c| c.id == sb)
                        .and_then(|b| find(b, src))
                });
                let Some(s) = found else { continue };
                let mut n = renamed(s, &inv);
                for k in ["x", "y"] {
                    set_geometry(&mut n, k, props.get(k).unwrap_or(&Value::Null));
                }
                w.attach(n, p, order);
            }
            _ => {}
        }
    }
    Patched {
        order: w.order,
        boards: w.boards,
    }
}

impl Host {
    /// Write `ops` as one batch, then keep the cached model, resolved page and renderer in step by patching only
    /// the boards they touch (the gesture preview's path) instead of re-reading and re-resolving the whole document,
    /// which costs 100+ ms at 5 000 nodes. Anything the patch cannot follow falls back to the full refresh.
    pub(crate) fn commit(&mut self, ops: &[Op], dups: &HashMap<String, String>) -> Result<(), i32> {
        self.commit_as(ops, dups, None)
    }

    /// `commit`, or with `typing = Some(merge)` a typing batch (`Live::apply_typing`: a run is one undo step).
    pub(crate) fn commit_as(
        &mut self,
        ops: &[Op],
        dups: &HashMap<String, String>,
        typing: Option<bool>,
    ) -> Result<(), i32> {
        if ops.is_empty() {
            return Ok(());
        }
        let simple = ops.iter().all(|o| {
            matches!(
                o,
                Op::Set { .. } | Op::Move { .. } | Op::Add { .. } | Op::Splice { .. }
            )
        });
        let patched = match (&self.model, &self.resolved) {
            (Some(m), Some(res)) if simple && self.is_loaded() => res
                .pages
                .get(self.page)
                .map(|page| patch(page, m, ops, dups)),
            _ => None,
        };
        let (Some(mut p), Some(mut m)) = (patched, self.model.take()) else {
            let mut m = self.live.read();
            let r = self.write_ops(&mut m, ops, typing);
            // also after a refusal: an `Error::Reset` emptied the document
            self.changed();
            return r.map_err(crate::host::code);
        };
        // inside `recover`: a yrs panic resets the replica and comes back as `Error::Reset` -> DE_ERR_RESET
        if let Err(e) = self.write_ops(&mut m, ops, typing) {
            self.changed();
            return Err(crate::host::code(e));
        }
        let (Some(res), Some(r)) = (self.resolved.as_mut(), self.renderer.as_mut()) else {
            self.changed();
            return Ok(());
        };
        let Some(page) = res.pages.get_mut(self.page) else {
            self.changed();
            return Ok(());
        };
        let mut changed: HashSet<String> = p.boards.keys().cloned().collect();
        changed.extend(std::mem::take(&mut self.previewed));
        let mut old: HashMap<String, ResolvedNode> = std::mem::take(&mut page.children)
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();
        page.children = p
            .order
            .iter()
            .filter_map(|id| p.boards.remove(id).or_else(|| old.remove(id)))
            .collect();
        let roots: Vec<&ResolvedNode> = page.children.iter().collect();
        r.load_patch(&roots, &changed);
        match self.tree.as_mut() {
            Some(t) => tree_apply(t, &m, ops),
            None => self.tree = Some(forest(&m)),
        }
        self.selection.retain(|id| m.nodes.contains_key(id));
        self.model = Some(m);
        Ok(())
    }
}

impl Host {
    fn write_ops(
        &mut self,
        m: &mut Doc,
        ops: &[Op],
        typing: Option<bool>,
    ) -> Result<(), design_doc::Error> {
        match typing {
            Some(merge) => self.live.apply_typing(m, ops, merge),
            None => self.live.apply_gesture_ops(m, ops),
        }
    }
}

/// Keep the tree in step with a committed batch of moves and adds (re-deriving it costs ~30 ms at 5 000 nodes).
/// Local moves never make a cycle, so only the parent map and the ordered child lists change.
fn tree_apply(t: &mut Forest, m: &Doc, ops: &[Op]) {
    let key = |id: &str| (m.nodes.get(id).map(|n| n.order.clone()), id.to_string());
    for op in ops {
        let (id, parent) = match op {
            Op::Move {
                id,
                parent: Some(p),
                ..
            }
            | Op::Add {
                id,
                parent: Some(p),
                ..
            } => (id, p),
            _ => continue,
        };
        if let Some(old) = t.parent.insert(id.clone(), parent.clone())
            && let Some(k) = t.children.get_mut(&old)
        {
            k.retain(|c| c != id);
        }
        let kids = t.children.entry(parent.clone()).or_default();
        let at = kids.partition_point(|c| key(c) < key(id));
        kids.insert(at, id.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use design_model::{Theme, resolve};
    use serde_json::json;

    const PAGE: &str = "n_pppppppppppp";
    const A: &str = "n_aaaaaaaaaaaa";
    const B: &str = "n_bbbbbbbbbbbb";
    const C: &str = "n_cccccccccccc";

    fn doc() -> Doc {
        serde_json::from_value(json!({"nodes": {
            PAGE: {"type": "page", "parent": null, "order": "a"},
            A: {"type": "frame", "parent": PAGE, "order": "a", "props": {"w": 100, "h": 100}},
            B: {"type": "frame", "parent": PAGE, "order": "b", "props": {"x": 200, "w": 100, "h": 100}},
            C: {"type": "rect", "parent": A, "order": "a", "props": {"x": 5, "w": 10, "h": 10}},
        }}))
        .unwrap()
    }

    fn page(d: &Doc) -> ResolvedNode {
        resolve("dd_t", d, None, Theme::Day)
            .unwrap()
            .pages
            .remove(0)
    }

    #[test]
    fn a_set_copies_only_its_board() {
        let d = doc();
        let base = page(&d);
        let ops = [Op::Set {
            id: C.into(),
            key: "x".into(),
            value: json!(50.0),
        }];
        let p = patch(&base, &d, &ops, &HashMap::new());
        assert_eq!(p.order, vec![A, B]);
        assert_eq!(p.boards.keys().collect::<Vec<_>>(), vec![A]);
        assert_eq!(p.boards[A].children[0].props["x"], json!(50.0));
    }

    #[test]
    fn moves_nest_and_unnest_across_boards() {
        let d = doc();
        let base = page(&d);
        // C from A into B
        let ops = [Op::Move {
            id: C.into(),
            parent: Some(B.into()),
            order: "a".into(),
        }];
        let p = patch(&base, &d, &ops, &HashMap::new());
        assert!(p.boards[A].children.is_empty());
        assert_eq!(p.boards[B].children[0].id, C);
        // C out to the page, after B
        let ops = [Op::Move {
            id: C.into(),
            parent: Some(PAGE.into()),
            order: "c".into(),
        }];
        let p = patch(&base, &d, &ops, &HashMap::new());
        assert_eq!(p.order, vec![A, B, C]);
        assert!(p.boards.contains_key(C));
        // board B into A, before C: B leaves the page
        let ops = [Op::Move {
            id: B.into(),
            parent: Some(A.into()),
            order: "0a".into(),
        }];
        let p = patch(&base, &d, &ops, &HashMap::new());
        assert_eq!(p.order, vec![A]);
        let kids: Vec<&str> = p.boards[A].children.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(kids, vec![B, C]);
    }

    #[test]
    fn a_copy_clones_the_resolved_source_under_its_new_ids() {
        let d = doc();
        let base = page(&d);
        let (na, nc) = ("n_dddddddddddd", "n_eeeeeeeeeeee");
        let dups: HashMap<String, String> = [
            (na.to_string(), A.to_string()),
            (nc.to_string(), C.to_string()),
        ]
        .into();
        let ops: Vec<Op> = serde_json::from_value(json!([
            {"op": "add", "id": na, "type": "frame", "parent": PAGE, "order": "c", "props": {"x": 400, "w": 100}},
            {"op": "add", "id": nc, "type": "rect", "parent": na, "order": "a"},
        ]))
        .unwrap();
        let p = patch(&base, &d, &ops, &dups);
        assert_eq!(p.order, vec![A, B, na]);
        assert_eq!(p.boards[na].props["x"], json!(400));
        assert_eq!(
            p.boards[na].props["h"],
            json!(100),
            "rest of the source's look"
        );
        assert_eq!(p.boards[na].children[0].id, nc);
    }
}
