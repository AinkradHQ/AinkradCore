//! Canvas edits as typed ops (V2-03): move (with snapping, auto-layout reorder, nest/unnest by drop target),
//! resize, duplicate (also alt-drag), nudge. Every edit is one `apply_ops` batch: one undo step.
//!
//! Geometry rules: `x`/`y` are written only where they mean something (a child of a frame without `layout`, or a
//! top-level node, whose `x`/`y` are world); in an auto-layout frame a drag or nudge changes the order instead.
//! Pointer deltas are whole points; snapped values are written to 1/100 pt. ⌘ held while dragging turns snapping off.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};

use design_doc::Op;
use design_model::NodeType;
use design_model::ids::between;
use design_render::Rect;
use serde_json::{Value, json};

use crate::ffi::*;
use crate::host::Host;
use crate::interact::{Edit, Gesture, Turn, union};
use crate::snap::{
    SNAP_PT, edges, insert_index, map_rect, norm_deg, resize, round2, snap_edges, snap_move, turn,
};

/// ⇧ while rotating snaps to this many degrees.
const ROTATE_SNAP: f32 = 15.0;

/// Gap between a duplicated top-level node and its original.
const DUP_GAP: f32 = 40.0;

type Guides = Vec<[f32; 4]>;

fn set(id: &str, key: &str, value: Value) -> Op {
    Op::Set {
        id: id.into(),
        key: key.into(),
        value,
    }
}

pub(crate) fn seed() -> u64 {
    RandomState::new().hash_one(std::time::SystemTime::now()) | 1
}

impl Host {
    pub(crate) fn order_of(&self, id: &str) -> Option<String> {
        Some(self.model.as_ref()?.nodes.get(id)?.order.clone())
    }

    /// World position children of `parent` are placed from (the page's is the world origin).
    pub(crate) fn origin(&self, parent: &str) -> (f32, f32) {
        match self.rect(parent) {
            Some(r) if Some(parent) != self.page_id().as_deref() => (r.left, r.top),
            _ => (0.0, 0.0),
        }
    }

    pub(crate) fn new_id(&mut self) -> String {
        const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        loop {
            let mut v = self.rng;
            v ^= v << 13;
            v ^= v >> 7;
            v ^= v << 17;
            self.rng = v;
            let id: String = "n_"
                .chars()
                .chain((0..12).map(|i| A[((v >> (i * 5)) & 31) as usize] as char))
                .collect();
            if !self
                .model
                .as_ref()
                .is_some_and(|m| m.nodes.contains_key(&id))
            {
                return id;
            }
        }
    }

    /// `add` ops copying `src`'s subtree under new ids (root first, its parent/order as given) and the id map.
    fn copy_ops(
        &mut self,
        src: &str,
        parent: &str,
        order: &str,
        dups: &mut HashMap<String, String>,
    ) -> Vec<Op> {
        let mut out = vec![];
        let mut stack = vec![(src.to_string(), parent.to_string(), Some(order.to_string()))];
        while let Some((s, p, ord)) = stack.pop() {
            let Some(n) = self.model.as_ref().and_then(|m| m.nodes.get(&s)).cloned() else {
                continue;
            };
            let id = self.new_id();
            for k in self.kids(&s).into_iter().rev() {
                stack.push((k, id.clone(), None));
            }
            dups.insert(id.clone(), s);
            out.push(Op::Add {
                id,
                ty: n.ty,
                parent: Some(p),
                order: ord.unwrap_or(n.order),
                name: n.name,
                props: n.props,
                text: n.text,
            });
        }
        out
    }

    pub(crate) fn begin_edit(
        &mut self,
        handle: Option<u8>,
        dup: bool,
        start: (f32, f32),
    ) -> Option<Gesture> {
        // a locked node stays where it is (selected from the layers panel, it is never carried)
        let srcs: Vec<String> = self
            .top_selected()
            .into_iter()
            .filter(|id| !self.locked(id))
            .collect();
        let rects: Vec<Rect> = srcs.iter().map(|id| self.rect(id)).collect::<Option<_>>()?;
        let frames: Vec<(Rect, f32)> = srcs
            .iter()
            .map(|id| self.frame(id))
            .collect::<Option<_>>()?;
        if srcs.is_empty() {
            return None;
        }
        let (mut copies, mut dups) = (vec![], HashMap::new());
        let ids = if dup {
            for s in &srcs {
                let (p, o) = (self.parent_of(s)?, self.order_of(s)?);
                copies.push(self.copy_ops(s, &p, &o, &mut dups));
            }
            copies.iter().filter_map(|c| op_id(c.first()?)).collect()
        } else {
            srcs
        };
        Some(Gesture::Edit(Edit {
            handle,
            ids,
            rects,
            frames,
            turn: None,
            start,
            copies,
            dups,
            ops: vec![],
            guides: vec![],
        }))
    }

    /// A rotate drag from world point `from`: about the centre of the selection's drawn bounds.
    pub(crate) fn begin_rotate(&mut self, from: (f32, f32)) -> Option<Gesture> {
        let Some(Gesture::Edit(mut e)) = self.begin_edit(None, false, from) else {
            return None;
        };
        let c = match &e.frames[..] {
            [(r, _)] => (r.center_x(), r.center_y()),
            _ => {
                let b = union(e.ids.iter().filter_map(|id| self.drawn(id)))?;
                (b.center_x(), b.center_y())
            }
        };
        e.turn = Some(Turn {
            center: c,
            from: (from.1 - c.1).atan2(from.0 - c.0).to_degrees(),
            base: e
                .frames
                .iter()
                .map(|(r, rot)| (*rot, (r.center_x(), r.center_y())))
                .collect(),
        });
        Some(Gesture::Edit(e))
    }

    /// `rotation` for each node turned by the pointer's angle about the centre (⇧: one node snaps to 15°, a group
    /// turns in 15° steps); in a group each node also moves around the group's centre.
    pub(crate) fn rotate_ops(&self, e: &Edit, t: &Turn, p: (f32, f32), mods: u32) -> Vec<Op> {
        let snap = mods & DE_MOD_SHIFT != 0;
        let step = |d: f32| (d / ROTATE_SNAP).round() * ROTATE_SNAP;
        let mut d = (p.1 - t.center.1).atan2(p.0 - t.center.0).to_degrees() - t.from;
        if snap && e.ids.len() > 1 {
            d = step(d);
        }
        let mut ops = vec![];
        for (i, id) in e.ids.iter().enumerate() {
            let (rot0, c0) = t.base[i];
            let mut r = rot0 + d;
            if snap && e.ids.len() == 1 {
                r = step(r);
            }
            // the node's own rotation: its drawn rotation minus what its ancestors add
            let own = self.own_rotation(id) + norm_deg(r - rot0);
            let own = round2(norm_deg(own));
            ops.push(set(
                id,
                "rotation",
                if own == 0.0 { Value::Null } else { json!(own) },
            ));
            let par = self.parent_of(id).unwrap_or_default();
            if e.ids.len() > 1 && !self.is_flow(&par) {
                let c1 = turn(c0, t.center, d);
                let (r0, o) = (e.rects[i], self.origin(&par));
                ops.push(set(id, "x", json!(round2(r0.left - o.0 + c1.0 - c0.0))));
                ops.push(set(id, "y", json!(round2(r0.top - o.1 + c1.1 - c0.1))));
            }
        }
        ops
    }

    fn own_rotation(&self, id: &str) -> f32 {
        self.model
            .as_ref()
            .and_then(|m| m.nodes.get(id))
            .and_then(|n| n.props.get("rotation")?.as_f64())
            .unwrap_or(0.0) as f32
    }

    /// One rotated node resized from a handle: the drag is read in the node's own axes and the opposite side stays
    /// where it shows. ponytail: a node inside a rotated parent moves in the parent's unrotated axes.
    fn resize_turned(&self, e: &Edit, h: u8, p: (f32, f32), mods: u32) -> Vec<Op> {
        let ((f0, rot), r0, id) = (e.frames[0], e.rects[0], &e.ids[0]);
        let c0 = (f0.center_x(), f0.center_y());
        let dw = (p.0 - e.start.0, p.1 - e.start.1);
        let dl = turn(dw, (0.0, 0.0), -rot);
        let n = resize(
            f0,
            h,
            (dl.0.round(), dl.1.round()),
            mods & DE_MOD_SHIFT != 0,
        );
        let c1 = turn((n.center_x(), n.center_y()), c0, rot);
        let mut ops = vec![
            set(id, "w", json!(round2(n.width()))),
            set(id, "h", json!(round2(n.height()))),
        ];
        let par = self.parent_of(id).unwrap_or_default();
        if !self.is_flow(&par) {
            let o = self.origin(&par);
            let x = r0.left - o.0 + (c1.0 - c0.0) - (n.width() - r0.width()) / 2.0;
            let y = r0.top - o.1 + (c1.1 - c0.1) - (n.height() - r0.height()) / 2.0;
            ops.push(set(id, "x", json!(round2(x))));
            ops.push(set(id, "y", json!(round2(y))));
        }
        ops
    }

    /// The container a drop at world `p` lands in: the deepest frame or component under it, looking through the
    /// carried nodes, else the page.
    pub(crate) fn drop_target(&self, p: (f32, f32), carried: &[String], page: &str) -> String {
        let skip = |id: &str| carried.iter().any(|c| c == id);
        let (Some(r), Some(m)) = (self.renderer.as_ref(), self.model.as_ref()) else {
            return page.to_string();
        };
        r.hit_world_skip(p.0, p.1, &skip)
            .and_then(|h| {
                h.path.into_iter().rev().find(|id| {
                    m.nodes
                        .get(id)
                        .is_some_and(|n| matches!(n.ty, NodeType::Frame | NodeType::Component))
                })
            })
            .unwrap_or_else(|| page.to_string())
    }

    /// Snap candidates for nodes placed in `parent`: its other children and itself.
    pub(crate) fn cands(&self, parent: &str, skip: &[String]) -> Vec<Rect> {
        let mut c: Vec<Rect> = self
            .kids(parent)
            .iter()
            .filter(|k| !skip.contains(k))
            .filter_map(|k| self.rect(k))
            .collect();
        if Some(parent) != self.page_id().as_deref() {
            c.extend(self.rect(parent));
        }
        c
    }

    /// Put node `i` of the gesture under `target` at `order` (a copy: its `add` ops; else a `move`), then `x`/`y`.
    fn place(
        &self,
        e: &Edit,
        i: usize,
        target: &str,
        order: String,
        xy: Option<(f32, f32)>,
    ) -> Vec<Op> {
        let id = &e.ids[i];
        let mut out = match e.copies.get(i) {
            Some(c) => {
                let mut c = c.clone();
                if let Some(Op::Add {
                    parent,
                    order: o,
                    props,
                    ..
                }) = c.first_mut()
                {
                    *parent = Some(target.to_string());
                    *o = order;
                    if let Some((x, y)) = xy {
                        props.insert("x".into(), json!(x));
                        props.insert("y".into(), json!(y));
                    }
                }
                return c;
            }
            None if self.parent_of(id).as_deref() == Some(target) && xy.is_some() => vec![],
            None => vec![Op::Move {
                id: id.clone(),
                parent: Some(target.to_string()),
                order,
            }],
        };
        if let Some((x, y)) = xy {
            out.push(set(id, "x", json!(x)));
            out.push(set(id, "y", json!(y)));
        }
        out
    }

    pub(crate) fn move_ops(&self, e: &Edit, p: (f32, f32), mods: u32) -> (Vec<Op>, Guides) {
        let Some(page) = self.page_id() else {
            return (vec![], vec![]);
        };
        let d = ((p.0 - e.start.0).round(), (p.1 - e.start.1).round());
        let target = self.drop_target(p, &e.ids, &page);
        let siblings: Vec<String> = self
            .kids(&target)
            .into_iter()
            .filter(|k| !e.ids.contains(k))
            .collect();
        let mut ops = vec![];
        if self.is_flow(&target) {
            let rects: Vec<Rect> = siblings.iter().filter_map(|k| self.rect(k)).collect();
            let row = self
                .model
                .as_ref()
                .and_then(|m| m.nodes.get(&target))
                .and_then(|n| {
                    n.props
                        .get("layout")?
                        .get("dir")?
                        .as_str()
                        .map(str::to_string)
                })
                .is_none_or(|d| d != "column");
            let at = insert_index(&rects, row, p);
            let mut lo = at.checked_sub(1).and_then(|i| self.order_of(&siblings[i]));
            let hi = siblings.get(at).and_then(|s| self.order_of(s));
            for i in 0..e.ids.len() {
                let Some(o) = between(lo.as_deref(), hi.as_deref()) else {
                    return (vec![], vec![]);
                };
                lo = Some(o.clone());
                ops.extend(self.place(e, i, &target, o, None));
            }
            return (ops, vec![]);
        }
        let Some(b) = union(e.rects.iter().copied()) else {
            return (vec![], vec![]);
        };
        let b = b.with_offset(d);
        let (sx, sy, guides) = if mods & DE_MOD_COMMAND == 0 {
            snap_move(b, &self.cands(&target, &e.ids), SNAP_PT / self.camera.zoom)
        } else {
            (0.0, 0.0, vec![])
        };
        let o = self.origin(&target);
        let mut lo = siblings.last().and_then(|s| self.order_of(s));
        for (i, r) in e.rects.iter().enumerate() {
            let xy = (
                round2(r.left + d.0 + sx - o.0),
                round2(r.top + d.1 + sy - o.1),
            );
            let Some(ord) = between(lo.as_deref(), None) else {
                return (vec![], vec![]);
            };
            lo = Some(ord.clone());
            ops.extend(self.place(e, i, &target, ord, Some(xy)));
        }
        (ops, guides)
    }

    pub(crate) fn resize_ops(
        &self,
        e: &Edit,
        h: u8,
        p: (f32, f32),
        mods: u32,
    ) -> (Vec<Op>, Guides) {
        if let [(_, rot)] = e.frames[..]
            && rot != 0.0
        {
            let mut ops = self.resize_turned(e, h, p, mods);
            ops.extend(self.fix_sizing(&e.ids[0], h));
            return (ops, vec![]);
        }
        let Some(b0) = union(e.rects.iter().copied()) else {
            return (vec![], vec![]);
        };
        let d = ((p.0 - e.start.0).round(), (p.1 - e.start.1).round());
        let aspect = mods & DE_MOD_SHIFT != 0;
        let mut b = resize(b0, h, d, aspect);
        let mut guides = vec![];
        let parent = self.parent_of(&e.ids[0]).unwrap_or_default();
        if !aspect && mods & DE_MOD_COMMAND == 0 {
            (b, guides) = snap_edges(
                b,
                h,
                &self.cands(&parent, &e.ids),
                SNAP_PT / self.camera.zoom,
            );
        }
        let mut ops = vec![];
        for (id, r0) in e.ids.iter().zip(&e.rects) {
            let n = map_rect(*r0, b0, b);
            ops.push(set(id, "w", json!(round2(n.width()))));
            ops.push(set(id, "h", json!(round2(n.height()))));
            ops.extend(self.fix_sizing(id, h));
            let par = self.parent_of(id).unwrap_or_default();
            if !self.is_flow(&par) {
                let o = self.origin(&par);
                ops.push(set(id, "x", json!(round2(n.left - o.0))));
                ops.push(set(id, "y", json!(round2(n.top - o.1))));
            }
        }
        (ops, guides)
    }

    /// A resized axis becomes `fixed` in a node that has `sizing`.
    fn fix_sizing(&self, id: &str, h: u8) -> Option<Op> {
        let (l, t, r, bt) = edges(h);
        let mut s = self
            .model
            .as_ref()
            .and_then(|m| m.nodes.get(id))
            .and_then(|n| n.props.get("sizing")?.as_object().cloned())?;
        if l || r {
            s.insert("w".into(), json!("fixed"));
        }
        if t || bt {
            s.insert("h".into(), json!("fixed"));
        }
        Some(set(id, "sizing", Value::Object(s)))
    }

    /// ⌘D: copy each selected subtree right after its original (a top-level copy sits to the right of it) and
    /// select the copies.
    pub(crate) fn duplicate(&mut self) -> Result<(), i32> {
        self.refresh();
        let page = self.page_id();
        let (mut ops, mut roots, mut dups) = (vec![], vec![], HashMap::new());
        for s in self.top_selected() {
            let (Some(p), Some(o)) = (self.parent_of(&s), self.order_of(&s)) else {
                continue;
            };
            let kids = self.kids(&p);
            let next = kids
                .iter()
                .position(|k| *k == s)
                .and_then(|i| kids.get(i + 1))
                .and_then(|k| self.order_of(k));
            let Some(ord) = between(Some(&o), next.as_deref()) else {
                continue;
            };
            let mut c = self.copy_ops(&s, &p, &ord, &mut dups);
            if Some(&p) == page.as_ref()
                && let (Some(r), Some(Op::Add { props, .. })) = (self.rect(&s), c.first_mut())
            {
                props.insert("x".into(), json!(round2(r.right + DUP_GAP)));
                props.insert("y".into(), json!(round2(r.top)));
            }
            roots.extend(c.first().and_then(op_id));
            ops.extend(c);
        }
        self.commit(&ops, &dups)?;
        if !roots.is_empty() {
            self.selection = roots;
        }
        Ok(())
    }

    /// Arrow keys: 1 pt (10 with shift) in a free parent; one place earlier/later in an auto-layout parent.
    pub(crate) fn nudge(&mut self, dx: f32, dy: f32) -> Result<(), i32> {
        self.refresh();
        let mut ops = vec![];
        for id in self.top_selected() {
            let Some(par) = self.parent_of(&id).filter(|_| !self.locked(&id)) else {
                continue;
            };
            if self.is_flow(&par) {
                let kids = self.kids(&par);
                let Some(i) = kids.iter().position(|k| *k == id) else {
                    continue;
                };
                let (lo, hi) = if dx + dy < 0.0 {
                    let Some(j) = i.checked_sub(1) else { continue };
                    (j.checked_sub(1).map(|k| &kids[k]), kids.get(j))
                } else {
                    (kids.get(i + 1), kids.get(i + 2))
                };
                let (lo, hi) = (
                    lo.and_then(|k| self.order_of(k)),
                    hi.and_then(|k| self.order_of(k)),
                );
                if hi.is_none() && lo.is_none() {
                    continue;
                }
                if let Some(o) = between(lo.as_deref(), hi.as_deref()) {
                    ops.push(Op::Move {
                        id,
                        parent: Some(par),
                        order: o,
                    });
                }
                continue;
            }
            let (Some(r), o) = (self.rect(&id), self.origin(&par)) else {
                continue;
            };
            if dx != 0.0 {
                ops.push(set(&id, "x", json!(round2(r.left - o.0 + dx))));
            }
            if dy != 0.0 {
                ops.push(set(&id, "y", json!(round2(r.top - o.1 + dy))));
            }
        }
        self.commit(&ops, &HashMap::new())
    }
}

fn op_id(op: &Op) -> Option<String> {
    match op {
        Op::Add { id, .. } => Some(id.clone()),
        _ => None,
    }
}
