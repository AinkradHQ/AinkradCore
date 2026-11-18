//! Canvas interaction (V2-03): pointer gestures, hover, the overlay, rubber-band camera bounds.
//!
//! A pointer-down records a press; past `DRAG_PT` it becomes a marquee, a move or a resize. A move or resize turns
//! every pointer event into typed edit ops (`edits.rs`), previewed on the resolved boards they touch (`preview.rs`),
//! and written to the document as one batch (one undo step) on pointer-up. Escape cancels; nothing is written.
//!
//! Selection rules: a click selects the deepest node under the pointer (an instance's insides select the instance);
//! shift toggles. A top-level frame with children is selected by clicking its background, and dragging on that
//! background starts a marquee inside it (unless it is already selected, then the drag moves it), as in Figma.
//! A marquee selects the nodes of its scope (the page, or that frame) it touches.

use std::collections::{HashMap, HashSet};

use design_doc::Op;
use design_model::{NodeType, ResolvedNode};
use design_render::Overlay;
use design_render::Rect;
use design_render::camera::{band, unband};

use crate::ffi::*;
use crate::host::{Host, MAX_COORD, finite};
use crate::preview;
use crate::snap::handle_at;

/// Screen points a press travels before it is a drag.
const DRAG_PT: f32 = 3.0;
/// Rubber-band settle speed (1/s): about 250 ms to rest.
const SETTLE: f32 = 14.0;

pub(crate) enum Press {
    /// a node, in the selection from the press on; `toggle` = shift-press on a selected node (a click drops it)
    Node {
        id: String,
        toggle: bool,
    },
    /// the background of a top-level frame with children
    Board(String),
    Empty,
    Handle(u8),
}

pub(crate) struct Edit {
    /// `None` = move, `Some(h)` = resize from handle `h`
    pub handle: Option<u8>,
    /// the nodes being edited (the copies on an alt-drag)
    pub ids: Vec<String>,
    /// their world rects when the drag started (of the originals)
    pub rects: Vec<Rect>,
    /// world pointer when the drag started
    pub start: (f32, f32),
    /// alt-drag: per copy, its `add` ops (root first)
    pub copies: Vec<Vec<Op>>,
    /// copy id -> source id
    pub dups: HashMap<String, String>,
    pub ops: Vec<Op>,
    pub guides: Vec<[f32; 4]>,
}

pub(crate) enum Gesture {
    Press {
        at: (f32, f32),
        mods: u32,
        kind: Press,
    },
    Marquee {
        scope: Option<String>,
        from: (f32, f32),
        to: (f32, f32),
        base: Vec<String>,
    },
    Edit(Edit),
}

pub(crate) fn union(rs: impl IntoIterator<Item = Rect>) -> Option<Rect> {
    rs.into_iter().reduce(|a, b| {
        Rect::new(
            a.left.min(b.left),
            a.top.min(b.top),
            a.right.max(b.right),
            a.bottom.max(b.bottom),
        )
    })
}

fn cursor_of(h: u8) -> i32 {
    match h {
        0 | 4 => DE_CURSOR_RESIZE_NWSE,
        2 | 6 => DE_CURSOR_RESIZE_NESW,
        1 | 5 => DE_CURSOR_RESIZE_NS,
        _ => DE_CURSOR_RESIZE_EW,
    }
}

impl Host {
    // ---- lookups (valid after `refresh`) -----------------------------------------------------------------------

    pub(crate) fn rect(&self, id: &str) -> Option<Rect> {
        self.renderer.as_ref()?.node_rect(id)
    }

    /// The deepest document node under screen point (x, y).
    pub(crate) fn hit_doc(&self, x: f32, y: f32) -> Option<String> {
        let h = self.renderer.as_ref()?.hit(x, y)?;
        let m = self.model.as_ref()?;
        h.path.into_iter().rev().find(|id| m.nodes.contains_key(id))
    }

    pub(crate) fn page_id(&self) -> Option<String> {
        self.tree.as_ref()?.pages.get(self.page).cloned()
    }

    pub(crate) fn kids(&self, id: &str) -> Vec<String> {
        self.tree
            .as_ref()
            .and_then(|t| t.children.get(id))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn parent_of(&self, id: &str) -> Option<String> {
        self.tree.as_ref()?.parent.get(id).cloned()
    }

    /// Selected nodes that are not inside another selected node.
    pub(crate) fn top_selected(&self) -> Vec<String> {
        self.selection
            .iter()
            .filter(|id| !self.in_selection(id))
            .cloned()
            .collect()
    }

    /// Whether an ancestor of `id` is selected.
    fn in_selection(&self, id: &str) -> bool {
        let mut cur = self.parent_of(id);
        for _ in 0..crate::host::MAX_DEPTH_WALK {
            match cur {
                Some(p) if self.selection.contains(&p) => return true,
                Some(p) => cur = self.parent_of(&p),
                None => break,
            }
        }
        false
    }

    fn sel_bounds_screen(&self) -> Option<Rect> {
        let b = union(self.selection.iter().filter_map(|id| self.rect(id)))?;
        let c = self.camera;
        let (l, t) = c.to_screen(b.left, b.top);
        let (r, bt) = c.to_screen(b.right, b.bottom);
        Some(Rect::new(l, t, r, bt))
    }

    // ---- pointer ------------------------------------------------------------------------------------------------

    pub fn pointer(&mut self, phase: u32, x: f32, y: f32, mods: u32) -> Result<(), i32> {
        finite(&[x, y], MAX_COORD)?;
        if phase > DE_POINTER_UP {
            return Err(DE_ERR_ARG);
        }
        self.refresh();
        if let Some(r) = self.text_pointer(phase, x, y, mods) {
            self.refresh();
            return r;
        }
        match phase {
            DE_POINTER_DOWN => self.down(x, y, mods),
            DE_POINTER_MOVE => self.drag(x, y, mods),
            _ => {
                let r = self.up();
                self.refresh();
                return r;
            }
        }
        self.refresh();
        Ok(())
    }

    fn down(&mut self, x: f32, y: f32, mods: u32) {
        self.cancel();
        let shift = mods & DE_MOD_SHIFT != 0;
        if let Some(h) = self.sel_bounds_screen().and_then(|b| handle_at(b, x, y)) {
            self.gesture = Some(Gesture::Press {
                at: (x, y),
                mods,
                kind: Press::Handle(h),
            });
            return;
        }
        let kind = match self.hit_doc(x, y) {
            None => {
                if !shift {
                    self.selection.clear();
                }
                Press::Empty
            }
            Some(id) => {
                let selected = self.selection.contains(&id);
                let board_bg = self.parent_of(&id) == self.page_id() && !self.kids(&id).is_empty();
                // inside a selected node: a drag moves that selection, a click selects this one
                let covered = !selected && !shift && self.in_selection(&id);
                if board_bg && !selected {
                    Press::Board(id)
                } else {
                    if !selected && !covered {
                        if !shift {
                            self.selection.clear();
                        }
                        self.selection.push(id.clone());
                    }
                    Press::Node {
                        id,
                        toggle: shift && selected,
                    }
                }
            }
        };
        self.gesture = Some(Gesture::Press {
            at: (x, y),
            mods,
            kind,
        });
    }

    fn drag(&mut self, x: f32, y: f32, mods: u32) {
        let p = self.camera.to_world(x, y);
        match self.gesture.take() {
            None => {
                self.hover = self.hit_doc(x, y);
            }
            Some(Gesture::Press { at, mods: m0, kind }) => {
                if (x - at.0).hypot(y - at.1) < DRAG_PT {
                    self.gesture = Some(Gesture::Press { at, mods: m0, kind });
                    return;
                }
                let from = self.camera.to_world(at.0, at.1);
                let base = if m0 & DE_MOD_SHIFT != 0 {
                    self.selection.clone()
                } else {
                    vec![]
                };
                self.hover = None;
                self.gesture = match kind {
                    Press::Node { .. } => self.begin_edit(None, m0 & DE_MOD_OPTION != 0, from),
                    Press::Handle(h) => self.begin_edit(Some(h), false, from),
                    Press::Board(id) => Some(Gesture::Marquee {
                        scope: Some(id),
                        from,
                        to: from,
                        base,
                    }),
                    Press::Empty => Some(Gesture::Marquee {
                        scope: None,
                        from,
                        to: from,
                        base,
                    }),
                };
                self.drag_to(p, mods);
            }
            g => {
                self.gesture = g;
                self.drag_to(p, mods);
            }
        }
    }

    fn drag_to(&mut self, p: (f32, f32), mods: u32) {
        match self.gesture.take() {
            Some(Gesture::Marquee {
                scope, from, base, ..
            }) => {
                let m = Rect::new(
                    from.0.min(p.0),
                    from.1.min(p.1),
                    from.0.max(p.0),
                    from.1.max(p.1),
                );
                let scope_id = scope.clone().or_else(|| self.page_id()).unwrap_or_default();
                let mut sel = base.clone();
                for k in self.kids(&scope_id) {
                    if !sel.contains(&k) && self.rect(&k).is_some_and(|r| Rect::intersects(&r, m)) {
                        sel.push(k);
                    }
                }
                self.selection = sel;
                self.gesture = Some(Gesture::Marquee {
                    scope,
                    from,
                    to: p,
                    base,
                });
            }
            Some(Gesture::Edit(mut e)) => {
                let (ops, guides) = match e.handle {
                    None => self.move_ops(&e, p, mods),
                    Some(h) => self.resize_ops(&e, h, p, mods),
                };
                e.ops = ops;
                e.guides = guides;
                self.gesture = Some(Gesture::Edit(e));
                self.sync_preview();
            }
            g => self.gesture = g,
        }
    }

    /// Errors: the gesture's batch was refused or reset the replica (`DE_ERR_RESET`); nothing of it is written.
    fn up(&mut self) -> Result<(), i32> {
        match self.gesture.take() {
            Some(Gesture::Press {
                kind: Press::Board(id),
                mods,
                ..
            }) => match self.selection.iter().position(|s| *s == id) {
                Some(i) if mods & DE_MOD_SHIFT != 0 => {
                    self.selection.remove(i);
                }
                _ if mods & DE_MOD_SHIFT != 0 => self.selection.push(id),
                _ => self.selection = vec![id],
            },
            // a click (no drag) on a selected node: shift drops it, otherwise it becomes the whole selection
            Some(Gesture::Press {
                kind: Press::Node { id, toggle },
                mods,
                ..
            }) => {
                if toggle {
                    self.selection.retain(|s| *s != id);
                } else if mods & DE_MOD_SHIFT == 0 {
                    self.selection = vec![id];
                }
            }
            Some(Gesture::Edit(e)) => {
                if let Err(c) = self.commit(&e.ops, &e.dups) {
                    self.sync_preview();
                    return Err(c);
                }
                if e.ops.is_empty() {
                    self.sync_preview();
                } else if !e.dups.is_empty() {
                    self.selection = e.ids;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Drop a gesture in progress without writing anything. `true` when there was one.
    pub(crate) fn cancel(&mut self) -> bool {
        let had = self.gesture.take().is_some();
        self.sync_preview();
        had
    }

    pub fn cursor(&mut self, x: f32, y: f32) -> Result<i32, i32> {
        finite(&[x, y], MAX_COORD)?;
        self.refresh();
        if let Some(Gesture::Edit(Edit {
            handle: Some(h), ..
        })) = &self.gesture
        {
            return Ok(cursor_of(*h));
        }
        Ok(self
            .sel_bounds_screen()
            .and_then(|b| handle_at(b, x, y))
            .map_or(DE_CURSOR_DEFAULT, cursor_of))
    }

    // ---- preview + overlay --------------------------------------------------------------------------------------

    /// Show the current edit gesture's ops on the boards they touch, or put back the boards a previous preview
    /// changed when there is none.
    pub(crate) fn sync_preview(&mut self) {
        // no gesture: the IME's marked text, if any, is the preview (V2-04)
        let (none_ops, none_dups): (Vec<Op>, _) =
            (self.marked_preview().into_iter().collect(), HashMap::new());
        let (ops, dups) = match &self.gesture {
            Some(Gesture::Edit(e)) => (&e.ops, &e.dups),
            _ => (&none_ops, &none_dups),
        };
        if ops.is_empty() && self.previewed.is_empty() {
            return;
        }
        let (Some(res), Some(m), Some(r)) = (
            self.resolved.as_ref(),
            self.model.as_ref(),
            self.renderer.as_mut(),
        ) else {
            return;
        };
        let Some(base) = res.pages.get(self.page) else {
            return;
        };
        let p = preview::patch(base, m, ops, dups);
        let mut changed: HashSet<String> = p.boards.keys().cloned().collect();
        changed.extend(self.previewed.drain());
        let index: HashMap<&str, &ResolvedNode> =
            base.children.iter().map(|c| (c.id.as_str(), c)).collect();
        let roots: Vec<&ResolvedNode> = p
            .order
            .iter()
            .filter_map(|id| p.boards.get(id).or_else(|| index.get(id.as_str()).copied()))
            .collect();
        r.load_patch(&roots, &changed);
        self.previewed = p.boards.into_keys().collect();
    }

    pub(crate) fn overlay(&self) -> Overlay {
        let mut o = Overlay::default();
        let ids = match &self.gesture {
            Some(Gesture::Edit(e)) => {
                o.guides = e.guides.clone();
                &e.ids
            }
            _ => &self.selection,
        };
        o.selected = ids.iter().filter_map(|id| self.rect(id)).collect();
        o.bounds = union(o.selected.iter().copied());
        if let Some(Gesture::Marquee { from, to, .. }) = &self.gesture {
            o.marquee = Some(Rect::new(
                from.0.min(to.0),
                from.1.min(to.1),
                from.0.max(to.0),
                from.1.max(to.1),
            ));
        }
        o.hover = self
            .hover
            .as_ref()
            .filter(|h| self.gesture.is_none() && !self.selection.contains(h))
            .and_then(|h| self.rect(h));
        self.text_overlay(&mut o);
        o
    }

    pub(crate) fn is_flow(&self, id: &str) -> bool {
        self.model
            .as_ref()
            .and_then(|m| m.nodes.get(id))
            .is_some_and(|n| {
                n.ty != NodeType::Page && n.props.get("layout").is_some_and(|l| l.is_object())
            })
    }

    // ---- camera bounds ------------------------------------------------------------------------------------------

    fn ranges(&mut self) -> Option<[(f32, f32); 2]> {
        self.refresh();
        let c = self.renderer.as_ref()?.world_bounds()?;
        Some(self.camera.pan_range(c))
    }

    /// Pan by a scroll delta; past the content bounds the pan is rubber-banded.
    pub fn scroll(&mut self, dx: f32, dy: f32) -> Result<(), i32> {
        finite(&[dx, dy], MAX_COORD)?;
        self.settle = None;
        let (pan, (w, h)) = (self.camera.pan, self.camera.view);
        let p = match self.ranges() {
            Some([rx, ry]) => (
                band(unband(pan.0, rx, w) + dx, rx, w),
                band(unband(pan.1, ry, h) + dy, ry, h),
            ),
            None => (pan.0 + dx, pan.1 + dy),
        };
        finite(&[p.0, p.1], MAX_COORD)?;
        self.camera.pan = p;
        Ok(())
    }

    /// A scroll or pinch ended: settle back inside the bounds, at once with Reduce Motion.
    pub fn gesture_end(&mut self, reduce_motion: bool) {
        let Some([rx, ry]) = self.ranges() else {
            return;
        };
        let p = self.camera.pan;
        // not `clamp`: it panics on lo > hi or a NaN bound
        let t = (p.0.max(rx.0).min(rx.1), p.1.max(ry.0).min(ry.1));
        if t == p {
            self.settle = None;
        } else if reduce_motion {
            self.camera.pan = t;
            self.settle = None;
        } else {
            self.settle = Some(t);
        }
    }

    /// Advance the settle by `dt` seconds. 1 while still moving.
    pub fn tick(&mut self, dt: f32) -> Result<bool, i32> {
        if !(dt.is_finite() && (0.0..=1.0).contains(&dt)) {
            return Err(DE_ERR_ARG);
        }
        let Some(t) = self.settle else {
            return Ok(false);
        };
        let k = 1.0 - (-dt * SETTLE).exp();
        let p = self.camera.pan;
        let n = (p.0 + (t.0 - p.0) * k, p.1 + (t.1 - p.1) * k);
        if (t.0 - n.0).abs() < 0.25 && (t.1 - n.1).abs() < 0.25 {
            self.camera.pan = t;
            self.settle = None;
        } else {
            self.camera.pan = n;
        }
        Ok(self.settle.is_some())
    }
}
