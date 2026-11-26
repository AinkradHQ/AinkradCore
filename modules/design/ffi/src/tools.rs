//! Drawing tools: the active tool (`de_set_tool`), and what the pointer does under each of them.
//!
//! Frame / rectangle / ellipse / line / text: a press picks the parent (the deepest frame or component under it, else
//! the page); a drag past `DRAG_PT` previews the new node (the gesture-preview path, nothing is written) and the
//! release writes one `add` op, selects the node and returns to the select tool. A click makes the default size.
//! Pen: each click adds a straight anchor, clicking the first anchor (3+ anchors) closes the path, Enter / Escape or a
//! second click on the last anchor ends an open one; one `vector` node comes out. Hand: a drag pans the camera.
//! Coordinates in the structs are world; the pointer arrives in view points and goes through the camera here.

use std::collections::HashMap;
use std::f32::consts::FRAC_PI_4;

use design_doc::Op;
use design_model::NodeType;
use design_model::ids::between;
use serde_json::{Map, Value, json};

use crate::ffi::*;
use crate::host::Host;
use crate::interact::{DRAG_PT, Edit, Gesture};
use crate::snap::{SNAP_PT, round2, snap_point};
use crate::text::Session;

/// Screen points within which a click lands on an anchor.
const ANCHOR_PT: f32 = 6.0;

pub(crate) struct Draw {
    tool: u32,
    from: (f32, f32),
    from_view: (f32, f32),
    to: Option<(f32, f32)>,
    shift: bool,
    parent: String,
    id: String,
}

pub(crate) struct Pen {
    pts: Vec<(f32, f32)>,
    rubber: Option<(f32, f32)>,
    parent: String,
    id: String,
}

#[derive(Default)]
pub(crate) struct Tools {
    pub tool: u32,
    draw: Option<Draw>,
    pen: Option<Pen>,
    /// last view point of a hand drag
    pan: Option<(f32, f32)>,
    /// a text node the text tool made: it goes again when editing ends with no text in it
    pub fresh_text: Option<String>,
}

impl Tools {
    pub fn pen_active(&self) -> bool {
        self.pen.is_some()
    }
    pub fn busy(&self) -> bool {
        self.draw.is_some() || self.pen.is_some()
    }
    pub fn clear(&mut self) -> bool {
        let had = self.busy();
        self.draw = None;
        self.pen = None;
        had
    }
    pub fn cursor(&self) -> Option<i32> {
        Some(match self.tool {
            DE_TOOL_SELECT => return None,
            DE_TOOL_HAND if self.pan.is_some() => DE_CURSOR_GRABBING,
            DE_TOOL_HAND => DE_CURSOR_GRAB,
            DE_TOOL_TEXT => DE_CURSOR_TEXT,
            _ => DE_CURSOR_CROSSHAIR,
        })
    }
}

/// A drawn shape in world coordinates; `line` holds a line's two ends.
struct Geo {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    line: Option<[(f32, f32); 2]>,
}

fn sign(v: f32) -> f32 {
    if v < 0.0 { -1.0 } else { 1.0 }
}

/// The shape for a drag from `from` to `to` (`None` = a click: the default size).
fn geometry(tool: u32, from: (f32, f32), to: Option<(f32, f32)>, shift: bool) -> Geo {
    // whole points: the box and the line's ends sit on integers (ponytail: no grid setting exists to snap to instead)
    let from = (from.0.round(), from.1.round());
    let (dx, dy) = to.map_or((0.0, 0.0), |t| (t.0.round() - from.0, t.1.round() - from.1));
    let (dx, dy) = match (tool, to) {
        (DE_TOOL_LINE, None) => (160.0, 0.0),
        (DE_TOOL_LINE, Some(_)) if shift => {
            let a = (dy.atan2(dx) / FRAC_PI_4).round() * FRAC_PI_4;
            let l = dx.hypot(dy);
            (l * a.cos(), l * a.sin())
        }
        (DE_TOOL_FRAME, None) => (400.0, 400.0),
        (DE_TOOL_RECT | DE_TOOL_ELLIPSE, None) => (100.0, 100.0),
        (DE_TOOL_FRAME | DE_TOOL_RECT | DE_TOOL_ELLIPSE, Some(_)) if shift => {
            let s = dx.abs().max(dy.abs());
            (s * sign(dx), s * sign(dy))
        }
        _ => (dx, dy),
    };
    let (dx, dy) = (dx.round(), dy.round());
    let (x, y) = (from.0.min(from.0 + dx), from.1.min(from.1 + dy));
    match tool {
        DE_TOOL_LINE => Geo {
            x,
            y,
            w: dx.abs(),
            h: dy.abs(),
            line: Some([from, (from.0 + dx, from.1 + dy)]),
        },
        // text: only the width is dragged, the height follows the text
        DE_TOOL_TEXT => Geo {
            x,
            y: from.1,
            w: dx.abs(),
            h: 0.0,
            line: None,
        },
        _ => Geo {
            x,
            y,
            w: dx.abs().max(1.0),
            h: dy.abs().max(1.0),
            line: None,
        },
    }
}

fn num(v: f32) -> String {
    // + 0.0: no "-0"
    format!("{}", round2(v) + 0.0)
}

/// Path data for `pts` relative to `(ox, oy)`.
fn path_data(pts: &[(f32, f32)], (ox, oy): (f32, f32), closed: bool) -> String {
    let mut s = String::new();
    for (i, p) in pts.iter().enumerate() {
        s += &format!(
            "{}{} {}",
            if i == 0 { "M" } else { " L" },
            num(p.0 - ox),
            num(p.1 - oy)
        );
    }
    if closed {
        s += " Z";
    }
    s
}

fn solid(c: &str) -> Value {
    json!([{"type": "solid", "color": c}])
}

fn stroke() -> Value {
    json!({"color": "#111111", "width": 2})
}

fn bounds(pts: &[(f32, f32)]) -> Geo {
    let f = |g: fn(f32, f32) -> f32, i: usize, s: f32| {
        pts.iter()
            .map(|p| if i == 0 { p.0 } else { p.1 })
            .fold(s, g)
    };
    let (l, t) = (f(f32::min, 0, f32::MAX), f(f32::min, 1, f32::MAX));
    let (r, b) = (f(f32::max, 0, f32::MIN), f(f32::max, 1, f32::MIN));
    Geo {
        x: l,
        y: t,
        w: r - l,
        h: b - t,
        line: None,
    }
}

impl Host {
    /// Pointer under a non-select tool; `None` when the select tool is active.
    pub(crate) fn tool_pointer(
        &mut self,
        phase: u32,
        x: f32,
        y: f32,
        mods: u32,
    ) -> Option<Result<(), i32>> {
        if self.tools.tool == DE_TOOL_SELECT {
            return None;
        }
        self.hover = None;
        Some(match self.tools.tool {
            DE_TOOL_HAND => self.hand_pointer(phase, x, y),
            DE_TOOL_PEN => self.pen_pointer(phase, x, y),
            _ => self.draw_pointer(phase, x, y, mods),
        })
    }

    pub fn set_tool(&mut self, tool: u32) -> Result<(), i32> {
        if tool > DE_TOOL_PEN {
            return Err(DE_ERR_ARG);
        }
        self.text_end()?;
        // switching away finishes a pen path in progress, as in Figma
        self.pen_finish(false)?;
        self.cancel();
        self.tools.pan = None;
        self.tools.tool = tool;
        Ok(())
    }

    fn world_of(&self, x: f32, y: f32) -> (f32, f32) {
        self.camera.to_world(x, y)
    }

    fn hand_pointer(&mut self, phase: u32, x: f32, y: f32) -> Result<(), i32> {
        match (phase, self.tools.pan) {
            (DE_POINTER_DOWN, _) => self.tools.pan = Some((x, y)),
            (DE_POINTER_MOVE, Some(p)) => {
                self.scroll(x - p.0, y - p.1)?;
                self.tools.pan = Some((x, y));
            }
            (DE_POINTER_UP, Some(_)) => {
                self.tools.pan = None;
                self.gesture_end(false);
            }
            _ => {}
        }
        Ok(())
    }

    // ---- frame, rectangle, ellipse, line, text ----------------------------------------------------------------------

    fn draw_pointer(&mut self, phase: u32, x: f32, y: f32, mods: u32) -> Result<(), i32> {
        let shift = mods & DE_MOD_SHIFT != 0;
        match phase {
            DE_POINTER_DOWN => {
                self.cancel();
                let from = self.world_of(x, y);
                let Some(page) = self.page_id() else {
                    return Ok(());
                };
                let parent = self.drop_target(from, &[], &page);
                let id = self.new_id();
                self.tools.draw = Some(Draw {
                    tool: self.tools.tool,
                    from,
                    from_view: (x, y),
                    to: None,
                    shift,
                    parent,
                    id,
                });
                Ok(())
            }
            DE_POINTER_MOVE => {
                self.draw_move(x, y, mods);
                Ok(())
            }
            _ => {
                self.draw_move(x, y, mods);
                self.draw_up()
            }
        }
    }

    /// Follow the pointer: past `DRAG_PT` the new node is previewed.
    fn draw_move(&mut self, x: f32, y: f32, mods: u32) {
        let Some(d) = self.tools.draw.as_ref() else {
            return;
        };
        let far = (x - d.from_view.0).hypot(y - d.from_view.1) >= DRAG_PT;
        if d.to.is_none() && !far {
            return;
        }
        let shift = mods & DE_MOD_SHIFT != 0;
        let mut to = self.world_of(x, y);
        // the end point snaps to the siblings' lines; a constrained shape (shift) and ⌘ do not
        if !shift && mods & DE_MOD_COMMAND == 0 && d.tool != DE_TOOL_TEXT {
            let c = self.cands(&d.parent, &[]);
            to = snap_point(to, &c, SNAP_PT / self.camera.zoom);
        }
        let Some(d) = self.tools.draw.as_mut() else {
            return;
        };
        d.to = Some(to);
        d.shift = shift;
        let op = self.draw_op();
        self.show(op.into_iter().collect());
    }

    /// The `add` op for the drawing in progress.
    fn draw_op(&mut self) -> Option<Op> {
        let d = self.tools.draw.as_ref()?;
        let (tool, id, parent) = (d.tool, d.id.clone(), d.parent.clone());
        let g = geometry(tool, d.from, d.to, d.shift);
        let mut props = Map::new();
        props.insert("w".into(), json!(g.w.round()));
        props.insert("h".into(), json!(g.h.round()));
        let ty = match tool {
            DE_TOOL_FRAME => {
                props.insert("fill".into(), solid("#FFFFFF"));
                props.insert("clip".into(), json!(true));
                (NodeType::Frame, "Frame")
            }
            DE_TOOL_RECT => {
                props.insert("fill".into(), solid("#D9D9D9"));
                props.insert("radius".into(), json!(0));
                (NodeType::Rect, "Rectangle")
            }
            DE_TOOL_ELLIPSE => {
                props.insert("fill".into(), solid("#D9D9D9"));
                (NodeType::Ellipse, "Ellipse")
            }
            DE_TOOL_LINE => {
                let ends = g.line?;
                props.insert("path".into(), json!(path_data(&ends, (g.x, g.y), false)));
                props.insert("stroke".into(), stroke());
                props.insert("fill".into(), json!([]));
                (NodeType::Vector, "Line")
            }
            _ => {
                // text: no height (it hugs the text), a width only when dragged
                props.remove("h");
                if g.w < 1.0 {
                    props.remove("w");
                }
                props.insert("type".into(), json!({"font": "system", "size": 16}));
                props.insert("fill".into(), solid("#111111"));
                (NodeType::Text, "Text")
            }
        };
        self.new_node(id, ty, &parent, (g.x, g.y), props)
    }

    /// An `add` op for a node whose top-left is world `at`, last among `parent`'s children.
    fn new_node(
        &self,
        id: String,
        (ty, name): (NodeType, &str),
        parent: &str,
        at: (f32, f32),
        mut props: Map<String, Value>,
    ) -> Option<Op> {
        // in an auto-layout parent the position is the layout's
        if !self.is_flow(parent) {
            let o = self.origin(parent);
            props.insert("x".into(), json!((at.0 - o.0).round()));
            props.insert("y".into(), json!((at.1 - o.1).round()));
        }
        let last = self.kids(parent).last().and_then(|k| self.order_of(k));
        Some(Op::Add {
            id,
            ty,
            parent: Some(parent.to_string()),
            order: between(last.as_deref(), None)?,
            name: name.to_string(),
            props,
            text: None,
        })
    }

    /// Show `ops` as the gesture preview (empty: nothing).
    fn show(&mut self, ops: Vec<Op>) {
        self.gesture = match ops.first() {
            Some(Op::Add { id, .. }) => Some(Gesture::Edit(Edit {
                handle: None,
                ids: vec![id.clone()],
                rects: vec![],
                start: (0.0, 0.0),
                copies: vec![],
                dups: HashMap::new(),
                ops,
                guides: vec![],
            })),
            _ => None,
        };
        self.sync_preview();
    }

    /// Write `op` as one undo step, select the node and go back to the select tool.
    fn finish_node(&mut self, op: Op) -> Result<(), i32> {
        let Op::Add { id, .. } = &op else {
            return Ok(());
        };
        let id = id.clone();
        self.gesture = None;
        if let Err(c) = self.commit(&[op], &HashMap::new()) {
            self.sync_preview();
            return Err(c);
        }
        self.selection = vec![id.clone()];
        self.tools.tool = DE_TOOL_SELECT;
        if self
            .model()
            .nodes
            .get(&id)
            .is_some_and(|n| n.ty == NodeType::Text)
        {
            // the text tool goes straight into editing
            self.refresh();
            self.text = Some(Session::new(id.clone(), String::new(), 0));
            self.tools.fresh_text = Some(id);
        }
        Ok(())
    }

    fn draw_up(&mut self) -> Result<(), i32> {
        // a click has no `to`: `draw_op` makes the default size
        let op = self.draw_op();
        self.tools.draw = None;
        match op {
            Some(op) => self.finish_node(op),
            None => Ok(()),
        }
    }

    // ---- pen --------------------------------------------------------------------------------------------------------

    fn near(&self, a: (f32, f32), view: (f32, f32)) -> bool {
        let s = self.camera.to_screen(a.0, a.1);
        (s.0 - view.0).hypot(s.1 - view.1) <= ANCHOR_PT
    }

    fn pen_pointer(&mut self, phase: u32, x: f32, y: f32) -> Result<(), i32> {
        let p = self.world_of(x, y);
        let p = (p.0.round(), p.1.round());
        match (phase, self.tools.pen.as_ref()) {
            (DE_POINTER_DOWN, None) => {
                let Some(page) = self.page_id() else {
                    return Ok(());
                };
                self.cancel();
                let parent = self.drop_target(p, &[], &page);
                let id = self.new_id();
                self.tools.pen = Some(Pen {
                    pts: vec![p],
                    rubber: None,
                    parent,
                    id,
                });
                Ok(())
            }
            (DE_POINTER_DOWN, Some(pen)) => {
                let (first, last, n) = (pen.pts[0], pen.pts[pen.pts.len() - 1], pen.pts.len());
                if n >= 3 && self.near(first, (x, y)) {
                    return self.pen_finish(true);
                }
                // a second click on the last anchor (a double-click) ends the path
                if self.near(last, (x, y)) {
                    return self.pen_finish(false);
                }
                if let Some(pen) = self.tools.pen.as_mut() {
                    pen.pts.push(p);
                    pen.rubber = Some(p);
                }
                self.pen_show();
                Ok(())
            }
            (DE_POINTER_MOVE, Some(_)) => {
                if let Some(pen) = self.tools.pen.as_mut() {
                    pen.rubber = Some(p);
                }
                self.pen_show();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The vector node for `pts` (open: stroke only; closed: filled too).
    fn pen_op(&self, pen: &Pen, closed: bool, with: Option<(f32, f32)>) -> Option<Op> {
        let mut pts = pen.pts.clone();
        pts.extend(with);
        let g = bounds(&pts);
        let mut props = Map::new();
        props.insert("w".into(), json!(g.w.round()));
        props.insert("h".into(), json!(g.h.round()));
        props.insert("path".into(), json!(path_data(&pts, (g.x, g.y), closed)));
        props.insert("stroke".into(), stroke());
        props.insert(
            "fill".into(),
            if closed { solid("#D9D9D9") } else { json!([]) },
        );
        self.new_node(
            pen.id.clone(),
            (NodeType::Vector, "Path"),
            &pen.parent,
            (g.x, g.y),
            props,
        )
    }

    /// Preview the path with the rubber band to the pointer.
    fn pen_show(&mut self) {
        let op = self.tools.pen.as_ref().and_then(|p| {
            let with = p.rubber.filter(|r| Some(r) != p.pts.last());
            (p.pts.len() + usize::from(with.is_some()) >= 2)
                .then(|| self.pen_op(p, false, with))
                .flatten()
        });
        self.show(op.into_iter().collect());
    }

    /// End the path: written when it has two anchors (three when closed), otherwise dropped. No pen path: nothing.
    pub(crate) fn pen_finish(&mut self, closed: bool) -> Result<(), i32> {
        let Some(pen) = self.tools.pen.take() else {
            return Ok(());
        };
        if pen.pts.len() < if closed { 3 } else { 2 } {
            self.gesture = None;
            self.sync_preview();
            return Ok(());
        }
        match self.pen_op(&pen, closed, None) {
            Some(op) => self.finish_node(op),
            None => Ok(()),
        }
    }
}
