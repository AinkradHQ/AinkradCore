//! The pen tool: each click adds a straight anchor, a rubber band shows the next segment, clicking the first anchor
//! (3+ anchors) closes the path, Enter / Escape or a second click on the last anchor ends an open one. One `vector`
//! node comes out, all coordinates whole points.

use design_doc::Op;
use design_model::NodeType;
use serde_json::{Map, json};

use crate::ffi::*;
use crate::host::Host;
use crate::tools::{bounds, path_data, solid, stroke};

/// Screen points within which a click lands on an anchor.
const ANCHOR_PT: f32 = 6.0;

pub(crate) struct Pen {
    pts: Vec<(f32, f32)>,
    rubber: Option<(f32, f32)>,
    parent: String,
    id: String,
}

impl Host {
    fn near(&self, a: (f32, f32), view: (f32, f32)) -> bool {
        let s = self.camera.to_screen(a.0, a.1);
        (s.0 - view.0).hypot(s.1 - view.1) <= ANCHOR_PT
    }

    pub(crate) fn pen_pointer(&mut self, phase: u32, x: f32, y: f32) -> Result<(), i32> {
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
