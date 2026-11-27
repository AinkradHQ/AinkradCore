//! Hit testing: the deepest visible node under a point.

use skia_safe::{Contains, Point};

use design_model::NodeType;

use crate::layout::LNode;
use crate::scene::Renderer;

/// World points a vector's hit box grows by on every side.
const VECTOR_PAD: f32 = 3.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// the deepest node under the point
    pub id: String,
    /// the top-level node (artboard) it is in
    pub artboard: String,
    /// artboard root ... id
    pub path: Vec<String>,
}

pub(crate) fn hit_node(
    nodes: &[LNode],
    i: usize,
    x: f32,
    y: f32,
    path: &mut Vec<String>,
    skip: &dyn Fn(&str) -> bool,
) -> Option<()> {
    let n = &nodes[i];
    if !n.look.visible || skip(&n.id) {
        return None;
    }
    // a rotated node is hit in its own unrotated box: the point goes back through the rotation
    let at = if n.mat.is_identity() {
        Point::new(x, y)
    } else {
        n.mat.invert()?.map_point((x, y))
    };
    // a line has no area: a few points of slack keep a flat vector clickable
    let inside = if n.ty == NodeType::Vector {
        n.rect.with_outset((VECTOR_PAD, VECTOR_PAD))
    } else {
        n.rect
    }
    .contains(at);
    if n.look.clip && !inside {
        return None;
    }
    path.push(n.id.clone());
    for k in n.kids.iter().rev() {
        if hit_node(nodes, *k as usize, x, y, path, skip).is_some() {
            return Some(());
        }
    }
    if inside {
        return Some(());
    }
    path.pop();
    None
}

impl Renderer {
    /// The deepest, topmost visible node under a screen point (points). Hidden nodes and anything outside a clipping
    /// frame are not hit.
    pub fn hit(&self, sx: f32, sy: f32) -> Option<Hit> {
        self.hit_skip(sx, sy, &|_| false)
    }

    /// As `hit`, looking through the nodes `skip` names (locked ones, for the canvas).
    pub fn hit_skip(&self, sx: f32, sy: f32, skip: &dyn Fn(&str) -> bool) -> Option<Hit> {
        let (x, y) = self.camera.to_world(sx, sy);
        self.hit_world_skip(x, y, skip)
    }

    pub fn hit_world(&self, x: f32, y: f32) -> Option<Hit> {
        self.hit_world_skip(x, y, &|_| false)
    }

    /// As `hit_world`, but nodes for which `skip` is true are not there (nor their subtrees): a drag looks through the
    /// nodes it carries to find the container under them.
    pub fn hit_world_skip(&self, x: f32, y: f32, skip: &dyn Fn(&str) -> bool) -> Option<Hit> {
        for b in self.boards.iter().rev() {
            let (lx, ly) = (x - b.origin.x, y - b.origin.y);
            if !b
                .laid
                .bounds
                .with_outset((VECTOR_PAD, VECTOR_PAD))
                .contains(Point::new(lx, ly))
            {
                continue;
            }
            let mut path = vec![];
            if hit_node(&b.laid.nodes, 0, lx, ly, &mut path, skip).is_some() {
                return Some(Hit {
                    id: path.last().cloned().unwrap_or_default(),
                    artboard: b.id.clone(),
                    path,
                });
            }
        }
        None
    }
}
