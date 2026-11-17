//! Hit testing: the deepest visible node under a point.

use skia_safe::{Contains, Point};

use crate::layout::LNode;

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
    let inside = n.rect.contains(Point::new(x, y));
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
