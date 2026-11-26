//! Canvas geometry (V2-03), pure: snapping with guides, resize from a handle, handle hit testing, auto-layout
//! insertion. World coordinates unless a name says screen.

use design_render::Rect;

/// Snap distance in screen points (divided by the zoom for world units).
pub(crate) const SNAP_PT: f32 = 6.0;
/// Handle grab distance in screen points.
pub(crate) const GRAB_PT: f32 = 6.0;
/// Smallest size a resize leaves.
pub(crate) const MIN_SIZE: f32 = 1.0;

pub type Guide = [f32; 4];

fn xs(r: &Rect) -> [f32; 3] {
    [r.left, r.center_x(), r.right]
}

fn ys(r: &Rect) -> [f32; 3] {
    [r.top, r.center_y(), r.bottom]
}

/// Smallest correction within `tol` that puts one of `edges` on one of the `lines`.
fn best(edges: &[f32], lines: impl Iterator<Item = f32> + Clone, tol: f32) -> f32 {
    let mut out: Option<f32> = None;
    for e in edges {
        for l in lines.clone() {
            let d = l - e;
            if d.abs() <= tol && out.is_none_or(|o| d.abs() < o.abs()) {
                out = Some(d);
            }
        }
    }
    out.unwrap_or(0.0)
}

/// Guides for `b` against `cands`: one vertical segment per candidate x line that `b` touches (left, centre or right),
/// one horizontal per y line, spanning both boxes.
pub fn guides(b: Rect, cands: &[Rect]) -> Vec<Guide> {
    let on = |a: f32, b: f32| (a - b).abs() < 0.01;
    let mut out = vec![];
    for c in cands {
        for x in xs(c) {
            if xs(&b).iter().any(|e| on(*e, x)) {
                out.push([x, b.top.min(c.top), x, b.bottom.max(c.bottom)]);
            }
        }
        for y in ys(c) {
            if ys(&b).iter().any(|e| on(*e, y)) {
                out.push([b.left.min(c.left), y, b.right.max(c.right), y]);
            }
        }
    }
    out
}

/// Snap one point to the candidates' lines (each axis within `tol`).
pub fn snap_point(p: (f32, f32), cands: &[Rect], tol: f32) -> (f32, f32) {
    (
        p.0 + best(&[p.0], cands.iter().flat_map(xs), tol),
        p.1 + best(&[p.1], cands.iter().flat_map(ys), tol),
    )
}

/// Snap a moving box: the correction `(dx, dy)` (each within `tol`) that lines one of its edges or its centre up with
/// a candidate's, and the guides that then show.
pub fn snap_move(b: Rect, cands: &[Rect], tol: f32) -> (f32, f32, Vec<Guide>) {
    let dx = best(&xs(&b), cands.iter().flat_map(xs), tol);
    let dy = best(&ys(&b), cands.iter().flat_map(ys), tol);
    let moved = b.with_offset((dx, dy));
    (dx, dy, guides(moved, cands))
}

/// Which edges a handle moves: (left, top, right, bottom). Handles: 0 nw, 1 n, 2 ne, 3 e, 4 se, 5 s, 6 sw, 7 w.
pub fn edges(handle: u8) -> (bool, bool, bool, bool) {
    (
        matches!(handle, 0 | 6 | 7),
        matches!(handle, 0..=2),
        matches!(handle, 2..=4),
        matches!(handle, 4..=6),
    )
}

/// `b` resized by dragging `handle` by `d`. Edges never cross (`MIN_SIZE`); `keep_aspect` (shift, corner handles)
/// scales both sides by the larger change, anchored at the opposite corner.
pub fn resize(b: Rect, handle: u8, d: (f32, f32), keep_aspect: bool) -> Rect {
    let (l, t, r, bt) = edges(handle);
    let mut n = b;
    if l {
        n.left = (b.left + d.0).min(b.right - MIN_SIZE);
    }
    if r {
        n.right = (b.right + d.0).max(b.left + MIN_SIZE);
    }
    if t {
        n.top = (b.top + d.1).min(b.bottom - MIN_SIZE);
    }
    if bt {
        n.bottom = (b.bottom + d.1).max(b.top + MIN_SIZE);
    }
    let corner = (l || r) && (t || bt);
    if keep_aspect && corner && b.width() > 0.0 && b.height() > 0.0 {
        let s = (n.width() / b.width()).max(n.height() / b.height());
        let (w, h) = (b.width() * s, b.height() * s);
        if l {
            n.left = n.right - w;
        } else {
            n.right = n.left + w;
        }
        if t {
            n.top = n.bottom - h;
        } else {
            n.bottom = n.top + h;
        }
    }
    n
}

/// Snap the edges a handle moves to the candidates' lines (each within `tol`), keeping `MIN_SIZE`.
pub fn snap_edges(b: Rect, handle: u8, cands: &[Rect], tol: f32) -> (Rect, Vec<Guide>) {
    let (l, t, r, bt) = edges(handle);
    let lines_x = || cands.iter().flat_map(xs);
    let lines_y = || cands.iter().flat_map(ys);
    let mut n = b;
    if l {
        n.left = (n.left + best(&[n.left], lines_x(), tol)).min(n.right - MIN_SIZE);
    }
    if r {
        n.right = (n.right + best(&[n.right], lines_x(), tol)).max(n.left + MIN_SIZE);
    }
    if t {
        n.top = (n.top + best(&[n.top], lines_y(), tol)).min(n.bottom - MIN_SIZE);
    }
    if bt {
        n.bottom = (n.bottom + best(&[n.bottom], lines_y(), tol)).max(n.top + MIN_SIZE);
    }
    (n, guides(n, cands))
}

/// `r` mapped from the box `from` to the box `to` (a multi-selection resize scales every member).
pub fn map_rect(r: Rect, from: Rect, to: Rect) -> Rect {
    let sx = if from.width() > 0.0 {
        to.width() / from.width()
    } else {
        1.0
    };
    let sy = if from.height() > 0.0 {
        to.height() / from.height()
    } else {
        1.0
    };
    Rect::new(
        to.left + (r.left - from.left) * sx,
        to.top + (r.top - from.top) * sy,
        to.left + (r.right - from.left) * sx,
        to.top + (r.bottom - from.top) * sy,
    )
}

/// The handle of screen box `b` within `GRAB_PT` of screen point (x, y); corners win over edges.
pub fn handle_at(b: Rect, x: f32, y: f32) -> Option<u8> {
    let hs = design_render::overlay::handles(b);
    [0u8, 2, 4, 6, 1, 3, 5, 7].into_iter().find(|i| {
        let (hx, hy) = hs[*i as usize];
        (hx - x).abs() <= GRAB_PT && (hy - y).abs() <= GRAB_PT
    })
}

/// Screen points outside a corner that rotate instead of resize.
pub(crate) const ROTATE_PT: f32 = 18.0;

/// `p` turned `deg` (clockwise on screen, y down) about `c`.
pub fn turn(p: (f32, f32), c: (f32, f32), deg: f32) -> (f32, f32) {
    let (s, k) = deg.to_radians().sin_cos();
    let (dx, dy) = (p.0 - c.0, p.1 - c.1);
    (c.0 + dx * k - dy * s, c.1 + dx * s + dy * k)
}

/// Point (x, y) in the frame of box `b` drawn turned `rot` degrees about its centre.
fn unturn(b: Rect, rot: f32, x: f32, y: f32) -> (f32, f32) {
    turn((x, y), (b.center_x(), b.center_y()), -rot)
}

/// `handle_at` on a box drawn turned `rot` degrees about its centre.
pub fn handle_at_turned(b: Rect, rot: f32, x: f32, y: f32) -> Option<u8> {
    let (x, y) = unturn(b, rot, x, y);
    handle_at(b, x, y)
}

/// The corner (0 nw, 2 ne, 4 se, 6 sw) whose rotate zone holds screen point (x, y): just outside the box, within
/// `ROTATE_PT` of the corner (a handle under the point wins; check `handle_at_turned` first).
pub fn rotate_at(b: Rect, rot: f32, x: f32, y: f32) -> Option<u8> {
    let (x, y) = unturn(b, rot, x, y);
    if (b.left..=b.right).contains(&x) && (b.top..=b.bottom).contains(&y) {
        return None;
    }
    let hs = design_render::overlay::handles(b);
    [0u8, 2, 4, 6].into_iter().find(|i| {
        let (hx, hy) = hs[*i as usize];
        (hx - x).hypot(hy - y) <= ROTATE_PT
    })
}

/// Degrees into (-180, 180].
pub fn norm_deg(d: f32) -> f32 {
    let r = d.rem_euclid(360.0);
    if r > 180.0 { r - 360.0 } else { r }
}

/// Where a dragged node lands among auto-layout siblings `kids` (their rects, in order): the number of siblings
/// whose centre on the main axis is before the pointer.
// ponytail: main axis only; a wrapping layout inserts by the main-axis centre too (row-aware when wrap matters).
pub fn insert_index(kids: &[Rect], row: bool, p: (f32, f32)) -> usize {
    kids.iter()
        .filter(|k| {
            if row {
                k.center_x() < p.0
            } else {
                k.center_y() < p.1
            }
        })
        .count()
}

/// Round to 1/100 pt: the values written to the document stay free of float noise.
pub fn round2(v: f32) -> f32 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(x: f32, y: f32, w: f32, h: f32) -> Rect {
        Rect::from_xywh(x, y, w, h)
    }

    #[test]
    fn turned_handles_and_rotate_zones() {
        let b = r(100.0, 100.0, 200.0, 100.0);
        // upright: the zone is outside the corner, the handle itself resizes
        assert_eq!(rotate_at(b, 0.0, 90.0, 90.0), Some(0));
        assert_eq!(rotate_at(b, 0.0, 110.0, 110.0), None);
        assert_eq!(rotate_at(b, 0.0, 200.0, 80.0), None);
        // turned 90 degrees: the nw corner (100,100) shows at (250,50) and its handle and zone go with it
        let nw = turn((100.0, 100.0), (200.0, 150.0), 90.0);
        assert!((nw.0 - 250.0).abs() < 0.01 && (nw.1 - 50.0).abs() < 0.01);
        assert_eq!(handle_at_turned(b, 90.0, 250.0, 50.0), Some(0));
        assert_eq!(rotate_at(b, 90.0, 262.0, 45.0), Some(0));
        assert_eq!(handle_at_turned(b, 90.0, 100.0, 100.0), None);
        assert_eq!(norm_deg(190.0), -170.0);
        assert_eq!(norm_deg(-180.0), 180.0);
        assert_eq!(norm_deg(360.0), 0.0);
    }

    #[test]
    fn move_snaps_the_nearest_edge_or_centre_and_shows_guides() {
        let sib = r(100.0, 0.0, 50.0, 50.0);
        // left edge 3 pt right of the sibling's right edge: snaps back by 3
        let (dx, dy, g) = snap_move(r(153.0, 200.0, 20.0, 20.0), &[sib], 6.0);
        assert_eq!((dx, dy), (-3.0, 0.0));
        assert_eq!(g, vec![[150.0, 0.0, 150.0, 220.0]]);
        // centre to centre beats a farther edge
        let (dx, _, _) = snap_move(r(114.0, 300.0, 20.0, 20.0), &[sib], 6.0);
        assert_eq!(dx, 1.0, "centre 124 -> 125");
        // out of tolerance: nothing
        let (dx, dy, g) = snap_move(r(170.0, 170.0, 10.0, 10.0), &[sib], 6.0);
        assert_eq!((dx, dy, g.len()), (0.0, 0.0, 0));
        // both axes at once
        let (dx, dy, g) = snap_move(r(98.0, 52.0, 10.0, 10.0), &[sib], 6.0);
        assert_eq!((dx, dy), (2.0, -2.0));
        assert_eq!(g.len(), 2);
    }

    #[test]
    fn resize_moves_only_the_handle_edges_and_never_inverts() {
        let b = r(0.0, 0.0, 100.0, 50.0);
        assert_eq!(resize(b, 4, (10.0, 5.0), false), r(0.0, 0.0, 110.0, 55.0));
        assert_eq!(resize(b, 0, (10.0, 5.0), false), r(10.0, 5.0, 90.0, 45.0));
        assert_eq!(
            resize(b, 1, (99.0, 7.0), false),
            r(0.0, 7.0, 100.0, 43.0),
            "n: y only"
        );
        assert_eq!(resize(b, 7, (500.0, 0.0), false).width(), MIN_SIZE);
        assert_eq!(resize(b, 3, (-500.0, 0.0), false).width(), MIN_SIZE);
        // shift on a corner keeps 2:1, anchored at the opposite corner
        let a = resize(b, 4, (100.0, 0.0), true);
        assert_eq!(a, r(0.0, 0.0, 200.0, 100.0));
        let a = resize(b, 0, (-100.0, 0.0), true);
        assert_eq!(
            (a.right, a.bottom, a.width(), a.height()),
            (100.0, 50.0, 200.0, 100.0)
        );
    }

    #[test]
    fn edge_snapping_and_rect_mapping() {
        let sib = r(200.0, 0.0, 50.0, 50.0);
        let (n, g) = snap_edges(r(0.0, 0.0, 197.0, 48.0), 4, &[sib], 6.0);
        assert_eq!(n, r(0.0, 0.0, 200.0, 50.0));
        assert_eq!(g.len(), 4, "right edge + top, centre and bottom lines");
        let (n, _) = snap_edges(r(0.0, 0.0, 197.0, 48.0), 7, &[sib], 6.0);
        assert_eq!(n, r(0.0, 0.0, 197.0, 48.0), "w moves the left edge only");
        let m = map_rect(
            r(50.0, 0.0, 50.0, 10.0),
            r(0.0, 0.0, 100.0, 10.0),
            r(0.0, 0.0, 200.0, 20.0),
        );
        assert_eq!(m, r(100.0, 0.0, 100.0, 20.0));
    }

    #[test]
    fn handles_are_found_corners_first() {
        let b = r(100.0, 100.0, 200.0, 100.0);
        assert_eq!(handle_at(b, 101.0, 99.0), Some(0));
        assert_eq!(handle_at(b, 200.0, 104.0), Some(1));
        assert_eq!(handle_at(b, 303.0, 201.0), Some(4));
        assert_eq!(handle_at(b, 99.0, 150.0), Some(7));
        assert_eq!(handle_at(b, 200.0, 150.0), None);
        // a tiny box: the corner wins over the overlapping edge handle
        assert_eq!(handle_at(r(0.0, 0.0, 4.0, 4.0), 0.0, 0.0), Some(0));
    }

    #[test]
    fn insertion_index_follows_the_main_axis() {
        let kids = [
            r(0.0, 0.0, 10.0, 10.0),
            r(20.0, 0.0, 10.0, 10.0),
            r(40.0, 0.0, 10.0, 10.0),
        ];
        assert_eq!(insert_index(&kids, true, (-5.0, 0.0)), 0);
        assert_eq!(insert_index(&kids, true, (26.0, 99.0)), 2);
        assert_eq!(insert_index(&kids, true, (99.0, 0.0)), 3);
        assert_eq!(insert_index(&kids, false, (99.0, 4.0)), 0);
        assert_eq!(round2(1.23456), 1.23);
    }
}
