//! Rotation (drawn, hit and bounded about the centre), inner shadows, layer and background blur, multiple strokes with
//! alignment and dashes: each checked on CPU pixels of a small board.

use common::*;
use design_model::Theme;
use design_render::{Rect, Renderer, cpu};
use serde_json::{Value, json};

mod common;

/// One 400 x 200 white board at the world origin holding `kids` (ids: page 1, board 2, kids 3...); wide enough to be
/// drawn at full detail (live blur) at zoom 1.
fn board(kids: Vec<Value>) -> Renderer {
    let doc = tree(page(vec![json!({"type": "frame", "props": {
        "x": 0, "y": 0, "w": 400, "h": 200, "fill": solid("#ffffff")}, "children": kids})]));
    load(&doc, Theme::Day).0
}

fn px(r: &mut Renderer, x: i32, y: i32) -> [u8; 4] {
    let png = cpu::export_png(r, Rect::from_xywh(0.0, 0.0, 200.0, 200.0), 1.0).unwrap();
    cpu::png_pixel(&png, x, y).unwrap().1
}

fn dark(p: [u8; 4]) -> bool {
    p[0] < 80 && p[1] < 80 && p[2] < 80
}

fn red(p: [u8; 4]) -> bool {
    p[0] > 200 && p[1] < 60 && p[2] < 60
}

fn white(p: [u8; 4]) -> bool {
    p[0] > 245 && p[1] > 245 && p[2] > 245
}

#[test]
fn a_rotated_node_draws_hits_and_bounds_about_its_centre() {
    // a 100 x 20 bar at (50, 90) turned 90 degrees stands upright over x 90..110, y 50..150
    let mut r = board(vec![json!({"type": "rect", "props": {
        "x": 50, "y": 90, "w": 100, "h": 20, "rotation": 90, "fill": solid("#ff0000")}})]);
    assert!(red(px(&mut r, 100, 60)), "upright part drawn");
    assert!(white(px(&mut r, 60, 100)), "the unrotated span is empty");
    let bar = id_of(3);
    assert_eq!(r.hit_world(100.0, 60.0).unwrap().id, bar);
    assert_eq!(
        r.hit_world(60.0, 100.0).unwrap().id,
        id_of(2),
        "falls through to the board"
    );
    let b = r.node_bounds(&bar).unwrap();
    for (got, want) in [
        (b.left, 90.0),
        (b.top, 50.0),
        (b.right, 110.0),
        (b.bottom, 150.0),
    ] {
        assert!((got - want).abs() < 0.01, "{b:?}");
    }
    // the layout box is what the props say; the frame is that box at its drawn centre with the turn
    assert_eq!(
        r.node_rect(&bar).unwrap(),
        Rect::from_xywh(50.0, 90.0, 100.0, 20.0)
    );
    let (f, rot) = r.node_frame(&bar).unwrap();
    assert!(
        (rot - 90.0).abs() < 0.01
            && (f.center_x() - 100.0).abs() < 0.01
            && (f.width() - 100.0).abs() < 0.01
    );
}

#[test]
fn a_child_turns_with_its_rotated_parent() {
    // a 100 x 100 frame at (50, 50) turned 90: its child at its top-left corner lands at the top-right
    let mut r = board(vec![
        json!({"type": "frame", "props": {"x": 50, "y": 50, "w": 100, "h": 100, "rotation": 90},
        "children": [{"type": "rect", "props": {"x": 0, "y": 0, "w": 20, "h": 20, "fill": solid("#ff0000")}}]}),
    ]);
    assert!(red(px(&mut r, 140, 60)), "child moved with the turn");
    assert!(white(px(&mut r, 60, 60)), "and is not where it was");
    let (_, rot) = r.node_frame(&id_of(4)).unwrap();
    assert!((rot - 90.0).abs() < 0.01, "inherits the parent's rotation");
    assert_eq!(r.hit_world(140.0, 60.0).unwrap().id, id_of(4));
}

#[test]
fn inner_shadow_darkens_inside_the_shape_only() {
    let mut r = board(vec![
        json!({"type": "rect", "props": {"x": 50, "y": 50, "w": 100, "h": 100,
        "fill": solid("#ffffff"), "shadow": [{"x": 10, "y": 0, "blur": 0, "color": "#000000", "inset": true}]}}),
    ]);
    assert!(dark(px(&mut r, 55, 100)), "a band on the inside left");
    assert!(white(px(&mut r, 100, 100)), "the middle stays");
    assert!(white(px(&mut r, 45, 100)), "nothing outside");
}

#[test]
fn strokes_stack_with_their_alignment_and_dash() {
    let mut r = board(vec![
        json!({"type": "rect", "props": {"x": 50, "y": 50, "w": 100, "h": 100,
        "stroke": [{"color": "#000000", "width": 10, "align": "outside"}, {"color": "#ff0000", "width": 10}]}}),
    ]);
    assert!(dark(px(&mut r, 45, 100)), "outside stroke outside the box");
    assert!(
        red(px(&mut r, 55, 100)),
        "the default (inside) stroke inside it"
    );
    assert!(white(px(&mut r, 100, 100)));
    // a dashed centred stroke along the top edge: on and off in turn (where the outline starts sets the phase)
    let mut r = board(vec![
        json!({"type": "rect", "props": {"x": 20, "y": 50, "w": 160, "h": 100,
        "stroke": {"color": "#000000", "width": 4, "align": "center", "dash": [20, 20]}}}),
    ]);
    let on: Vec<bool> = (0..8).map(|i| dark(px(&mut r, 30 + i * 20, 50))).collect();
    assert!(on.windows(2).all(|w| w[0] != w[1]), "{on:?}");
}

#[test]
fn layer_blur_spreads_and_background_blur_softens_what_is_under() {
    let mut r = board(vec![
        json!({"type": "rect", "props": {"x": 50, "y": 50, "w": 100, "h": 100,
        "fill": solid("#000000"), "blur": 20}}),
    ]);
    let edge = px(&mut r, 45, 100);
    assert!(
        !white(edge) && !dark(edge),
        "the blur spills past the edge: {edge:?}"
    );
    // black left half, white right half; a clear pane over the seam with a background blur greys it
    let halves = |extra: Value| {
        let mut pane = json!({"type": "rect", "props": {"x": 50, "y": 50, "w": 100, "h": 100}});
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            pane["props"][k] = v;
        }
        board(vec![
            json!({"type": "rect", "props": {"x": 0, "y": 0, "w": 100, "h": 200, "fill": solid("#000000")}}),
            pane,
        ])
    };
    assert!(
        dark(px(&mut halves(json!({})), 98, 100)),
        "sharp without the blur"
    );
    let g = px(&mut halves(json!({"backdrop_blur": 40})), 98, 100);
    assert!(!dark(g) && !white(g), "blurred seam: {g:?}");
}
