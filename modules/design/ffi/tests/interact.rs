//! V2-03 acceptance through the C ABI: select / marquee, move with snapping, nest and unnest by drag, auto-layout
//! reorder, resize, duplicate, nudge, delete, cancel, one undo step per gesture, rubber-band camera bounds.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use design_ffi::testing;
use serde_json::{Value, json};

const PAGE: &str = "n_pppppppppppp";
/// free frame at 0,0 400x400
const A: &str = "n_aaaaaaaaaaaa";
/// free frame at 500,0 400x400
const B: &str = "n_bbbbbbbbbbbb";
/// rect in A at 10,10 50x50
const R: &str = "n_rrrrrrrrrrrr";
/// rect in A at 100,200 40x40 (a snap target)
const S: &str = "n_ssssssssssss";
/// auto-layout column in B at 20,20, holding K1, K2, K3 (each 100x30, gap 10)
const L: &str = "n_llllllllllll";
const K: [&str; 3] = ["n_kkkkkkkkkkk2", "n_kkkkkkkkkkk3", "n_kkkkkkkkkkk4"];

fn engine() -> u64 {
    let mut h = 0u64;
    let id = b"dd_interact";
    let ops = json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a", "props": {"x": 0, "y": 0, "w": 400, "h": 400}},
        {"op": "add", "id": B, "type": "frame", "parent": PAGE, "order": "b", "props": {"x": 500, "y": 0, "w": 400, "h": 400}},
        {"op": "add", "id": R, "type": "rect", "parent": A, "order": "a", "props": {"x": 10, "y": 10, "w": 50, "h": 50}},
        {"op": "add", "id": S, "type": "rect", "parent": A, "order": "b", "props": {"x": 100, "y": 200, "w": 40, "h": 40}},
        {"op": "add", "id": L, "type": "frame", "parent": B, "order": "a",
         "props": {"x": 20, "y": 20, "layout": {"dir": "column", "gap": 10}}},
        {"op": "add", "id": K[0], "type": "rect", "parent": L, "order": "a", "props": {"w": 100, "h": 30}},
        {"op": "add", "id": K[1], "type": "rect", "parent": L, "order": "b", "props": {"w": 100, "h": 30}},
        {"op": "add", "id": K[2], "type": "rect", "parent": L, "order": "c", "props": {"w": 100, "h": 30}},
    ])
    .to_string();
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut h), DE_OK);
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
    }
    assert_eq!(de_resize(h, 1200.0, 800.0, 1.0), DE_OK);
    h
}

fn gets(f: impl Fn(*mut u8, usize, *mut usize) -> i32) -> Value {
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0usize;
    assert_eq!(f(buf.as_mut_ptr(), buf.len(), &mut n), DE_OK);
    serde_json::from_slice(&buf[..n]).unwrap()
}

fn selection(h: u64) -> Vec<String> {
    serde_json::from_value(gets(|o, c, l| unsafe { de_selection(h, o, c, l) })).unwrap()
}

fn node(h: u64, id: &str) -> Value {
    gets(|o, c, l| unsafe { de_node(h, id.as_ptr(), id.len(), o, c, l) })
}

fn rect(h: u64, id: &str) -> [f32; 4] {
    testing::rect(h, id).unwrap()
}

fn drag(h: u64, from: (f32, f32), to: (f32, f32), mods: u32) {
    assert_eq!(de_pointer(h, DE_POINTER_DOWN, from.0, from.1, mods), DE_OK);
    for i in 1..=4 {
        let t = i as f32 / 4.0;
        let p = (from.0 + (to.0 - from.0) * t, from.1 + (to.1 - from.1) * t);
        assert_eq!(de_pointer(h, DE_POINTER_MOVE, p.0, p.1, mods), DE_OK);
    }
    assert_eq!(de_pointer(h, DE_POINTER_UP, to.0, to.1, mods), DE_OK);
}

fn click(h: u64, at: (f32, f32), mods: u32) {
    assert_eq!(de_pointer(h, DE_POINTER_DOWN, at.0, at.1, mods), DE_OK);
    assert_eq!(de_pointer(h, DE_POINTER_UP, at.0, at.1, mods), DE_OK);
}

#[test]
fn click_shift_click_and_marquee_select() {
    let h = engine();
    click(h, (30.0, 30.0), 0);
    assert_eq!(selection(h), [R]);
    click(h, (120.0, 220.0), DE_MOD_SHIFT);
    assert_eq!(selection(h), [R, S]);
    click(h, (30.0, 30.0), DE_MOD_SHIFT);
    assert_eq!(selection(h), [S], "shift-click drops a selected node");
    // A has children: a click on its background selects it, a drag there is a marquee inside it
    click(h, (300.0, 100.0), 0);
    assert_eq!(selection(h), [A]);
    click(h, (1100.0, 700.0), 0);
    drag(h, (5.0, 300.0), (150.0, 5.0), 0);
    assert_eq!(
        selection(h),
        [R, S],
        "marquee inside A picks A's children it touches"
    );
    // from the empty canvas: top-level nodes
    drag(h, (450.0, 450.0), (380.0, 380.0), 0);
    assert_eq!(selection(h), [A]);
    click(h, (1100.0, 700.0), 0);
    assert!(selection(h).is_empty());
    assert_eq!(de_key(h, DE_KEY_ESCAPE, 0), DE_OK);
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn move_snaps_and_is_one_undo_step() {
    let h = engine();
    click(h, (30.0, 30.0), 0);
    // R would land at 97..147 (centre 122): the nearest line is S's centre (120), 2 pt away
    drag(h, (30.0, 30.0), (117.0, 64.0), 0);
    assert_eq!(rect(h, R), [95.0, 44.0, 145.0, 94.0]);
    assert_eq!(node(h, R)["props"]["x"], json!(95.0));
    // ⌘ turns snapping off
    drag(h, (120.0, 60.0), (117.0, 60.0), DE_MOD_COMMAND);
    assert_eq!(rect(h, R)[0], 92.0);
    assert_eq!(de_undo(h), 1);
    assert_eq!(de_undo(h), 1);
    assert_eq!(
        rect(h, R),
        [10.0, 10.0, 60.0, 60.0],
        "two gestures, two undo steps"
    );
    // Escape mid-drag: nothing written
    assert_eq!(
        de_pointer(h, DE_POINTER_DOWN, 30.0, 30.0, DE_MOD_COMMAND),
        DE_OK
    );
    assert_eq!(
        de_pointer(h, DE_POINTER_MOVE, 200.0, 300.0, DE_MOD_COMMAND),
        DE_OK
    );
    assert_eq!(rect(h, R)[0], 180.0, "the preview moves it");
    assert_eq!(de_key(h, DE_KEY_ESCAPE, 0), DE_OK);
    assert_eq!(de_pointer(h, DE_POINTER_UP, 200.0, 300.0, 0), DE_OK);
    assert_eq!(rect(h, R)[0], 10.0);
    assert_eq!(
        selection(h),
        [R],
        "escape cancels the drag, not the selection"
    );
    assert_eq!(de_undo(h), 1, "only the seed is left to undo");
    assert_eq!(de_undo(h), 0);
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn drag_nests_unnests_and_reorders_auto_layout() {
    let h = engine();
    click(h, (30.0, 30.0), 0);
    // into B (free frame): parent B, x/y relative to B
    drag(h, (30.0, 30.0), (730.0, 330.0), 0);
    let n = node(h, R);
    assert_eq!(n["parent"], B);
    assert_eq!(
        (n["props"]["x"].clone(), n["props"]["y"].clone()),
        (json!(210.0), json!(310.0))
    );
    // out to the empty canvas: a top-level node with world x/y
    drag(h, (730.0, 330.0), (730.0, 530.0), 0);
    let n = node(h, R);
    assert_eq!(n["parent"], PAGE);
    assert_eq!(n["props"]["y"], json!(510.0));
    // into the auto-layout column, between K1 and K2: order, not x/y
    drag(h, (730.0, 530.0), (560.0, 72.0), 0);
    assert_eq!(node(h, R)["parent"], L);
    let ys: Vec<f32> = [K[0], R, K[1], K[2]]
        .iter()
        .map(|k| rect(h, k)[1])
        .collect();
    assert!(
        ys.windows(2).all(|w| w[0] < w[1]),
        "reflowed in order: {ys:?}"
    );
    // K3 dragged to the top of the column
    click(h, (560.0, rect(h, K[2])[1] + 5.0), 0);
    assert_eq!(selection(h), [K[2]]);
    let y = rect(h, K[2])[1] + 5.0;
    drag(h, (560.0, y), (560.0, 22.0), 0);
    assert!(rect(h, K[2])[1] < rect(h, K[0])[1]);
    // four gestures, four undo steps
    for _ in 0..4 {
        assert_eq!(de_undo(h), 1);
    }
    assert_eq!(node(h, R)["parent"], A);
    assert_eq!(rect(h, R), [10.0, 10.0, 60.0, 60.0]);
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn resize_from_handles_and_cursor() {
    let h = engine();
    click(h, (30.0, 30.0), 0);
    assert_eq!(de_cursor(h, 60.0, 60.0), DE_CURSOR_RESIZE_NWSE);
    assert_eq!(de_cursor(h, 60.0, 35.0), DE_CURSOR_RESIZE_EW);
    assert_eq!(de_cursor(h, 35.0, 10.0), DE_CURSOR_RESIZE_NS);
    assert_eq!(de_cursor(h, 30.0, 30.0), DE_CURSOR_DEFAULT);
    drag(h, (60.0, 60.0), (90.0, 70.0), DE_MOD_COMMAND);
    assert_eq!(rect(h, R), [10.0, 10.0, 90.0, 70.0]);
    // shift keeps the aspect (80:60)
    drag(h, (90.0, 70.0), (170.0, 75.0), DE_MOD_SHIFT);
    assert_eq!(rect(h, R), [10.0, 10.0, 170.0, 130.0]);
    // the left edge snaps to S's right edge (140) from 3 pt away
    drag(h, (10.0, 70.0), (137.0, 70.0), 0);
    assert_eq!(rect(h, R)[0], 140.0);
    assert_eq!(node(h, R)["props"]["x"], json!(140.0));
    assert_eq!(de_cursor(h, f32::NAN, 0.0), DE_ERR_ARG);
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn keys_duplicate_nudge_delete() {
    let h = engine();
    click(h, (30.0, 30.0), 0);
    assert_eq!(de_key(h, DE_KEY_RIGHT, 0), DE_OK);
    assert_eq!(de_key(h, DE_KEY_DOWN, DE_MOD_SHIFT), DE_OK);
    assert_eq!(rect(h, R), [11.0, 20.0, 61.0, 70.0]);
    assert_eq!(de_key(h, DE_KEY_DUPLICATE, 0), DE_OK);
    let copy = selection(h);
    assert_eq!(copy.len(), 1);
    assert_ne!(copy[0], R);
    assert_eq!(node(h, &copy[0])["parent"], A);
    assert_eq!(
        rect(h, &copy[0]),
        rect(h, R),
        "a nested copy sits on its original"
    );
    // a top-level copy goes to the right of its original, children copied too
    click(h, (300.0, 100.0), 0);
    assert_eq!(de_key(h, DE_KEY_DUPLICATE, 0), DE_OK);
    let a2 = selection(h)[0].clone();
    assert_eq!(rect(h, &a2)[0], 440.0);
    assert_eq!(node(h, &a2)["parent"], PAGE);
    // alt-drag copies R (one gesture, one undo step)
    click(h, (30.0, 40.0), 0);
    let r_sel = selection(h)[0].clone();
    drag(
        h,
        (30.0, 40.0),
        (230.0, 40.0),
        DE_MOD_OPTION | DE_MOD_COMMAND,
    );
    let moved = selection(h)[0].clone();
    assert_ne!(moved, r_sel);
    assert_eq!(rect(h, &moved)[0] - rect(h, &r_sel)[0], 200.0);
    assert_eq!(de_undo(h), 1);
    assert_eq!(node(h, &moved), Value::Null);
    // reorder in auto layout with the arrows
    click(h, (560.0, rect(h, K[1])[1] + 5.0), 0);
    assert_eq!(de_key(h, DE_KEY_UP, 0), DE_OK);
    assert!(rect(h, K[1])[1] < rect(h, K[0])[1]);
    assert_eq!(de_key(h, DE_KEY_DELETE, 0), DE_OK);
    assert_eq!(node(h, K[1]), Value::Null);
    assert_eq!(de_key(h, 999, 0), DE_OK, "unknown keys are ignored");
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn camera_rubber_band_settles_inside_the_bounds() {
    let h = engine();
    assert_eq!(de_fit(h), DE_OK);
    assert_eq!(de_fit_selection(h), DE_OK, "no selection: fit all");
    // scroll the content far off to the left: resisted past the edge
    for _ in 0..50 {
        assert_eq!(de_scroll(h, -100.0, 0.0), DE_OK);
    }
    assert_eq!(de_gesture_end(h, 0), DE_OK);
    let mut frames = 0;
    while de_tick(h, 1.0 / 120.0) == 1 {
        frames += 1;
        assert!(frames < 240, "settles within 2 s");
    }
    assert!(frames > 3, "animated");
    assert_eq!(de_tick(h, 1.0 / 120.0), 0);
    assert_eq!(de_tick(h, f32::NAN), DE_ERR_ARG);
    assert_eq!(de_tick(h, 5.0), DE_ERR_ARG);
    // with Reduce Motion the jump back is immediate
    for _ in 0..50 {
        assert_eq!(de_scroll(h, -100.0, 0.0), DE_OK);
    }
    assert_eq!(de_gesture_end(h, 1), DE_OK);
    assert_eq!(de_tick(h, 0.01), 0);
    assert_eq!(de_engine_free(h), DE_OK);
}
