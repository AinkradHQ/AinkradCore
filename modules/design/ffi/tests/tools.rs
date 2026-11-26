//! Drawing tools through the C ABI: a drag draws in document coordinates (camera zoom 2, pan 100/50), a click makes
//! the default size, shift constrains, the pen builds a vector, one undo step per node, Escape cancels.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use design_ffi::testing;
use serde_json::{Value, json};

const PAGE: &str = "n_pppppppppppp";
/// frame at 20,30 400x400
const A: &str = "n_aaaaaaaaaaaa";

fn engine() -> u64 {
    let mut h = 0u64;
    let id = b"dd_tools";
    let ops = json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a", "props": {"x": 20, "y": 30, "w": 400, "h": 400}},
    ])
    .to_string();
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut h), DE_OK);
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
    }
    assert_eq!(de_resize(h, 1200.0, 800.0, 1.0), DE_OK);
    testing::set_camera(h, 2.0, (100.0, 50.0));
    h
}

fn gets(f: impl Fn(*mut u8, usize, *mut usize) -> i32) -> Value {
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0usize;
    assert_eq!(f(buf.as_mut_ptr(), buf.len(), &mut n), DE_OK);
    serde_json::from_slice(&buf[..n]).unwrap()
}

fn node(h: u64, id: &str) -> Value {
    gets(|o, c, l| unsafe { de_node(h, id.as_ptr(), id.len(), o, c, l) })
}

fn selection(h: u64) -> Vec<String> {
    serde_json::from_value(gets(|o, c, l| unsafe { de_selection(h, o, c, l) })).unwrap()
}

/// nodes in the document
fn count(h: u64) -> usize {
    let t = gets(|o, c, l| unsafe { de_tree(h, o, c, l) }).to_string();
    let ids: std::collections::HashSet<&str> = t
        .split("\"n_")
        .skip(1)
        .filter_map(|s| s.get(..12))
        .collect();
    ids.len()
}

/// view point of world point `w` (zoom 2, pan 100/50)
fn v(w: (f32, f32)) -> (f32, f32) {
    (w.0 * 2.0 + 100.0, w.1 * 2.0 + 50.0)
}

fn ptr(h: u64, phase: u32, w: (f32, f32), mods: u32) {
    let p = v(w);
    assert_eq!(de_pointer(h, phase, p.0, p.1, mods), DE_OK);
}

fn drag(h: u64, tool: u32, from: (f32, f32), to: (f32, f32), mods: u32) {
    assert_eq!(de_set_tool(h, tool), DE_OK);
    ptr(h, DE_POINTER_DOWN, from, mods);
    for i in 1..=4 {
        let t = i as f32 / 4.0;
        ptr(
            h,
            DE_POINTER_MOVE,
            (from.0 + (to.0 - from.0) * t, from.1 + (to.1 - from.1) * t),
            mods,
        );
    }
    ptr(h, DE_POINTER_UP, to, mods);
}

fn click(h: u64, tool: u32, at: (f32, f32)) {
    assert_eq!(de_set_tool(h, tool), DE_OK);
    ptr(h, DE_POINTER_DOWN, at, 0);
    ptr(h, DE_POINTER_UP, at, 0);
}

fn created(h: u64) -> Value {
    let s = selection(h);
    assert_eq!(s.len(), 1, "the new node is selected");
    node(h, &s[0])
}

fn num(v: &Value) -> f64 {
    v.as_f64().unwrap()
}

#[test]
fn a_drag_draws_in_document_coordinates_and_is_one_undo_step() {
    let h = engine();
    let before = count(h);
    drag(h, DE_TOOL_RECT, (600.0, 200.0), (700.0, 300.0), 0);
    let n = created(h);
    assert_eq!(n["type"], "rect");
    assert_eq!(n["name"], "Rectangle");
    assert_eq!(n["parent"], PAGE);
    let p = &n["props"];
    assert_eq!(
        (num(&p["x"]), num(&p["y"]), num(&p["w"]), num(&p["h"])),
        (600.0, 200.0, 100.0, 100.0)
    );
    assert_eq!(p["fill"], json!([{"type": "solid", "color": "#D9D9D9"}]));
    assert_eq!(de_tool(h), DE_TOOL_SELECT as i32, "back to select");
    assert_eq!(count(h), before + 1);
    assert_eq!(de_undo(h), 1);
    assert_eq!(count(h), before, "one step removes it");
    assert_eq!(de_redo(h), 1);
    assert_eq!(count(h), before + 1);

    // a frame inside a frame is placed relative to its parent; the ellipse and the frame defaults
    drag(h, DE_TOOL_ELLIPSE, (100.0, 150.0), (160.0, 190.0), 0);
    let n = created(h);
    assert_eq!(
        (n["type"].as_str(), n["parent"].as_str()),
        (Some("ellipse"), Some(A))
    );
    assert_eq!(
        (num(&n["props"]["x"]), num(&n["props"]["y"])),
        (80.0, 120.0)
    );
    assert_eq!((num(&n["props"]["w"]), num(&n["props"]["h"])), (60.0, 40.0));
    drag(h, DE_TOOL_FRAME, (500.0, 200.0), (560.0, 240.0), 0);
    let n = created(h);
    assert_eq!(n["name"], "Frame");
    assert_eq!(n["props"]["clip"], json!(true));
    assert_eq!(
        n["props"]["fill"],
        json!([{"type": "solid", "color": "#FFFFFF"}])
    );
}

#[test]
fn a_drag_previews_and_escape_cancels() {
    let h = engine();
    let before = count(h);
    assert_eq!(de_set_tool(h, DE_TOOL_RECT), DE_OK);
    ptr(h, DE_POINTER_DOWN, (600.0, 200.0), 0);
    ptr(h, DE_POINTER_MOVE, (700.0, 300.0), 0);
    assert_eq!(count(h), before, "nothing is written while dragging");
    let v = v((650.0, 250.0));
    let hit = gets(|o, c, l| unsafe { de_hit(h, v.0, v.1, o, c, l) });
    assert!(
        hit["id"].is_string(),
        "the preview is drawn under the pointer: {hit}"
    );
    assert_eq!(de_cursor(h, 0.0, 0.0), DE_CURSOR_CROSSHAIR);
    assert_eq!(de_key(h, DE_KEY_ESCAPE, 0), DE_OK);
    ptr(h, DE_POINTER_UP, (700.0, 300.0), 0);
    assert_eq!(count(h), before);
    assert!(selection(h).is_empty());
    assert_eq!(
        de_tool(h),
        DE_TOOL_RECT as i32,
        "a cancelled drag keeps the tool"
    );
    assert_eq!(de_key(h, DE_KEY_ESCAPE, 0), DE_OK);
    assert_eq!(de_tool(h), DE_TOOL_SELECT as i32, "Escape again leaves it");
    assert_eq!(de_set_tool(h, 99), DE_ERR_ARG);
}

#[test]
fn a_click_makes_the_default_size() {
    let h = engine();
    let size = |h: u64| {
        let p = created(h)["props"].clone();
        (num(&p["x"]), num(&p["y"]), num(&p["w"]), num(&p["h"]))
    };
    // inside the frame at 20,30: positions are the frame's
    click(h, DE_TOOL_FRAME, (100.0, 150.0));
    assert_eq!(size(h), (80.0, 120.0, 400.0, 400.0));
    click(h, DE_TOOL_RECT, (700.0, 500.0));
    assert_eq!(size(h), (700.0, 500.0, 100.0, 100.0));
    click(h, DE_TOOL_ELLIPSE, (700.0, 500.0));
    assert_eq!(size(h), (700.0, 500.0, 100.0, 100.0));
    click(h, DE_TOOL_LINE, (700.0, 500.0));
    let n = created(h);
    assert_eq!(n["type"], "vector");
    assert_eq!(n["name"], "Line");
    assert_eq!(n["props"]["path"], "M0 0 L160 0");
    assert_eq!(
        n["props"]["stroke"],
        json!({"color": "#111111", "width": 2})
    );
    assert_eq!(num(&n["props"]["w"]), 160.0);
}

#[test]
fn shift_keeps_a_rectangle_square_and_a_line_at_45_degrees() {
    let h = engine();
    drag(
        h,
        DE_TOOL_RECT,
        (600.0, 200.0),
        (700.0, 260.0),
        DE_MOD_SHIFT,
    );
    let p = created(h)["props"].clone();
    assert_eq!((num(&p["w"]), num(&p["h"])), (100.0, 100.0));
    // dragged up and left, the square grows that way
    drag(
        h,
        DE_TOOL_RECT,
        (700.0, 500.0),
        (640.0, 400.0),
        DE_MOD_SHIFT,
    );
    let p = created(h)["props"].clone();
    assert_eq!(
        (num(&p["x"]), num(&p["y"]), num(&p["w"])),
        (600.0, 400.0, 100.0)
    );

    drag(
        h,
        DE_TOOL_LINE,
        (600.0, 600.0),
        (700.0, 670.0),
        DE_MOD_SHIFT,
    );
    let p = created(h)["props"].clone();
    assert!((num(&p["w"]) - num(&p["h"])).abs() < 0.02, "{p}");
    assert!(num(&p["w"]) > 80.0);
    // up and to the right: from the bottom-left corner to the top-right
    drag(h, DE_TOOL_LINE, (600.0, 600.0), (700.0, 500.0), 0);
    assert_eq!(created(h)["props"]["path"], "M0 100 L100 0");
}

#[test]
fn the_text_tool_starts_editing_and_an_empty_text_goes_again() {
    let h = engine();
    click(h, DE_TOOL_TEXT, (600.0, 200.0));
    let n = created(h);
    assert_eq!(
        (n["type"].as_str(), n["name"].as_str()),
        (Some("text"), Some("Text"))
    );
    assert_eq!(n["props"]["type"]["size"], json!(16));
    assert_eq!(
        n["props"]["fill"],
        json!([{"type": "solid", "color": "#111111"}])
    );
    assert_eq!(de_text_active(h), 1);
    assert_eq!(de_tool(h), DE_TOOL_SELECT as i32);
    let id = selection(h)[0].clone();
    assert_eq!(
        unsafe { de_text_insert(h, b"hi".as_ptr(), 2, DE_TEXT_NO_RANGE, 0) },
        DE_OK
    );
    assert_eq!(node(h, &id)["text"], "hi");
    assert_eq!(de_text_end(h), DE_OK);
    assert_eq!(de_text_active(h), 0);
    assert_eq!(node(h, &id)["text"], "hi", "typed text stays");

    click(h, DE_TOOL_TEXT, (600.0, 400.0));
    let id = selection(h)[0].clone();
    assert_eq!(de_text_end(h), DE_OK);
    assert_eq!(node(h, &id), Value::Null, "never typed into: removed");

    drag(h, DE_TOOL_TEXT, (600.0, 500.0), (700.0, 510.0), 0);
    assert_eq!(num(&created(h)["props"]["w"]), 100.0);
}

fn pen_click(h: u64, at: (f32, f32)) {
    ptr(h, DE_POINTER_DOWN, at, 0);
    ptr(h, DE_POINTER_UP, at, 0);
}

#[test]
fn the_pen_builds_open_and_closed_paths() {
    let h = engine();
    let before = count(h);
    assert_eq!(de_set_tool(h, DE_TOOL_PEN), DE_OK);
    pen_click(h, (600.0, 200.0));
    pen_click(h, (700.0, 200.0));
    ptr(h, DE_POINTER_MOVE, (650.0, 260.0), 0);
    assert_eq!(count(h), before, "the rubber band is only a preview");
    pen_click(h, (700.0, 300.0));
    assert_eq!(de_key(h, DE_KEY_ENTER, 0), DE_OK);
    let n = created(h);
    assert_eq!(
        (n["type"].as_str(), n["name"].as_str()),
        (Some("vector"), Some("Path"))
    );
    let p = &n["props"];
    assert_eq!(p["path"], "M0 0 L100 0 L100 100");
    assert_eq!(
        (num(&p["x"]), num(&p["y"]), num(&p["w"]), num(&p["h"])),
        (600.0, 200.0, 100.0, 100.0)
    );
    assert_eq!(p["stroke"], json!({"color": "#111111", "width": 2}));
    assert_eq!(p["fill"], json!([]));
    assert_eq!(de_tool(h), DE_TOOL_SELECT as i32);
    assert_eq!(de_undo(h), 1);
    assert_eq!(count(h), before);

    // clicking the first anchor closes it
    assert_eq!(de_set_tool(h, DE_TOOL_PEN), DE_OK);
    for at in [
        (600.0, 200.0),
        (700.0, 200.0),
        (700.0, 300.0),
        (600.0, 300.0),
    ] {
        pen_click(h, at);
    }
    pen_click(h, (600.0, 200.0));
    let p = created(h)["props"].clone();
    assert_eq!(p["path"], "M0 0 L100 0 L100 100 L0 100 Z");
    assert_eq!(p["fill"], json!([{"type": "solid", "color": "#D9D9D9"}]));

    // a second click on the last anchor ends an open path
    assert_eq!(de_set_tool(h, DE_TOOL_PEN), DE_OK);
    pen_click(h, (600.0, 500.0));
    pen_click(h, (700.0, 560.0));
    pen_click(h, (700.0, 560.0));
    assert_eq!(created(h)["props"]["path"], "M0 0 L100 60");

    // Escape with one anchor cancels
    let n = count(h);
    assert_eq!(de_set_tool(h, DE_TOOL_PEN), DE_OK);
    pen_click(h, (600.0, 700.0));
    assert_eq!(de_key(h, DE_KEY_ESCAPE, 0), DE_OK);
    assert_eq!(count(h), n);
    assert_eq!(de_tool(h), DE_TOOL_SELECT as i32);
}

#[test]
fn the_hand_pans_and_the_cursor_follows_the_tool() {
    let h = engine();
    assert_eq!(de_set_tool(h, DE_TOOL_HAND), DE_OK);
    assert_eq!(de_cursor(h, 5.0, 5.0), DE_CURSOR_GRAB);
    assert_eq!(de_pointer(h, DE_POINTER_DOWN, 500.0, 400.0, 0), DE_OK);
    assert_eq!(de_cursor(h, 5.0, 5.0), DE_CURSOR_GRABBING);
    assert_eq!(de_pointer(h, DE_POINTER_MOVE, 540.0, 430.0, 0), DE_OK);
    assert_eq!(de_pointer(h, DE_POINTER_UP, 540.0, 430.0, 0), DE_OK);
    let (z, px, py) = testing::camera(h).unwrap();
    assert_eq!(z, 2.0);
    assert!(px > 100.0 && py > 50.0, "panned right and down: {px} {py}");
    assert_eq!(de_tool(h), DE_TOOL_HAND as i32, "the hand stays");
    assert_eq!(de_set_tool(h, DE_TOOL_TEXT), DE_OK);
    assert_eq!(de_cursor(h, 5.0, 5.0), DE_CURSOR_TEXT);
    assert_eq!(de_set_tool(h, DE_TOOL_SELECT), DE_OK);
    assert_eq!(de_cursor(h, 5.0, 5.0), DE_CURSOR_DEFAULT);
}
