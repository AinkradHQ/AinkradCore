//! Engine tools through the C ABI: rotate from a corner (⇧ snaps), lock (looked through on the canvas, still
//! selectable by id), copy / paste across designs, group / ungroup, components (create, insert, detach), and a
//! remote (AI session) frame removed as a local edit and brought back by undo.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use design_ffi::testing;
use serde_json::{Value, json};

const PAGE: &str = "n_pppppppppppp";
/// free frame at 0,0 400x400
const A: &str = "n_aaaaaaaaaaaa";
/// rect in A at 100,100 100x50
const R: &str = "n_rrrrrrrrrrrr";
/// rect in A at 250,250 50x50
const S: &str = "n_ssssssssssss";

fn new(doc: &str) -> u64 {
    let mut h = 0u64;
    unsafe { assert_eq!(de_engine_new(doc.as_ptr(), doc.len(), &mut h), DE_OK) };
    assert_eq!(de_resize(h, 1200.0, 800.0, 1.0), DE_OK);
    h
}

fn edit(h: u64, ops: Value) -> i32 {
    let s = ops.to_string();
    unsafe { de_edit(h, s.as_ptr(), s.len()) }
}

fn engine() -> u64 {
    let h = new("dd_tools");
    let r = edit(
        h,
        json!([
            {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
            {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a", "props": {"x": 0, "y": 0, "w": 400, "h": 400}},
            {"op": "add", "id": R, "type": "rect", "parent": A, "order": "a", "props": {"x": 100, "y": 100, "w": 100, "h": 50}},
            {"op": "add", "id": S, "type": "rect", "parent": A, "order": "b", "props": {"x": 250, "y": 250, "w": 50, "h": 50}},
        ]),
    );
    assert_eq!(r, DE_OK);
    h
}

fn gets(f: impl Fn(*mut u8, usize, *mut usize) -> i32) -> Value {
    let mut buf = vec![0u8; 1 << 20];
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

fn tree(h: u64) -> Vec<Value> {
    serde_json::from_value(gets(|o, c, l| unsafe { de_tree(h, o, c, l) })).unwrap()
}

fn row(h: u64, id: &str) -> Value {
    tree(h).into_iter().find(|r| r["id"] == id).unwrap()
}

fn select(h: u64, ids: &[&str]) {
    let s = json!(ids).to_string();
    unsafe { assert_eq!(de_select(h, s.as_ptr(), s.len()), DE_OK) };
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

fn rect(h: u64, id: &str) -> [f32; 4] {
    testing::rect(h, id).unwrap()
}

fn hit(h: u64, at: (f32, f32)) -> Value {
    gets(|o, c, l| unsafe { de_hit(h, at.0, at.1, o, c, l) })
}

#[test]
fn rotate_from_just_outside_a_corner_snaps_and_is_one_undo_step() {
    let h = engine();
    click(h, (150.0, 125.0), 0);
    assert_eq!(selection(h), [R]);
    // just outside the ne corner (200, 100): the rotate cursor, not a resize one
    assert_eq!(de_cursor(h, 210.0, 90.0), DE_CURSOR_ROTATE);
    assert_eq!(de_cursor(h, 200.0, 100.0), DE_CURSOR_RESIZE_NESW);
    // a quarter turn clockwise about the centre (150, 125), a little short: ⇧ snaps it to 90
    drag(h, (210.0, 90.0), (187.0, 183.0), DE_MOD_SHIFT);
    assert_eq!(node(h, R)["props"]["rotation"], json!(90.0));
    assert_eq!(row(h, R)["rotation"], json!(90.0));
    assert_eq!(
        rect(h, R),
        [100.0, 100.0, 200.0, 150.0],
        "the layout box is unchanged"
    );
    // now upright: (150, 170) is on it, (110, 125) is not
    assert_eq!(hit(h, (150.0, 170.0))["id"], R);
    assert_eq!(hit(h, (110.0, 125.0))["id"], A);
    // the handles turned with it: the old ne corner now shows at (175, 175), its cursor turned a quarter
    assert_eq!(de_cursor(h, 175.0, 175.0), DE_CURSOR_RESIZE_NWSE);
    assert_eq!(de_undo(h), 1);
    assert_eq!(node(h, R)["props"].get("rotation"), None);
    // without ⇧ the angle follows the pointer (to 1/100 degree)
    drag(h, (210.0, 90.0), (187.0, 183.0), 0);
    let r = node(h, R)["props"]["rotation"].as_f64().unwrap();
    assert!(r > 80.0 && r < 90.0, "{r}");
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn a_rotated_node_resizes_along_its_own_axes() {
    let h = engine();
    assert_eq!(
        edit(
            h,
            json!([{"op": "set", "id": R, "key": "rotation", "value": 90}])
        ),
        DE_OK
    );
    select(h, &[R]);
    // turned 90: the box's right edge (e handle) shows at the bottom, (150, 175); dragging it down 20 widens it
    drag(h, (150.0, 175.0), (150.0, 195.0), DE_MOD_COMMAND);
    let p = &node(h, R)["props"];
    assert_eq!(
        (p["w"].clone(), p["h"].clone()),
        (json!(120.0), json!(50.0))
    );
    // the top (its left edge) stays where it shows: the centre moved down 10
    assert_eq!(
        (p["x"].clone(), p["y"].clone()),
        (json!(90.0), json!(110.0))
    );
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn locked_nodes_are_looked_through_but_selectable_by_id() {
    let h = engine();
    assert_eq!(
        edit(
            h,
            json!([{"op": "set", "id": R, "key": "locked", "value": true}])
        ),
        DE_OK
    );
    assert_eq!(row(h, R)["locked"], json!(true));
    assert_eq!(row(h, S)["locked"], json!(false));
    assert_eq!(row(h, S)["hidden"], json!(false));
    assert_eq!(hit(h, (150.0, 125.0))["id"], A);
    click(h, (150.0, 125.0), 0);
    assert_eq!(selection(h), [A], "the click went through to the board");
    // a marquee over it inside the board picks S only
    click(h, (1100.0, 700.0), 0);
    drag(h, (50.0, 50.0), (390.0, 390.0), 0);
    assert_eq!(selection(h), [S]);
    // from the layers panel it is selected, but never carried or nudged
    select(h, &[R]);
    assert_eq!(de_key(h, DE_KEY_RIGHT, 0), DE_OK);
    assert_eq!(selection(h), [R]);
    drag(h, (150.0, 125.0), (250.0, 125.0), 0);
    assert_eq!(rect(h, R), [100.0, 100.0, 200.0, 150.0]);
    assert_eq!(de_engine_free(h), DE_OK);
}

fn copy(h: u64, ids: &[&str]) -> Vec<u8> {
    let s = if ids.is_empty() {
        String::new()
    } else {
        json!(ids).to_string()
    };
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0usize;
    let r = unsafe { de_copy(h, s.as_ptr(), s.len(), buf.as_mut_ptr(), buf.len(), &mut n) };
    assert_eq!(r, DE_OK);
    buf.truncate(n);
    buf
}

fn paste(h: u64, clip: &[u8], parent: &str, at: Option<(f32, f32)>) -> i32 {
    let (x, y) = at.unwrap_or_default();
    unsafe {
        de_paste(
            h,
            clip.as_ptr(),
            clip.len(),
            parent.as_ptr(),
            parent.len(),
            x,
            y,
            at.is_some() as u32,
        )
    }
}

#[test]
fn copy_and_paste_make_fresh_copies_in_one_undo_step() {
    let h = engine();
    let clip = copy(h, &[A, R]);
    let v: Value = serde_json::from_slice(&clip).unwrap();
    assert_eq!(v["format"], "ainkrad-design/1");
    assert_eq!(v["nodes"].as_array().unwrap().len(), 1, "R goes with A");
    assert_eq!(v["nodes"][0]["children"].as_array().unwrap().len(), 2);
    assert!(
        !clip.windows(R.len()).any(|w| w == R.as_bytes()),
        "no ids in the clipboard"
    );
    // into another design, at a view point
    let h2 = new("dd_other");
    assert_eq!(
        edit(
            h2,
            json!([{"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"}])
        ),
        DE_OK
    );
    assert_eq!(paste(h2, &clip, "", Some((500.0, 20.0))), DE_OK);
    let sel = selection(h2);
    assert_eq!(sel.len(), 1);
    assert_eq!(rect(h2, &sel[0]), [500.0, 20.0, 900.0, 420.0]);
    assert_eq!(tree(h2).len(), 4, "page + the frame and its two rects");
    assert_eq!(de_undo(h2), 1);
    assert_eq!(tree(h2).len(), 1, "one undo step");
    // in place, into a frame: the world position is kept
    let rc = copy(h, &[R]);
    assert_eq!(paste(h, &rc, A, None), DE_OK);
    let p = selection(h)[0].clone();
    assert_ne!(p, R);
    assert_eq!(rect(h, &p), rect(h, R));
    // refused input writes nothing
    let n = tree(h).len();
    assert_eq!(
        paste(h, b"{\"format\":\"x\",\"nodes\":[]}", "", None),
        DE_ERR_INVALID
    );
    assert_eq!(
        paste(h, &rc, R, None),
        DE_ERR_INVALID,
        "a rect holds no children"
    );
    let page = json!({"format": "ainkrad-design/1", "nodes": [{"type": "page"}]}).to_string();
    assert_eq!(paste(h, page.as_bytes(), "", None), DE_ERR_INVALID);
    assert_eq!(tree(h).len(), n);
    for h in [h, h2] {
        assert_eq!(de_engine_free(h), DE_OK);
    }
}

#[test]
fn group_and_ungroup_keep_everything_in_place() {
    let h = engine();
    select(h, &[R, S]);
    assert_eq!(de_group(h), DE_OK);
    let g = selection(h)[0].clone();
    assert_eq!(row(h, &g)["type"], "frame");
    assert_eq!(row(h, &g)["parent"], A);
    assert_eq!(rect(h, &g), [100.0, 100.0, 300.0, 300.0]);
    assert_eq!(row(h, R)["parent"], json!(g));
    assert_eq!(rect(h, R), [100.0, 100.0, 200.0, 150.0]);
    assert_eq!(node(h, S)["props"]["x"], json!(150.0));
    assert_eq!(de_ungroup(h), DE_OK);
    assert_eq!(selection(h), [R, S]);
    assert!(tree(h).iter().all(|r| r["id"] != json!(g)));
    assert_eq!(row(h, S)["parent"], A);
    assert_eq!(rect(h, S), [250.0, 250.0, 300.0, 300.0]);
    assert_eq!(de_undo(h), 1);
    assert_eq!(de_undo(h), 1);
    assert_eq!(
        row(h, R)["parent"],
        A,
        "group and ungroup: one undo step each"
    );
    // not siblings: refused
    select(h, &[A, R]);
    assert_eq!(de_group(h), DE_OK, "R is inside A: only A is grouped");
    select(h, &[S]);
    assert_eq!(de_ungroup(h), DE_ERR_INVALID, "a rect is not a group");
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn components_create_insert_and_detach_with_overrides() {
    let h = engine();
    assert_eq!(
        edit(
            h,
            json!([{"op": "set", "id": R, "key": "fill", "value": [{"type": "solid", "color": "#ff0000"}]}])
        ),
        DE_OK
    );
    select(h, &[R]);
    assert_eq!(de_component_create(h), DE_OK);
    let c = selection(h)[0].clone();
    assert_eq!(row(h, &c)["type"], "component");
    assert_eq!(row(h, R)["parent"], json!(c));
    // an instance on the empty canvas, then an override on the component's rect
    assert_eq!(
        unsafe { de_instance_insert(h, c.as_ptr(), c.len(), 600.0, 50.0) },
        DE_OK
    );
    let i = selection(h)[0].clone();
    assert_eq!(row(h, &i)["parent"], PAGE);
    assert_eq!(
        node(h, &i)["props"]["component"],
        json!(format!("dd_tools/{c}"))
    );
    assert_eq!(
        rect(h, &i),
        [600.0, 50.0, 700.0, 100.0],
        "sized by its component"
    );
    let ov = json!({(R): {"fill": [{"type": "solid", "color": "#00ff00"}]}});
    assert_eq!(
        edit(
            h,
            json!([{"op": "set", "id": i, "key": "overrides", "value": ov}])
        ),
        DE_OK
    );
    assert_eq!(de_instance_detach(h), DE_OK);
    let f = selection(h)[0].clone();
    assert_eq!(row(h, &f)["type"], "frame");
    assert!(
        tree(h).iter().all(|r| r["id"] != json!(i)),
        "the instance is gone"
    );
    let kid = tree(h)
        .into_iter()
        .find(|r| r["parent"] == json!(f))
        .unwrap();
    assert_eq!(
        node(h, kid["id"].as_str().unwrap())["props"]["fill"][0]["color"],
        "#00ff00"
    );
    assert_eq!(
        rect(h, &f),
        [600.0, 50.0, 700.0, 100.0],
        "in the instance's place"
    );
    // refusals
    let bad = "n_zzzzzzzzzzzz";
    assert_eq!(
        unsafe { de_instance_insert(h, bad.as_ptr(), bad.len(), 0.0, 0.0) },
        DE_ERR_INVALID
    );
    assert_eq!(
        de_instance_detach(h),
        DE_ERR_INVALID,
        "a frame is no instance"
    );
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn a_remote_ai_frame_is_removed_as_a_local_edit_and_undo_brings_it_back() {
    // the Core applies an AI session's frame with a remote origin: on this device it arrives through sync
    let ai = new("dd_tools");
    assert_eq!(
        edit(
            ai,
            json!([
                {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
                {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a", "props": {"w": 10, "h": 10}},
            ])
        ),
        DE_OK
    );
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0usize;
    unsafe {
        assert_eq!(
            de_sync_outbox(ai, buf.as_mut_ptr(), buf.len(), &mut n),
            DE_OK
        )
    };
    let h = new("dd_tools");
    unsafe { assert_eq!(de_sync_apply(h, DE_DOC, buf.as_ptr(), n), DE_OK) };
    assert_eq!(tree(h).len(), 2);
    assert_eq!(de_undo(h), 0, "a remote frame is not this device's to undo");
    assert_eq!(edit(h, json!([{"op": "delete", "id": A}])), DE_OK);
    assert_eq!(tree(h).len(), 1);
    unsafe {
        assert_eq!(
            de_sync_outbox(h, buf.as_mut_ptr(), buf.len(), &mut n),
            DE_OK
        )
    };
    assert!(n > 0, "the delete goes out like any local edit");
    assert_eq!(de_undo(h), 1);
    assert_eq!(tree(h).len(), 2, "undo brings the frame back");
    for h in [h, ai] {
        assert_eq!(de_engine_free(h), DE_OK);
    }
}
