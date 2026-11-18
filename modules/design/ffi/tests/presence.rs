//! V2-06 through the C ABI: one engine's presence reaches another as cursor, selection and viewport markers; follow
//! moves the camera and ends when the viewer takes it back; hostile messages change nothing.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use design_ffi::testing;
use serde_json::{Value, json};

const PAGE: &str = "n_pppppppppppp";
const A: &str = "n_aaaaaaaaaaaa";
const R: &str = "n_rrrrrrrrrrrr";

fn engine() -> u64 {
    let mut h = 0u64;
    let id = b"dd_presence";
    let ops = json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a", "props": {"x": 0, "y": 0, "w": 400, "h": 400}},
        {"op": "add", "id": R, "type": "rect", "parent": A, "order": "a", "props": {"x": 10, "y": 10, "w": 50, "h": 50}},
    ])
    .to_string();
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut h), DE_OK);
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
    }
    assert_eq!(de_resize(h, 800.0, 400.0, 1.0), DE_OK);
    h
}

fn remote(h: u64, m: &Value) -> i32 {
    let s = m.to_string();
    unsafe { de_presence_remote(h, s.as_ptr(), s.len()) }
}

fn local(h: u64) -> Option<Value> {
    let mut buf = vec![0u8; 1 << 14];
    let mut n = 0usize;
    assert_eq!(
        unsafe { de_presence_local(h, buf.as_mut_ptr(), buf.len(), &mut n) },
        DE_OK
    );
    (n > 0).then(|| serde_json::from_slice(&buf[..n]).unwrap())
}

fn list(h: u64) -> Value {
    let mut buf = vec![0u8; 1 << 14];
    let mut n = 0usize;
    assert_eq!(
        unsafe { de_presence_list(h, buf.as_mut_ptr(), buf.len(), &mut n) },
        DE_OK
    );
    serde_json::from_slice(&buf[..n]).unwrap()
}

fn follow(h: u64, peer: &str) -> i32 {
    unsafe { de_follow(h, peer.as_ptr(), peer.len()) }
}

#[test]
fn own_presence_is_sent_once_per_change() {
    let h = engine();
    let first = local(h).expect("a first state");
    assert_eq!(first["cursor"], Value::Null);
    assert!(local(h).is_none(), "unchanged: nothing to send");
    de_pointer(h, DE_POINTER_MOVE, 100.0, 50.0, 0);
    let s = local(h).unwrap();
    assert_eq!(s["cursor"], json!([100.0, 50.0]));
    assert_eq!(s["view"], json!([0.0, 0.0, 800.0, 400.0]));
    de_pointer(h, DE_POINTER_DOWN, 20.0, 20.0, 0);
    de_pointer(h, DE_POINTER_UP, 20.0, 20.0, 0);
    assert_eq!(local(h).unwrap()["selection"].as_array().unwrap().len(), 1);
    // a buffer too small leaves it pending
    de_pointer(h, DE_POINTER_MOVE, 5.0, 5.0, 0);
    let mut n = 0usize;
    let mut tiny = [0u8; 4];
    assert_eq!(
        unsafe { de_presence_local(h, tiny.as_mut_ptr(), tiny.len(), &mut n) },
        DE_ERR_SMALL_BUFFER
    );
    assert!(local(h).is_some(), "not consumed by the failed call");
    de_engine_free(h);
}

#[test]
fn peers_show_as_markers_and_expire_with_gone() {
    let h = engine();
    let person = json!({"peer": "person:d_ana", "conn": 1, "label": "Ana", "cursor": [30, 40], "selection": [R]});
    let ai = json!({"peer": "session:as_c1", "conn": 2, "label": "Claude", "selection": [A, "n_gonegonegone"]});
    assert_eq!((remote(h, &person), remote(h, &ai)), (DE_OK, DE_OK));
    let marks = testing::peer_marks(h);
    assert_eq!(marks.len(), 2);
    assert_eq!(
        (marks[0].0.as_str(), marks[0].1, marks[0].2, marks[0].3),
        ("Ana", false, Some((30.0, 40.0)), 1)
    );
    assert_eq!(
        (marks[1].0.as_str(), marks[1].1, marks[1].3),
        ("Claude", true, 1),
        "a node that does not exist has no outline"
    );
    let l = list(h);
    assert_eq!((&l[0]["kind"], &l[1]["kind"]), (&json!("person"), &json!("ai")));
    // the peer's selection follows the node when it is gone from the document
    let del = json!([{"op": "delete", "id": R}]).to_string();
    unsafe { de_edit(h, del.as_ptr(), del.len()) };
    assert_eq!(testing::peer_marks(h)[0].3, 0);
    assert_eq!(remote(h, &json!({"conn": 1, "gone": true})), DE_OK);
    assert_eq!(testing::peer_marks(h).len(), 1);
    de_engine_free(h);
}

#[test]
fn follow_moves_the_camera_and_the_viewer_ends_it() {
    let h = engine();
    assert_eq!(follow(h, "person:d_ana"), DE_ERR_ARG, "nobody to follow");
    let p = |view: Value| json!({"peer": "person:d_ana", "conn": 1, "label": "Ana", "view": view});
    assert_eq!(remote(h, &p(json!([100, 100, 400, 200]))), DE_OK);
    assert_eq!(follow(h, "person:d_ana"), DE_OK);
    let (z, px, py) = testing::camera(h).unwrap();
    assert!((z - 2.0).abs() < 1e-3);
    assert!((300.0 * z + px - 400.0).abs() < 1e-2 && (200.0 * z + py - 200.0).abs() < 1e-2);
    assert_eq!(list(h)[0]["following"], json!(true));
    // the peer moves: the camera goes along
    assert_eq!(remote(h, &p(json!([500, 0, 800, 400]))), DE_OK);
    let (z, px, _) = testing::camera(h).unwrap();
    assert!((z - 1.0).abs() < 1e-3 && (900.0 * z + px - 400.0).abs() < 1e-2);
    // the viewer pans: following ends, the next peer move leaves the camera alone
    assert_eq!(de_scroll(h, 10.0, 0.0), DE_OK);
    assert_eq!(list(h)[0]["following"], json!(false));
    let at = testing::camera(h).unwrap();
    assert_eq!(remote(h, &p(json!([0, 0, 100, 100]))), DE_OK);
    assert_eq!(testing::camera(h).unwrap(), at);
    // follow again, then a press on the canvas ends it too
    assert_eq!(follow(h, "person:d_ana"), DE_OK);
    de_pointer(h, DE_POINTER_DOWN, 10.0, 10.0, 0);
    assert_eq!(list(h)[0]["following"], json!(false));
    de_pointer(h, DE_POINTER_UP, 10.0, 10.0, 0);
    assert_eq!(follow(h, ""), DE_OK);
    de_engine_free(h);
}

#[test]
fn hostile_messages_change_nothing() {
    let h = engine();
    let bad = [
        json!({"peer": "person:d_x", "conn": 1, "cursor": [1e300, 0]}),
        json!({"peer": "root", "conn": 1}),
        json!({"peer": "person:d_x", "conn": 1, "selection": ["nope"]}),
        json!({"peer": "person:d_x", "conn": 1, "view": [0, 0, 0, 0]}),
        json!({"peer": "person:d_x"}),
    ];
    for m in &bad {
        assert_eq!(remote(h, m), DE_ERR_INVALID, "{m}");
    }
    for junk in [&b"\xff\xfe"[..], b"{", b"[]", b"null"] {
        let rc = unsafe { de_presence_remote(h, junk.as_ptr(), junk.len()) };
        assert!(rc == DE_ERR_ARG || rc == DE_ERR_INVALID, "{rc}");
    }
    let big = vec![b' '; 5000];
    assert_eq!(
        unsafe { de_presence_remote(h, big.as_ptr(), big.len()) },
        DE_ERR_TOO_LARGE
    );
    assert!(testing::peer_marks(h).is_empty());
    assert_eq!(unsafe { de_presence_remote(0, std::ptr::null(), 3) }, DE_ERR_HANDLE);
    assert_eq!(unsafe { de_presence_remote(h, std::ptr::null(), 3) }, DE_ERR_ARG);
    assert_eq!(unsafe { de_follow(h, std::ptr::null(), 3) }, DE_ERR_ARG);
    de_engine_free(h);
}
