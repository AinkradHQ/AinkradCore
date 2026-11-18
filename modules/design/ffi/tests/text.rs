//! V2-04 acceptance through the C ABI: an editing session (typing, undo, IME composition, commands, pointer),
//! its sync to a second engine, and the argument checks of the new calls.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use serde_json::Value;

const TEXT: &str = "n_cccccccccccc";

fn get(f: impl Fn(*mut u8, usize, *mut usize) -> i32) -> Value {
    let mut n = 0usize;
    let mut buf = vec![0u8; 1 << 16];
    assert_eq!(f(buf.as_mut_ptr(), buf.len(), &mut n), DE_OK);
    serde_json::from_slice(&buf[..n]).unwrap()
}

fn state(h: u64) -> Value {
    get(|o, c, l| unsafe { de_text_state(h, o, c, l) })
}

fn node_text(h: u64) -> String {
    let v = get(|o, c, l| unsafe { de_node(h, TEXT.as_ptr(), TEXT.len(), o, c, l) });
    v["text"].as_str().unwrap_or_default().to_string()
}

fn insert(h: u64, s: &str) -> i32 {
    unsafe { de_text_insert(h, s.as_ptr(), s.len(), DE_TEXT_NO_RANGE, 0) }
}

fn engine() -> u64 {
    let id = b"dd_text";
    let mut h = 0u64;
    let ops = br##"[
      {"op":"add","id":"n_aaaaaaaaaaaa","type":"page","parent":null,"order":"a"},
      {"op":"add","id":"n_bbbbbbbbbbbb","type":"frame","parent":"n_aaaaaaaaaaaa","order":"a",
       "props":{"w":400,"h":200,"fill":[{"type":"solid","color":"#ffffff"}]}},
      {"op":"add","id":"n_cccccccccccc","type":"text","parent":"n_bbbbbbbbbbbb","order":"a","text":"hello",
       "props":{"x":20,"y":20,"type":{"font":"system","size":20,"weight":400}}}]"##;
    let font = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../render/tests/fonts/Roboto-Regular.ttf"
    ))
    .unwrap();
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut h), DE_OK);
        assert_eq!(
            de_font_add(h, std::ptr::null(), 0, font.as_ptr(), font.len()),
            DE_OK
        );
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
    }
    assert_eq!(de_resize(h, 800.0, 600.0, 1.0), DE_OK);
    h
}

fn drain(h: u64) -> Vec<u8> {
    let mut out = vec![0u8; 1 << 16];
    let mut n = 0usize;
    assert_eq!(
        unsafe { de_sync_outbox(h, out.as_mut_ptr(), out.len(), &mut n) },
        DE_OK
    );
    out.truncate(n);
    out
}

#[test]
fn an_editing_session_through_the_abi() {
    let (a, b) = (engine(), engine());
    // b starts from a's state
    let full = drain(a);
    let _ = drain(b);
    let b2 = {
        let id = b"dd_text";
        let mut h = 0u64;
        assert_eq!(
            unsafe { de_engine_new(id.as_ptr(), id.len(), &mut h) },
            DE_OK
        );
        assert_eq!(
            unsafe { de_sync_apply(h, DE_DOC, full.as_ptr(), full.len()) },
            DE_OK
        );
        h
    };
    assert_eq!(de_engine_free(b), DE_OK);

    assert_eq!(
        de_text_begin(a, 300.0, 150.0),
        DE_ERR_INVALID,
        "the frame, not text"
    );
    assert_eq!(state(a), Value::Null);
    assert_eq!(de_text_begin(a, 22.0, 30.0), DE_OK);
    assert_eq!(state(a)["id"], TEXT);
    assert_eq!(state(a)["selection"], serde_json::json!([0, 0]));
    assert_eq!(de_text_command(a, DE_TEXT_RIGHT, DE_MOD_COMMAND), DE_OK);
    assert_eq!(state(a)["selection"], serde_json::json!([5, 0]), "line end");

    // typing: one batch per key, one undo step for the run
    for c in [" ", "w", "ö", "r", "l", "d"] {
        assert_eq!(insert(a, c), DE_OK);
    }
    assert_eq!(node_text(a), "hello wörld");
    assert_eq!(state(a)["selection"], serde_json::json!([11, 0]));
    assert_eq!(de_undo(a), 1);
    assert_eq!(node_text(a), "hello", "the typed run undoes at once");
    assert_eq!(
        state(a)["selection"],
        serde_json::json!([5, 0]),
        "the caret follows"
    );
    assert_eq!(de_redo(a), 1);
    assert_eq!(node_text(a), "hello wörld");
    assert_eq!(de_text_command(a, DE_TEXT_DOWN, DE_MOD_COMMAND), DE_OK);
    let u = drain(a);
    assert_eq!(
        unsafe { de_sync_apply(b2, DE_DOC, u.as_ptr(), u.len()) },
        DE_OK
    );

    // an IME composition stays local until committed
    let m = "にほん";
    assert_eq!(
        unsafe { de_text_set_marked(a, m.as_ptr(), m.len(), 3, 0, DE_TEXT_NO_RANGE, 0) },
        DE_OK
    );
    let st = state(a);
    assert_eq!(st["text"], "hello wörldにほん");
    assert_eq!(st["marked"], serde_json::json!([11, 3]));
    assert_eq!(st["selection"], serde_json::json!([14, 0]));
    assert_eq!(node_text(a), "hello wörld", "not in the document");
    assert!(drain(a).is_empty(), "nothing to send");
    assert_eq!(
        design_ffi::testing::draw_cpu(a, 64, 64),
        1,
        "the preview draws"
    );
    let fr = get(|o, c, l| unsafe { de_text_first_rect(a, 11, 3, o, c, l) });
    let r: Vec<f64> = serde_json::from_value(fr["rect"].clone()).unwrap();
    assert!(
        r[0] > 20.0 && r[1] >= 15.0 && r[1] < 40.0 && r[2] > 20.0 && r[3] >= 20.0,
        "{fr}"
    );
    assert_eq!(fr["range"], serde_json::json!([11, 3]));
    assert_eq!(insert(a, "日本"), DE_OK);
    assert_eq!(node_text(a), "hello wörld日本");
    assert_eq!(state(a)["marked"], Value::Null);
    let u = drain(a);
    assert!(!u.is_empty());
    assert_eq!(
        unsafe { de_sync_apply(b2, DE_DOC, u.as_ptr(), u.len()) },
        DE_OK
    );
    assert_eq!(
        node_text(b2),
        "hello wörld日本",
        "the peer gets the committed text only"
    );

    // the caret hits back where it is drawn
    let c = get(|o, cap, l| unsafe { de_text_first_rect(a, 13, 0, o, cap, l) });
    let r: Vec<f32> = serde_json::from_value(c["rect"].clone()).unwrap();
    assert_eq!(de_text_index_at(a, r[0] + 0.3, r[1] + r[3] / 2.0), 13);

    // an emoji sequence deletes as one; Delete as a key never removes the node being edited
    assert_eq!(insert(a, "👩‍💻"), DE_OK);
    assert_eq!(de_text_command(a, DE_TEXT_DELETE_BACK, 0), DE_OK);
    assert_eq!(node_text(a), "hello wörld日本");
    assert_eq!(de_key(a, DE_KEY_DELETE, 0), DE_OK);
    assert_eq!(node_text(a), "hello wörld日本");
    assert_eq!(de_text_command(a, DE_TEXT_SELECT_ALL, 0), DE_OK);
    assert_eq!(de_text_command(a, DE_TEXT_LEFT, DE_MOD_SHIFT), DE_OK);
    assert_eq!(state(a)["selection"], serde_json::json!([0, 12]));
    assert_eq!(de_text_command(a, DE_TEXT_NEWLINE, 0), DE_OK);
    assert_eq!(node_text(a), "\n本");

    // refused: formatting characters, bad ranges and pointers, bad UTF-8, unknown commands
    let rlo = "\u{202E}";
    assert_eq!(insert(a, rlo), DE_ERR_INVALID);
    assert_eq!(
        unsafe { de_text_insert(a, b"x".as_ptr(), 1, -5, 0) },
        DE_ERR_ARG
    );
    assert_eq!(
        unsafe { de_text_insert(a, b"x".as_ptr(), 1, 0, i64::MAX) },
        DE_ERR_ARG
    );
    assert_eq!(
        unsafe { de_text_insert(a, std::ptr::null(), 3, -1, 0) },
        DE_ERR_ARG
    );
    assert_eq!(
        unsafe { de_text_insert(a, [0xffu8].as_ptr(), 1, -1, 0) },
        DE_ERR_ARG
    );
    assert_eq!(
        unsafe { de_text_insert(a, b"x".as_ptr(), 1, 999, 5) },
        DE_OK,
        "clamped to the end"
    );
    assert_eq!(node_text(a), "\n本x");
    assert_eq!(de_text_command(a, 99, 0), DE_ERR_ARG);
    assert_eq!(de_text_index_at(a, f32::NAN, 0.0), DE_ERR_ARG);

    // a press outside the text ends editing; then the text calls refuse
    assert_eq!(de_pointer(a, DE_POINTER_DOWN, 700.0, 500.0, 0), DE_OK);
    assert_eq!(de_pointer(a, DE_POINTER_UP, 700.0, 500.0, 0), DE_OK);
    assert_eq!(state(a), Value::Null);
    assert_eq!(insert(a, "x"), DE_ERR_INVALID);
    assert_eq!(de_text_index_at(a, 10.0, 10.0), DE_ERR_INVALID);
    assert_eq!(de_text_end(a), DE_OK);
    for h in [a, b2] {
        assert_eq!(de_engine_free(h), DE_OK);
    }
    assert_eq!(de_text_begin(a, 0.0, 0.0), DE_ERR_HANDLE);
}

#[test]
fn someone_else_typing_in_the_same_label_keeps_the_caret_on_its_characters() {
    let (a, b) = (engine(), engine());
    let full = drain(a);
    let _ = drain(b);
    assert_eq!(de_engine_free(b), DE_OK);
    let id = b"dd_text";
    let mut b = 0u64;
    assert_eq!(
        unsafe { de_engine_new(id.as_ptr(), id.len(), &mut b) },
        DE_OK
    );
    assert_eq!(
        unsafe { de_sync_apply(b, DE_DOC, full.as_ptr(), full.len()) },
        DE_OK
    );
    assert_eq!(de_resize(b, 800.0, 600.0, 1.0), DE_OK);
    assert_eq!(de_text_begin(a, 22.0, 30.0), DE_OK);
    assert_eq!(de_text_command(a, DE_TEXT_RIGHT, DE_MOD_COMMAND), DE_OK); // a: hello|
    assert_eq!(de_text_begin(b, 22.0, 30.0), DE_OK); // b: |hello
    assert_eq!(insert(b, ">> "), DE_OK);
    let u = drain(b);
    assert_eq!(
        unsafe { de_sync_apply(a, DE_DOC, u.as_ptr(), u.len()) },
        DE_OK
    );
    assert_eq!(insert(a, "!"), DE_OK);
    assert_eq!(node_text(a), ">> hello!");
    let u = drain(a);
    assert_eq!(
        unsafe { de_sync_apply(b, DE_DOC, u.as_ptr(), u.len()) },
        DE_OK
    );
    assert_eq!(node_text(b), ">> hello!");
    assert_eq!(state(b)["selection"], serde_json::json!([3, 0]));
    for h in [a, b] {
        assert_eq!(de_engine_free(h), DE_OK);
    }
}
