//! V2-02 acceptance: the C ABI under random calls and one end-to-end
//! session through it: edit, sync to a second engine, query, hit test.
#![allow(unsafe_code)]

#[path = "../fuzz/abi_program.rs"]
mod program;

use design_ffi::ffi::*;

/// xorshift: a deterministic stream of program bytes.
fn stream(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn random_calls() {
    for seed in 0..300 {
        program::run(&stream(seed, 4000));
    }
}

/// Inputs the fuzz target once crashed on (`fuzz/regressions/`), replayed on every test run.
#[test]
fn fuzz_regressions() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions");
    for f in std::fs::read_dir(dir).unwrap() {
        program::run(&std::fs::read(f.unwrap().path()).unwrap());
    }
}

fn get(f: impl Fn(*mut u8, usize, *mut usize) -> i32) -> Vec<u8> {
    let mut n = 0usize;
    assert_eq!(
        f(std::ptr::null_mut(), 0, &mut n),
        if n == 0 { DE_OK } else { DE_ERR_SMALL_BUFFER }
    );
    let mut buf = vec![0u8; n];
    assert_eq!(f(buf.as_mut_ptr(), buf.len(), &mut n), DE_OK);
    buf
}

fn gets(f: impl Fn(*mut u8, usize, *mut usize) -> i32) -> String {
    String::from_utf8(get(f)).unwrap()
}

#[test]
fn a_session_through_the_abi() {
    let id = b"dd_session";
    let (mut a, mut b) = (0u64, 0u64);
    let ops = br##"[
      {"op":"add","id":"n_aaaaaaaaaaaa","type":"page","parent":null,"order":"a"},
      {"op":"add","id":"n_bbbbbbbbbbbb","type":"frame","parent":"n_aaaaaaaaaaaa","order":"a",
       "props":{"w":300,"h":200,"fill":[{"type":"solid","color":"#336699"}]}}]"##;
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut a), DE_OK);
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut b), DE_OK);
        assert_eq!(de_engine_new(b"nope".as_ptr(), 4, &mut b), DE_ERR_INVALID);
        assert_eq!(de_edit(a, ops.as_ptr(), ops.len()), DE_OK);
        assert_eq!(de_edit(a, b"[{".as_ptr(), 2), DE_ERR_INVALID);
        assert_eq!(de_edit(a, std::ptr::null(), 5), DE_ERR_ARG);
        // relay A's edits to B
        assert!(!get(|o, c, l| de_sync_outbox(a, o, c, l)).is_empty());
        let mut n = 0usize;
        assert_eq!(
            de_sync_outbox(a, std::ptr::null_mut(), 0, &mut n),
            DE_OK,
            "drained"
        );
        assert_eq!(n, 0);
        let mut sv = vec![0u8; 256];
        assert_eq!(
            de_sync_state_vector(b, sv.as_mut_ptr(), sv.len(), &mut n),
            DE_OK
        );
        sv.truncate(n);
        let mut full = vec![0u8; 1 << 16];
        assert_eq!(
            de_sync_diff(
                a,
                sv.as_ptr(),
                sv.len(),
                full.as_mut_ptr(),
                full.len(),
                &mut n
            ),
            DE_OK
        );
        assert_eq!(de_sync_apply(b, DE_DOC, full.as_ptr(), n), DE_OK);
        let node = gets(|o, c, l| de_node(b, b"n_bbbbbbbbbbbb".as_ptr(), 14, o, c, l));
        let v: serde_json::Value = serde_json::from_str(&node).unwrap();
        assert_eq!(v["props"]["w"], 300);
        assert_eq!(
            gets(|o, c, l| de_node(b, b"n_zzzzzzzzzzzz".as_ptr(), 14, o, c, l)),
            "null"
        );
        assert_eq!(de_undo(a), 1);
        assert_eq!(
            gets(|o, c, l| de_node(a, b"n_bbbbbbbbbbbb".as_ptr(), 14, o, c, l)),
            "null"
        );
        assert_eq!(de_redo(a), 1);
    }
    assert_eq!(de_resize(a, f32::NAN, 10.0, 2.0), DE_ERR_ARG);
    assert_eq!(de_resize(a, 800.0, 600.0, 2.0), DE_OK);
    assert_eq!(de_scroll(a, f32::INFINITY, 0.0), DE_ERR_ARG);
    assert_eq!(de_magnify(a, -1.0, 0.0, 0.0), DE_ERR_ARG);
    // the frame sits at world 0,0 300x200 with an identity camera: (50, 50) hits it, selects it, Delete removes it
    let hit = gets(|o, c, l| unsafe { de_hit(a, 50.0, 50.0, o, c, l) });
    assert!(hit.contains("n_bbbbbbbbbbbb"), "{hit}");
    assert_eq!(de_needs_frame(a), 1);
    assert_eq!(design_ffi::testing::draw_cpu(a, 64, 64), 1);
    assert_eq!(de_pointer(a, DE_POINTER_DOWN, 50.0, 50.0, 0), DE_OK);
    assert_eq!(
        gets(|o, c, l| unsafe { de_selection(a, o, c, l) }),
        r#"["n_bbbbbbbbbbbb"]"#
    );
    // V2-07: the tree, select by id, tokens
    let tree = gets(|o, c, l| unsafe { de_tree(a, o, c, l) });
    assert!(tree.contains(r#""id":"n_bbbbbbbbbbbb""#) && tree.contains(r#""parent":"n_aaaaaaaaaaaa""#));
    assert_eq!(gets(|o, c, l| unsafe { de_tokens(a, o, c, l) }), "[]");
    assert_eq!(unsafe { de_select(a, b"[]".as_ptr(), 2) }, DE_OK);
    assert_eq!(gets(|o, c, l| unsafe { de_selection(a, o, c, l) }), "[]");
    let one = br#"["n_bbbbbbbbbbbb","n_bbbbbbbbbbbb"]"#;
    assert_eq!(unsafe { de_select(a, one.as_ptr(), one.len()) }, DE_OK);
    assert_eq!(
        gets(|o, c, l| unsafe { de_selection(a, o, c, l) }),
        r#"["n_bbbbbbbbbbbb"]"#
    );
    let bad = br#"["n_zzzzzzzzzzzz"]"#;
    assert_eq!(unsafe { de_select(a, bad.as_ptr(), bad.len()) }, DE_ERR_INVALID);
    assert_eq!(unsafe { de_select(a, std::ptr::null(), 5) }, DE_ERR_ARG);
    assert_eq!(unsafe { de_select(a, b"{".as_ptr(), 1) }, DE_ERR_INVALID);
    assert_eq!(unsafe { de_select(0, b"[]".as_ptr(), 2) }, DE_ERR_HANDLE);
    assert_eq!(
        unsafe { de_tree(a, std::ptr::null_mut(), 0, std::ptr::null_mut()) },
        DE_ERR_ARG
    );
    assert_eq!(de_key(a, DE_KEY_DELETE, 0), DE_OK);
    assert_eq!(gets(|o, c, l| unsafe { de_selection(a, o, c, l) }), "[]");
    assert_eq!(
        unsafe { de_draw_metal(a, std::ptr::null_mut()) },
        DE_ERR_ARG
    );
    assert_eq!(de_engine_free(a), DE_OK);
    assert_eq!(de_engine_free(b), DE_OK);
    assert_eq!(de_undo(a), DE_ERR_HANDLE);
}
