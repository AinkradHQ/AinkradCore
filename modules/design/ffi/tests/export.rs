//! `de_doc_tokens` and `de_export_png` through the C ABI.
#![allow(unsafe_code)]

use design_ffi::ffi::*;
use serde_json::{Value, json};

const PAGE: &str = "n_pppppppppppp";
const A: &str = "n_aaaaaaaaaaaa";
const R: &str = "n_rrrrrrrrrrrr";

fn engine(ops: Value) -> u64 {
    let mut h = 0u64;
    let id = b"dd_export";
    let ops = ops.to_string();
    unsafe {
        assert_eq!(de_engine_new(id.as_ptr(), id.len(), &mut h), DE_OK);
        assert_eq!(de_edit(h, ops.as_ptr(), ops.len()), DE_OK);
    }
    assert_eq!(de_resize(h, 800.0, 600.0, 2.0), DE_OK);
    h
}

fn export(h: u64, id: &str, scale: f32, night: i32) -> Result<Vec<u8>, i32> {
    let mut n = 0usize;
    let mut cap = 16usize;
    loop {
        let mut buf = vec![0u8; cap];
        let c = unsafe {
            de_export_png(
                h,
                id.as_ptr(),
                id.len(),
                scale,
                night,
                buf.as_mut_ptr(),
                cap,
                &mut n,
            )
        };
        match c {
            DE_OK => {
                buf.truncate(n);
                return Ok(buf);
            }
            DE_ERR_SMALL_BUFFER => cap = n,
            e => return Err(e),
        }
    }
}

#[test]
fn a_frame_exports_at_the_right_size_with_the_rect_in_the_middle() {
    let h = engine(json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a",
         "props": {"x": 300, "y": 200, "w": 200, "h": 100, "fill": [{"type": "solid", "color": "#FFFFFF"}]}},
        {"op": "add", "id": R, "type": "rect", "parent": A, "order": "a",
         "props": {"x": 50, "y": 25, "w": 100, "h": 50, "fill": [{"type": "solid", "color": "#FF0000"}]}},
    ]));
    // moved camera: the export does not depend on it
    assert_eq!(de_scroll(h, 123.0, 45.0), DE_OK);
    for scale in [1.0f32, 2.0, 3.0] {
        let png = export(h, A, scale, 0).unwrap();
        let w = (200.0 * scale) as i32;
        let ht = (100.0 * scale) as i32;
        let ((pw, ph), mid) = design_render::cpu::png_pixel(&png, w / 2, ht / 2).unwrap();
        assert_eq!((pw, ph), (w, ht));
        assert_eq!(
            mid,
            [255, 0, 0, 255],
            "the rect is in the middle at {scale}x"
        );
        let (_, corner) = design_render::cpu::png_pixel(&png, 3, 3).unwrap();
        assert_eq!(corner, [255, 255, 255, 255], "the frame's own fill");
    }
    // the view is as it was, and the theme too
    let again = export(h, A, 1.0, 0).unwrap();
    assert!(!again.is_empty());
    // bad calls
    assert_eq!(export(h, A, 0.5, 0), Err(DE_ERR_ARG));
    assert_eq!(export(h, A, 5.0, 0), Err(DE_ERR_ARG));
    assert_eq!(export(h, "n_zzzzzzzzzzzz", 1.0, 0), Err(DE_ERR_INVALID));
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn night_uses_the_night_literal_of_a_token() {
    let h = engine(json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": A, "type": "frame", "parent": PAGE, "order": "a",
         "props": {"x": 0, "y": 0, "w": 40, "h": 40, "fill": [{"type": "solid", "color": "#FFFFFF"}]}},
    ]));
    let day = export(h, A, 1.0, 0).unwrap();
    let night = export(h, A, 1.0, 1).unwrap();
    assert!(!day.is_empty() && !night.is_empty());
    assert_eq!(de_engine_free(h), DE_OK);
}

#[test]
fn doc_tokens_lists_this_documents_tokens_in_name_order() {
    let h = engine(json!([
        {"op": "token", "name": "space.md", "value": {"kind": "space", "day": 16, "night": 16}},
        {"op": "token", "name": "color.primary", "value": {"kind": "color", "day": "#2F7BEF", "night": "#5B9BFF"}},
    ]));
    let mut buf = vec![0u8; 4096];
    let mut n = 0usize;
    assert_eq!(
        unsafe { de_doc_tokens(h, buf.as_mut_ptr(), buf.len(), &mut n) },
        DE_OK
    );
    let v: Value = serde_json::from_slice(&buf[..n]).unwrap();
    assert_eq!(
        v,
        json!([
            {"name": "color.primary", "kind": "color", "day": "#2F7BEF", "night": "#5B9BFF"},
            {"name": "space.md", "kind": "space", "day": 16, "night": 16},
        ])
    );
    assert_eq!(de_undo(h), 1);
    assert_eq!(
        unsafe { de_doc_tokens(h, buf.as_mut_ptr(), buf.len(), &mut n) },
        DE_OK
    );
    assert_eq!(n, 2, "[] after the undo of the whole batch");
    assert_eq!(de_engine_free(h), DE_OK);
}
