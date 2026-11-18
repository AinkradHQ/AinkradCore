//! V2-04: text-editing geometry on Skia paragraph (caret, hit position, selection rects), font fallback, and
//! missing library fonts reported to the host.

mod common;

use common::*;
use design_model::Theme;
use serde_json::json;

const SIZE: f32 = 20.0;

/// One text node alone on the page (id_of(2)), its renderer.
fn one(s: &str) -> design_render::Renderer {
    let (r, _) = load(&tree(page(vec![text(s, SIZE, json!({}))])), Theme::Day);
    r
}

#[test]
fn carets_advance_with_the_text_and_hit_back_to_their_offset() {
    let r = one("hello");
    let g = r.text_geo(&id_of(2)).expect("geometry");
    let xs: Vec<f32> = (0..=5)
        .map(|k| g.caret(k.max(1) - 1, k, (k + 1).min(5), false).left)
        .collect();
    assert!(xs.windows(2).all(|w| w[1] > w[0]), "{xs:?}");
    assert!(xs[0].abs() < 0.5, "starts at the box's left: {xs:?}");
    for k in 0..=5 {
        let c = g.caret(k.max(1) - 1, k, (k + 1).min(5), false);
        assert!(c.height() >= SIZE, "a line tall: {c:?}");
        assert_eq!(
            g.index_at(c.left + 0.3, c.center_y()),
            k,
            "hit at caret {k}"
        );
    }
    let sel = g.ranges(1, 4);
    assert_eq!(sel.len(), 1);
    assert!((sel[0].left - xs[1]).abs() < 0.5 && (sel[0].right - xs[4]).abs() < 0.5);
    assert!(g.ranges(3, 3).is_empty());
}

#[test]
fn a_newline_puts_the_caret_on_the_next_line() {
    let r = one("ab\ncd\n");
    let g = r.text_geo(&id_of(2)).unwrap();
    let first = g.caret(0, 0, 1, false);
    let after_nl = g.caret(2, 3, 4, true);
    assert!(
        after_nl.top > first.top + SIZE * 0.8,
        "{first:?} {after_nl:?}"
    );
    assert!(after_nl.left.abs() < 0.5, "line start");
    let end = g.caret(5, 6, 6, true);
    assert!(
        end.top > after_nl.top + SIZE * 0.8,
        "the empty last line: {end:?}"
    );
    // the first-line rect of a range across lines stays on the first line
    let fr = g.first_rect(0, 1, 5, false);
    assert!((fr.top - first.top).abs() < 0.5, "{fr:?}");
}

/// Font fallback: the Roboto test face has no CJK, emoji or Arabic; the platform's faces draw them. Linux runners
/// depend on the fonts installed there, so this runs on the Mac.
#[cfg(target_os = "macos")]
#[test]
fn cjk_emoji_and_arabic_fall_back_to_a_face_that_has_them() {
    let f = fonts();
    assert_eq!(f.unresolved("Hello"), 0);
    assert_eq!(f.unresolved("日本語 한국어 中文 👩‍💻 😀 مرحبا שלום"), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn rtl_carets_run_right_to_left() {
    let s = "مرحبا";
    let r = one(s);
    let g = r.text_geo(&id_of(2)).unwrap();
    let start = g.caret(0, 0, 1, false);
    let end = g.caret(4, 5, 5, false);
    assert!(
        start.left > end.left + 10.0,
        "logical start on the right: {start:?} {end:?}"
    );
}

#[test]
fn a_library_font_the_host_lacks_is_reported_missing() {
    let hash = "ab".repeat(32);
    let doc = tree(page(vec![text(
        "x",
        12.0,
        json!({"font": {"asset": hash}}),
    )]));
    let (r, _) = load(&doc, Theme::Day);
    assert!(r.missing.contains(&hash), "{:?}", r.missing);
}
