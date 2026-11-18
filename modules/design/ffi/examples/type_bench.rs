//! V2-04 frame-cost check: typing into a label of the spike-sized scene (50 screens, ~5 600 nodes) through the C
//! ABI, against the T5 frame budget (p99 <= 8.3 ms from key to a finished frame).
//!
//!   cargo run --release -p design-ffi --features metal --example type_bench -- [--metal] [--scale 2]
//!
//! Measured per keystroke: `de_text_insert` (splice op, validation, yrs write, patch + re-layout of the one board)
//! plus one full frame; the same for IME marked-text updates (`de_text_set_marked`: preview only) and ⌫.
//! Exits 1 when a budget is missed.
#![allow(unsafe_code)]

use std::time::Instant;

use design_ffi::ffi::*;
use design_ffi::testing;
use design_render::synth;

const BUDGET_MS: f64 = 8.3;

fn pct(v: &[f64], p: f64) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn report(name: &str, v: &[f64]) -> bool {
    let p99 = pct(v, 0.99);
    println!(
        "{name:<34} n={:<4} p50 {:>6.2}  p95 {:>6.2}  p99 {:>6.2}  max {:>6.2} ms  {}",
        v.len(),
        pct(v, 0.5),
        pct(v, 0.95),
        p99,
        pct(v, 1.0),
        if p99 <= BUDGET_MS { "ok" } else { "OVER" }
    );
    p99 <= BUDGET_MS
}

fn frame(h: u64, metal: bool) {
    let us = testing::frame_us(h, metal);
    assert!(us >= 0, "frame failed: {us}");
}

/// Time `f` + one frame, `n` times: (input, input + frame) in ms.
fn run(h: u64, metal: bool, n: usize, mut f: impl FnMut(usize) -> i32) -> (Vec<f64>, Vec<f64>) {
    let (mut input, mut total) = (vec![], vec![]);
    for i in 0..n {
        let t = Instant::now();
        assert_eq!(f(i), DE_OK);
        input.push(t.elapsed().as_secs_f64() * 1e3);
        frame(h, metal);
        total.push(t.elapsed().as_secs_f64() * 1e3);
    }
    (input, total)
}

fn main() {
    let metal = std::env::args().any(|a| a == "--metal");
    let scale: f32 = std::env::args()
        .skip_while(|a| a != "--scale")
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2.0);
    let s = synth::app(50, 10);
    let doc = synth::DOC_ID.as_bytes();
    let mut h = 0u64;
    // SAFETY: live buffers.
    unsafe {
        assert_eq!(de_engine_new(doc.as_ptr(), doc.len(), &mut h), DE_OK);
        let font = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../render/tests/fonts/Roboto-Regular.ttf"
        ))
        .expect("font");
        assert_eq!(
            de_font_add(h, std::ptr::null(), 0, font.as_ptr(), font.len()),
            DE_OK
        );
        for (k, b) in &s.images {
            assert_eq!(
                de_asset_add(h, k.as_ptr(), k.len(), b.as_ptr(), b.len()),
                DE_OK
            );
        }
    }
    assert_eq!(testing::import(h, &s.doc, &s.system), 0);
    assert_eq!(de_resize(h, 1440.0, 900.0, scale), DE_OK);
    // a label of the first screen, at 100 % in the middle of the view
    frame(h, metal);
    let label = s
        .doc
        .nodes
        .iter()
        .filter(|(_, n)| n.ty == design_model::NodeType::Text)
        .map(|(k, _)| k.clone())
        .find(|k| testing::rect(h, k).is_some())
        .expect("a text node");
    let [l, t, _, b] = testing::rect(h, &label).unwrap();
    assert_eq!(testing::set_camera(h, 1.0, (400.0 - l, 400.0 - t)), 0);
    frame(h, metal);
    for _ in 0..20 {
        frame(h, metal);
    }
    assert_eq!(de_text_begin(h, 401.0, 400.0 + (b - t) / 2.0), DE_OK);
    assert_eq!(de_text_command(h, DE_TEXT_RIGHT, DE_MOD_COMMAND), DE_OK);
    println!(
        "backend {}  scale {scale}  nodes ~{}  label {label}",
        if metal { "Metal" } else { "CPU raster" },
        s.doc.nodes.len()
    );
    // the same frame with no input (the camera nudged so it is a real redraw): what the renderer alone costs here
    let (_, base) = run(h, metal, 120, |i| {
        de_scroll(h, if i % 2 == 0 { 1.0 } else { -1.0 }, 0.0)
    });
    report("redraw, no typing (baseline)", &base);
    let mut pass = true;
    let keys: Vec<char> = "the quick brown fox jumps over the lazy dog "
        .chars()
        .collect();
    let (i, tot) = run(h, metal, 200, |i| {
        let k = keys[i % keys.len()].to_string();
        // SAFETY: a live buffer.
        unsafe { de_text_insert(h, k.as_ptr(), k.len(), DE_TEXT_NO_RANGE, 0) }
    });
    report("type a key (input)", &i);
    pass &= report("type a key (input + frame)", &tot);
    let comp = ["に", "にほ", "にほん", "日本"];
    let (i, tot) = run(h, metal, 120, |i| {
        let m = comp[i % comp.len()];
        let n = m.encode_utf16().count() as i64;
        // SAFETY: a live buffer.
        let rc = unsafe { de_text_set_marked(h, m.as_ptr(), m.len(), n, 0, DE_TEXT_NO_RANGE, 0) };
        if i % comp.len() == comp.len() - 1 {
            assert_eq!(de_text_unmark(h), DE_OK);
        }
        rc
    });
    report("IME marked text (input)", &i);
    pass &= report("IME marked text (input + frame)", &tot);
    let (i, tot) = run(h, metal, 120, |_| {
        de_text_command(h, DE_TEXT_DELETE_BACK, 0)
    });
    report("delete back (input)", &i);
    pass &= report("delete back (input + frame)", &tot);
    assert_eq!(de_text_end(h), DE_OK);
    assert_eq!(de_engine_free(h), DE_OK);
    if !pass {
        println!("T5 budget missed");
        std::process::exit(1);
    }
}
