//! V2-03 frame-cost check: drag and resize on the spike-sized scene (50 screens, ~5 600 nodes) through the C ABI,
//! against the T5 budget (p99 <= 8.3 ms from pointer event to a finished frame), plus hit testing (<= 1 ms).
//!
//!   cargo run --release -p design-ffi --features metal --example drag_bench -- [--metal] [--scale 2]
//!
//! Each step = `de_pointer(MOVE)` (gesture ops, preview patch, re-layout of the touched boards) + one full frame
//! (Metal offscreen waiting for the GPU with `--metal`, else CPU raster). Exits 1 when a budget is missed.
#![allow(unsafe_code)]

use std::time::Instant;

use design_ffi::ffi::*;
use design_ffi::testing;
use design_render::synth;

const BUDGET_MS: f64 = 8.3;
const HIT_BUDGET_MS: f64 = 1.0;

fn pct(v: &[f64], p: f64) -> f64 {
    let mut v = v.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn report(name: &str, v: &[f64], budget: f64) -> bool {
    let p99 = pct(v, 0.99);
    println!(
        "{name:<34} n={:<4} p50 {:>6.2}  p95 {:>6.2}  p99 {:>6.2}  max {:>6.2} ms  {}",
        v.len(),
        pct(v, 0.5),
        pct(v, 0.95),
        p99,
        pct(v, 1.0),
        if p99 <= budget { "ok" } else { "OVER" }
    );
    p99 <= budget
}

fn hit_id(h: u64, x: f32, y: f32) -> Option<String> {
    let mut out = vec![0u8; 4096];
    let mut n = 0usize;
    // SAFETY: a live buffer and length.
    let rc = unsafe { de_hit(h, x, y, out.as_mut_ptr(), out.len(), &mut n) };
    assert_eq!(rc, DE_OK);
    let v: serde_json::Value = serde_json::from_slice(&out[..n]).ok()?;
    v["id"].as_str().map(str::to_string)
}

/// A screen point that hits `id` itself, away from its handles (so a press there grabs, not resizes).
fn grab_point(h: u64, id: &str, cam: (f32, (f32, f32))) -> (f32, f32) {
    let [l, t, r, b] = testing::rect(h, id).expect("node rect");
    let s = |x: f32, y: f32| (x * cam.0 + cam.1.0, y * cam.0 + cam.1.1);
    for fy in [0.1f32, 0.2, 0.3, 0.5, 0.7, 0.9] {
        for fx in [0.03f32, 0.1, 0.2, 0.35, 0.5, 0.65, 0.8, 0.9] {
            let (x, y) = s(l + (r - l) * fx, t + (b - t) * fy);
            let (sl, st) = s(l, t);
            let (sr, sb) = s(r, b);
            let far = |a: f32, c: f32| (a - c).abs() > 10.0;
            let off_handles = far(x, sl) && far(x, sr) && far(x, (sl + sr) / 2.0)
                || far(y, st) && far(y, sb) && far(y, (st + sb) / 2.0);
            if off_handles && hit_id(h, x, y).as_deref() == Some(id) {
                return (x, y);
            }
        }
    }
    panic!("no grab point on {id}");
}

fn frame(h: u64, metal: bool) -> f64 {
    let us = testing::frame_us(h, metal);
    assert!(us >= 0, "frame failed: {us}");
    us as f64 / 1e3
}

struct Run {
    total: Vec<f64>,
    input: Vec<f64>,
    commit: f64,
}

/// Press at `at`, then `steps` moves of `d` each, timing event (input) + frame; release (commit timed apart), undo.
fn drag(h: u64, metal: bool, at: (f32, f32), d: (f32, f32), steps: usize, mods: u32) -> Run {
    assert_eq!(de_pointer(h, DE_POINTER_DOWN, at.0, at.1, mods), DE_OK);
    let (mut total, mut input) = (vec![], vec![]);
    for i in 1..=steps {
        let p = (at.0 + d.0 * i as f32, at.1 + d.1 * i as f32);
        let t = Instant::now();
        assert_eq!(de_pointer(h, DE_POINTER_MOVE, p.0, p.1, mods), DE_OK);
        input.push(t.elapsed().as_secs_f64() * 1e3);
        frame(h, metal);
        total.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let p = (at.0 + d.0 * steps as f32, at.1 + d.1 * steps as f32);
    let t = Instant::now();
    assert_eq!(de_pointer(h, DE_POINTER_UP, p.0, p.1, mods), DE_OK);
    frame(h, metal);
    let commit = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(de_undo(h), 1, "the gesture is one undo step");
    frame(h, metal);
    Run {
        total,
        input,
        commit,
    }
}

/// Report a run; the budget applies to event + frame.
fn check(name: &str, r: Run, commits: &mut Vec<f64>) -> bool {
    report(&format!("{name} (input)"), &r.input, BUDGET_MS);
    commits.push(r.commit);
    report(&format!("{name} (input + frame)"), &r.total, BUDGET_MS)
}

fn select(h: u64, at: (f32, f32)) {
    assert_eq!(de_pointer(h, DE_POINTER_DOWN, at.0, at.1, 0), DE_OK);
    assert_eq!(de_pointer(h, DE_POINTER_UP, at.0, at.1, 0), DE_OK);
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
    let named = |name: &str, nth: usize| {
        s.doc
            .nodes
            .iter()
            .filter(|(_, n)| n.name == name)
            .nth(nth)
            .map(|(k, _)| k.clone())
            .expect("node")
    };
    // 100 % zoom on the first two screens
    let cam = (1.0f32, (60.0f32, -300.0f32));
    assert_eq!(testing::set_camera(h, cam.0, cam.1), 0);
    let t = Instant::now();
    frame(h, metal);
    println!(
        "backend {}  scale {scale}  nodes ~{}  first frame (resolve + layout + draw) {:.0} ms",
        if metal { "Metal" } else { "CPU raster" },
        s.doc.nodes.len(),
        t.elapsed().as_secs_f64() * 1e3
    );
    for _ in 0..20 {
        frame(h, metal);
    }
    // the same frame with no input: what the renderer alone costs here (camera nudged so it is a real redraw)
    let base: Vec<f64> = (0..120)
        .map(|i| {
            assert_eq!(
                de_scroll(h, if i % 2 == 0 { 1.0 } else { -1.0 }, 0.0),
                DE_OK
            );
            frame(h, metal)
        })
        .collect();
    report("redraw, no gesture (baseline)", &base, BUDGET_MS);
    let mut pass = true;
    let mut commits = vec![];

    // 1. a glass panel (free child) dragged across into the next screen: snapping, guides, unnest + nest
    let glass = named("glass", 0);
    let at = grab_point(h, &glass, cam);
    select(h, at);
    pass &= check(
        "drag glass across screens",
        drag(h, metal, at, (4.0, 0.5), 120, 0),
        &mut commits,
    );
    // 2. the same, alt-drag: a copy
    pass &= check(
        "alt-drag a copy of the glass",
        drag(h, metal, at, (3.0, 1.0), 120, DE_MOD_OPTION),
        &mut commits,
    );
    // 3. resize it from the bottom-right handle (the copy was undone: select the glass again)
    select(h, at);
    let [_, _, r, b] = testing::rect(h, &glass).unwrap();
    let se = (r * cam.0 + cam.1.0, b * cam.0 + cam.1.1);
    pass &= check(
        "resize glass (se handle)",
        drag(h, metal, se, (1.5, 0.5), 120, 0),
        &mut commits,
    );
    // 4. a card reordered down its auto-layout column (live reflow)
    let card = named("Card", 0);
    let at = grab_point(h, &card, cam);
    select(h, at);
    pass &= check(
        "drag card through auto-layout",
        drag(h, metal, at, (0.0, 4.0), 120, 0),
        &mut commits,
    );
    // 5. a whole screen: marquee-select it from the empty canvas above, then drag it
    let cam = (1.0f32, (60.0f32, 60.0f32));
    assert_eq!(testing::set_camera(h, cam.0, cam.1), 0);
    let screen = named("Screen", 0);
    let [l, t, _, _] = testing::rect(h, &screen).unwrap();
    let above = (l * cam.0 + cam.1.0 + 20.0, t * cam.0 + cam.1.1 - 30.0);
    assert_eq!(de_pointer(h, DE_POINTER_DOWN, above.0, above.1, 0), DE_OK);
    assert_eq!(
        de_pointer(h, DE_POINTER_MOVE, above.0 + 10.0, above.1 + 60.0, 0),
        DE_OK
    );
    assert_eq!(
        de_pointer(h, DE_POINTER_UP, above.0 + 10.0, above.1 + 60.0, 0),
        DE_OK
    );
    let at = (l * cam.0 + cam.1.0 + 100.0, t * cam.0 + cam.1.1 + 500.0);
    pass &= check(
        "drag a whole screen",
        drag(h, metal, at, (2.0, 2.0), 120, 0),
        &mut commits,
    );
    // 6. resize a whole screen from its right edge
    let [_, t, r, b] = testing::rect(h, &screen).unwrap();
    let e = (r * cam.0 + cam.1.0, ((t + b) / 2.0) * cam.0 + cam.1.1);
    pass &= check(
        "resize a screen (e handle)",
        drag(h, metal, e, (1.0, 0.0), 120, 0),
        &mut commits,
    );

    // hit testing at 5 000 nodes, fitted out (every board on screen)
    assert_eq!(de_fit(h), DE_OK);
    frame(h, metal);
    let mut v = vec![];
    for i in 0..2000 {
        let (x, y) = ((i * 37 % 1440) as f32, (i * 53 % 900) as f32);
        let t = Instant::now();
        let _ = hit_id(h, x, y);
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    pass &= report("hit test (de_hit, 5k nodes)", &v, HIT_BUDGET_MS);
    println!(
        "pointer-up commit (write + re-resolve + frame): {}",
        commits
            .iter()
            .map(|c| format!("{c:.0}"))
            .collect::<Vec<_>>()
            .join(" / ")
            + " ms"
    );
    assert_eq!(de_engine_free(h), DE_OK);
    if !pass {
        println!("T5 budget missed");
        std::process::exit(1);
    }
}
