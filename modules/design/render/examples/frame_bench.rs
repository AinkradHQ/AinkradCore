//! Frame-cost bench on the generated T5 scene (50 screens, ~5 000 nodes, 2 000 text runs, 200 glass panels, images).
//!
//!   cargo run --release -p design-render --example frame_bench -- [--screens 50] [--scale 2] [--metal] [--blur-below 250] [--path <dir>]
//!
//! CPU raster by default; `--metal` (needs `--features metal`, macOS) draws on the GPU. A scripted camera path calls the
//! same `zoom_at` / `pan_by` the gestures will. Prints p50/p95/p99/max per phase, open cost, hit-test cost, an edit's
//! re-layout + partial redraw, idle frames, and memory.

use std::time::Instant;

use design_model::{Theme, resolve};
use design_render::{Assets, Dirty, Fonts, Renderer, cpu, synth};
use skia_safe::surfaces;

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1))
        .cloned()
}

fn rss_mb() -> f64 {
    let pid = std::process::id().to_string();
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map_or(0.0, |k| k / 1024.0)
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn report(name: &str, mut v: Vec<f64>) {
    let over = v.iter().filter(|x| **x > 8.3).count() as f64 * 100.0 / v.len() as f64;
    println!(
        "{name:<28} n={:<5} p50 {:>6.2}  p95 {:>6.2}  p99 {:>6.2}  max {:>7.2} ms   >8.3ms {over:>5.1}%",
        v.len(),
        pct(&mut v, 0.5),
        pct(&mut v, 0.95),
        pct(&mut v, 0.99),
        pct(&mut v, 1.0)
    );
}

fn main() {
    let screens: usize = arg("--screens").and_then(|s| s.parse().ok()).unwrap_or(50);
    let scale: f32 = arg("--scale").and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let use_metal = std::env::args().any(|a| a == "--metal");
    let dir =
        arg("--path").unwrap_or_else(|| format!("{}/tests/fonts", env!("CARGO_MANIFEST_DIR")));
    let font = std::fs::read(format!("{dir}/Roboto-Regular.ttf")).expect("font");
    let rss0 = rss_mb();

    let t = Instant::now();
    let s = synth::app(screens, 10);
    let gen_ms = t.elapsed().as_secs_f64() * 1e3;
    let t = Instant::now();
    let res = resolve(
        synth::DOC_ID,
        &s.doc,
        Some((synth::SYSTEM_ID, &s.system)),
        Theme::Day,
    )
    .expect("resolve");
    let resolve_ms = t.elapsed().as_secs_f64() * 1e3;
    assert!(
        res.diagnostics.is_empty(),
        "{:?}",
        &res.diagnostics[..res.diagnostics.len().min(3)]
    );

    let mut fonts = Fonts::new();
    assert!(fonts.set_fallback(&font));
    let mut assets = Assets::default();
    for (h, b) in &s.images {
        assets.add(h, b);
    }
    let mut r = Renderer::new(fonts, assets);
    r.set_view(1440.0, 900.0, scale);
    if let Some(b) = arg("--blur-below").and_then(|s| s.parse().ok()) {
        r.cfg.blur_below = b;
    }
    let t = Instant::now();
    r.load(&res, 0);
    let load_ms = t.elapsed().as_secs_f64() * 1e3;
    let nodes = r.node_count();

    #[cfg(all(feature = "metal", target_os = "macos"))]
    let mut metal =
        use_metal.then(|| design_render::metal::Metal::system_default().expect("no Metal device"));
    #[cfg(not(all(feature = "metal", target_os = "macos")))]
    assert!(!use_metal, "build with --features metal");

    // one frame, CPU or GPU; returns (cpu ms, total ms)
    let mut cpu_surface =
        surfaces::raster_n32_premul(((1440.0 * scale) as i32, (900.0 * scale) as i32))
            .expect("surface");
    let mut frame = |r: &mut Renderer, partial: bool| -> (f64, f64) {
        #[cfg(all(feature = "metal", target_os = "macos"))]
        if let Some(m) = metal.as_mut() {
            let f = m.render_offscreen(r).expect("metal frame");
            return (f.cpu_ms, f.total_ms);
        }
        let t = Instant::now();
        r.draw(cpu_surface.canvas(), partial);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        (ms, ms)
    };

    println!(
        "backend {}  scale {scale}  screens {screens}  nodes {nodes}  (resolve {resolve_ms:.0} ms, generate {gen_ms:.0} ms)",
        if use_metal { "Metal" } else { "CPU raster" }
    );
    r.fit_all();
    let first = frame(&mut r, false);
    println!(
        "open: layout {load_ms:.0} ms + first frame {:.0} ms = {:.0} ms (budget 1000)",
        first.1,
        resolve_ms + load_ms + first.1
    );

    // the scripted camera path: zoom in on a point, pan across, zoom out, repeated twice (first pass is cold)
    let mut script = |r: &mut Renderer| -> Vec<(&'static str, f64, f64)> {
        let mut out = vec![];
        r.fit_all();
        let (cx, cy) = (720.0, 450.0);
        for _ in 0..240 {
            r.zoom_at(1.012, cx, cy);
            let f = frame(r, false);
            out.push(("zoom in", f.0, f.1));
        }
        for i in 0..400 {
            r.pan_by(if i < 200 { -9.0 } else { 9.0 }, -3.0);
            let f = frame(r, false);
            out.push(("pan", f.0, f.1));
        }
        for _ in 0..240 {
            r.zoom_at(1.0 / 1.012, cx, cy);
            let f = frame(r, false);
            out.push(("zoom out", f.0, f.1));
        }
        out
    };
    for pass in ["cold", "warm"] {
        let all = script(&mut r);
        for ph in ["zoom in", "pan", "zoom out"] {
            let v: Vec<f64> = all.iter().filter(|x| x.0 == ph).map(|x| x.2).collect();
            report(&format!("{pass} {ph} (total)"), v);
        }
        if use_metal {
            for ph in ["zoom in", "pan", "zoom out"] {
                let v: Vec<f64> = all.iter().filter(|x| x.0 == ph).map(|x| x.1).collect();
                report(&format!("{pass} {ph} (CPU encode)"), v);
                let v: Vec<f64> = all
                    .iter()
                    .filter(|x| x.0 == ph)
                    .map(|x| x.2 - x.1)
                    .collect();
                report(&format!("{pass} {ph} (GPU wait)"), v);
            }
        }
        let v: Vec<f64> = all.iter().map(|x| x.2).collect();
        report(&format!("{pass} ALL FRAMES"), v);
    }

    // 100 % and 400 % close-ups (text, glass, images at full detail)
    for z in [1.0f32, 4.0] {
        let mut c = r.camera;
        c.zoom = z;
        c.pan = (-300.0 * z, -200.0 * z);
        r.set_camera(c);
        let f: Vec<(f64, f64)> = (0..120)
            .map(|i| {
                r.pan_by(1.0 + (i % 3) as f32, 0.5);
                frame(&mut r, false)
            })
            .collect();
        let pc = format!("close-up {:.0}% pan", z * 100.0);
        report(&format!("{pc} (total)"), f.iter().map(|x| x.1).collect());
        if use_metal {
            report(
                &format!("{pc} (CPU encode)"),
                f.iter().map(|x| x.0).collect(),
            );
            report(
                &format!("{pc} (GPU wait)"),
                f.iter().map(|x| x.1 - x.0).collect(),
            );
        }
    }

    // hit testing
    let mut v = vec![];
    for i in 0..2000 {
        let (x, y) = ((i * 37 % 1440) as f32, (i * 53 % 900) as f32);
        let t = Instant::now();
        let _ = r.hit(x, y);
        v.push(t.elapsed().as_secs_f64() * 1e3);
    }
    println!(
        "hit test (5k nodes)          p50 {:.4} p99 {:.4} max {:.4} ms",
        pct(&mut v.clone(), 0.5),
        pct(&mut v.clone(), 0.99),
        pct(&mut v, 1.0)
    );

    // an edit: change one label, re-resolve, re-layout that screen only, partial redraw
    r.fit_all();
    frame(&mut r, false);
    let mut doc = s.doc.clone();
    let id = doc
        .nodes
        .iter()
        .find(|(_, n)| n.text.is_some())
        .map(|(k, _)| k.clone())
        .unwrap();
    doc.nodes.get_mut(&id).unwrap().text = Some("Edited label".into());
    let before = r.stats;
    let t = Instant::now();
    let res2 = resolve(
        synth::DOC_ID,
        &doc,
        Some((synth::SYSTEM_ID, &s.system)),
        Theme::Day,
    )
    .unwrap();
    let d = r.load(&res2, 0);
    let (_, draw_ms) = frame(&mut r, true);
    println!(
        "edit one label: resolve+layout+redraw {:.1} ms (draw {draw_ms:.1}), layouts {} pictures {}, dirty {}",
        t.elapsed().as_secs_f64() * 1e3,
        r.stats.layouts - before.layouts,
        r.stats.pictures_recorded - before.pictures_recorded,
        matches!(d, Dirty::Rect(_))
    );

    // idle: nothing changed, nothing to draw
    let idle = (0..180).filter(|_| r.needs_frame()).count();
    println!("idle canvas: {idle} frames needed over 180 ticks (target 0)");
    println!(
        "memory: rss {:.0} MB (start {rss0:.0}), pictures {:.0} MB, decoded images {:.0} MB (budget 500 MB total)",
        rss_mb(),
        r.picture_bytes() as f64 / 1048576.0,
        r.assets.used() as f64 / 1048576.0
    );
    let _ = cpu::render_png;
}
