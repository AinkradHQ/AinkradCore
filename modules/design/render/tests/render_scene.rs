//! V2-01 acceptance, scene half: dirty-region redraw, caches, hostile input, Metal vs CPU.

use common::*;
use design_model::{Doc, Theme, resolve};
use design_render::{Assets, Camera, Dirty, Renderer, cpu, synth};
use serde_json::json;

mod common;

#[test]
fn unchanged_load_is_clean_and_an_edit_redraws_only_its_screen() {
    let s = synth::app(6, 3);
    let res = |d: &Doc| {
        resolve(
            synth::DOC_ID,
            d,
            Some((synth::SYSTEM_ID, &s.system)),
            Theme::Day,
        )
        .unwrap()
    };
    let mut r = Renderer::new(fonts(), assets());
    for (h, b) in &s.images {
        r.assets.add(h, b);
    }
    r.set_view(1200.0, 800.0, 1.0);
    assert_eq!(r.load(&res(&s.doc), 0), Dirty::All);
    r.fit_all();
    let mut surf = skia_safe::surfaces::raster_n32_premul((1200, 800)).unwrap();
    r.draw(surf.canvas(), false);
    assert!(!r.needs_frame(), "idle after a draw: zero frames");
    let st = r.stats;
    assert_eq!(r.load(&res(&s.doc), 0), Dirty::Clean);
    assert_eq!(r.stats.layouts, st.layouts, "nothing re-laid-out");
    // edit one label
    let mut doc = s.doc.clone();
    let id = doc
        .nodes
        .iter()
        .find(|(_, n)| n.text.is_some())
        .map(|(k, _)| k.clone())
        .unwrap();
    doc.nodes.get_mut(&id).unwrap().text = Some("Edited".into());
    let d = r.load(&res(&doc), 0);
    assert!(matches!(d, Dirty::Rect(_)), "{d:?}");
    assert_eq!(r.stats.layouts, st.layouts + 1, "one artboard re-laid-out");
    assert!(r.needs_frame());
    r.draw(surf.canvas(), true);
    assert_eq!(
        r.stats.pictures_recorded,
        st.pictures_recorded + 1,
        "one picture re-recorded"
    );
    assert!(!r.needs_frame());
    // a camera move is a full redraw
    r.pan_by(10.0, 0.0);
    assert_eq!(r.dirty(), Dirty::All);
}

#[test]
fn theme_change_redraws_everything() {
    let (mut r, _) = load(&layout_fixture(), Theme::Day);
    let night = resolve("dd_t", &layout_fixture(), None, Theme::Night).unwrap();
    assert_eq!(r.load(&night, 0), Dirty::All);
}

#[test]
fn image_cache_respects_its_byte_cap() {
    let mut a = Assets::new(600_000); // a 256x256 image decodes to 262 144 bytes
    for i in 0..5 {
        a.add(&format!("{:0>64}", i), &synth::png(i));
    }
    for i in 0..5 {
        assert!(a.image(&format!("{:0>64}", i)).is_some());
        assert!(a.used() <= 600_000, "used {}", a.used());
    }
    assert!(a.image(&format!("{:0>64}", 9)).is_none(), "unknown asset");
    a.add(&"f".repeat(64), b"not an image");
    assert!(
        a.image(&"f".repeat(64)).is_none(),
        "undecodable bytes are a miss, not a panic"
    );
    assert!(a.image(&"f".repeat(64)).is_none());
}

#[test]
fn picture_cap_drops_pictures_of_screens_not_in_view() {
    let s = synth::app(12, 6);
    let res = resolve(
        synth::DOC_ID,
        &s.doc,
        Some((synth::SYSTEM_ID, &s.system)),
        Theme::Day,
    )
    .unwrap();
    let mut r = Renderer::new(fonts(), assets());
    for (h, b) in &s.images {
        r.assets.add(h, b);
    }
    r.set_view(1200.0, 800.0, 1.0);
    r.load(&res, 0);
    r.fit_all();
    let mut surf = skia_safe::surfaces::raster_n32_premul((1200, 800)).unwrap();
    r.draw(surf.canvas(), false);
    let all = r.picture_bytes();
    assert!(all > 0);
    r.cfg.picture_cap = all / 4;
    r.set_camera(Camera {
        zoom: 1.0,
        pan: (-100.0, -100.0),
        ..r.camera
    }); // one screen in view
    r.draw(surf.canvas(), false);
    assert!(
        r.picture_bytes() < all * 3 / 4,
        "{} of {all}",
        r.picture_bytes()
    );
}

#[test]
fn hostile_documents_do_not_panic() {
    // 60-deep nesting, a 100 000 character label in a 200 pt box, a huge radius, zero sizes, NaN-free extremes
    let mut node = json!({"type": "frame", "props": {"w": 10, "h": 10, "radius": 1.0e6, "layout": {"dir": "row", "pad": [1, 1, 1, 1]}}});
    for _ in 0..60 {
        node = json!({"type": "frame", "props": {"layout": {"dir": "column", "gap": 1000000}}, "children": [node]});
    }
    let long = "word ".repeat(20_000);
    let big = json!({"type": "text", "text": long, "props": {"w": 200, "type": {"font": "system", "size": 12}}});
    let wide = json!({"type": "frame", "props": {"x": 1.0e6, "y": -1.0e6, "w": 0, "h": 0, "sizing": {"w": "fill", "h": "fill"}}, "children": [big]});
    let doc = tree(page(vec![node, wide]));
    let res = resolve("dd_t", &doc, None, Theme::Day).unwrap();
    let mut r = Renderer::new(fonts(), assets());
    let t = std::time::Instant::now();
    r.load(&res, 0);
    r.set_view(400.0, 300.0, 1.0);
    r.fit_all();
    assert!(!cpu::render_png(&mut r).is_empty());
    assert!(t.elapsed().as_secs() < 20, "took {:?}", t.elapsed());
}

#[cfg(all(feature = "metal", target_os = "macos"))]
#[test]
fn metal_matches_cpu_within_tolerance() {
    let (mut r, _) = load(&layout_fixture(), Theme::Day);
    r.set_view(760.0, 540.0, 1.0);
    r.fit_all();
    let cpu_png = cpu::render_png(&mut r);
    let mut m = design_render::metal::Metal::system_default().expect("a Metal device");
    r.invalidate_all();
    m.render_offscreen(&mut r).expect("metal frame");
    let (mean, big) = diff(&m.png(), &cpu_png);
    println!("metal vs cpu: mean {mean:.3}, >48 {:.4}%", big * 100.0);
    assert!(mean <= 2.5 && big <= 0.02, "mean {mean} big {big}");
}
