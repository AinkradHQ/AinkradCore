//! V2-01 acceptance, layout half: semantics, goldens, level of detail, hit testing.
//! Regenerate goldens with `UPDATE_GOLDEN=1 cargo test -p design-render` ON THE MAC; read the PNG diff first.

use common::*;
use design_model::{Doc, Theme, resolve};
use design_render::{Camera, Lod, Renderer, cpu, synth};
use serde_json::json;

mod common;

#[test]
fn layout_semantics() {
    let (r, _) = load(&layout_fixture(), Theme::Day);
    let rc = |n: usize| {
        r.node_rect(&id_of(n))
            .unwrap_or_else(|| panic!("no node {n}"))
    };
    // node 1 = page, 2 = screen A (360x480 at 0,0), 3 = bar: pad 16 -> x16 y16, fill width = 360-32, fixed height 44
    let bar = rc(3);
    assert_eq!(
        (bar.left, bar.top, bar.width(), bar.height()),
        (16.0, 16.0, 328.0, 44.0)
    );
    // bar children: icon at pad-left 12, centred vertically (44-28)/2
    let icon = rc(4);
    assert_eq!(
        (icon.left, icon.top, icon.width()),
        (16.0 + 12.0, 16.0 + 8.0, 28.0)
    );
    // fill spacer takes the rest of the row: bar inner 328-24=304, minus icon 28, title, ellipse 20, three gaps of 8
    let (title, spacer, dot) = (rc(5), rc(6), rc(7));
    assert!(
        title.width() > 20.0 && title.width() < 80.0,
        "hug text width {}",
        title.width()
    );
    assert!((spacer.left - (title.right + 8.0)).abs() < 0.01);
    assert!(
        (dot.right - (bar.right - 12.0)).abs() < 0.01,
        "ellipse sits at the right pad"
    );
    assert!((spacer.right + 8.0 - dot.left).abs() < 0.01);
    // wrap: 7 rects of 80 + gaps 6 in 328 -> 3 per row (3*80+2*6 = 252, a 4th needs 338)
    let (a, d) = (rc(9), rc(12));
    assert_eq!(a.top, rc(10).top);
    assert!(
        d.top > a.top && (d.left - a.left).abs() < 0.01,
        "fourth rect starts a new row"
    );
    // justify between: first at the left edge, last at the right edge of the 328 row
    let (one, three) = (rc(17), rc(19));
    assert!((one.left - 16.0).abs() < 0.01 && (three.right - 344.0).abs() < 0.01);
    // fixed width text wraps inside 220
    let para = rc(20);
    assert_eq!(para.width(), 220.0);
    assert!(
        para.height() >= 40.0,
        "wrapped to at least two 20 px lines: {}",
        para.height()
    );
}

#[test]
fn absolute_children_use_x_and_y() {
    let (r, _) = load(&layout_fixture(), Theme::Day);
    let card = r.node_rect(&id_of(21)).unwrap();
    let inner = r.node_rect(&id_of(22)).unwrap();
    assert_eq!((inner.left - card.left, inner.top - card.top), (10.0, 10.0));
}

#[test]
fn golden_layout_day() {
    let (mut r, _) = load(&layout_fixture(), Theme::Day);
    golden("layout-day", &shot(&mut r, 760.0, 540.0));
    assert!(
        r.missing.iter().any(|m| m.starts_with("2222")),
        "a missing image is reported, not fatal"
    );
}

#[test]
fn golden_layout_night() {
    let (mut r, _) = load(&layout_fixture(), Theme::Night);
    golden("layout-night", &shot(&mut r, 760.0, 540.0));
}

#[test]
fn golden_model_fixtures_with_tokens_and_instances() {
    let dir = here().join("../model/tests/fixtures/basic");
    let doc = Doc::from_json(&std::fs::read(dir.join("doc.json")).unwrap()).unwrap();
    let sys = Doc::from_json(&std::fs::read(dir.join("system.json")).unwrap()).unwrap();
    for (theme, name) in [(Theme::Day, "basic-day"), (Theme::Night, "basic-night")] {
        let res = resolve("dd_main", &doc, Some(("dd_sys", &sys)), theme).unwrap();
        let mut r = Renderer::new(fonts(), assets());
        r.assets.add(&"a".repeat(64), &synth::png(1));
        r.load(&res, 0);
        golden(name, &shot(&mut r, 640.0, 480.0));
    }
}

#[test]
fn golden_text_stays_crisp_at_five_zooms() {
    let (mut r, _) = load(&text_fixture(), Theme::Day);
    for (z, name) in [
        (0.1f32, "text-10"),
        (0.25, "text-25"),
        (1.0, "text-100"),
        (4.0, "text-400"),
        (8.0, "text-800"),
    ] {
        r.set_camera(Camera {
            zoom: z,
            pan: (160.0 - 60.0 * z, 120.0 - 30.0 * z),
            view: (320.0, 240.0),
            scale: 1.0,
        });
        let (m, b) = if z >= 1.0 {
            (6.0, 0.05)
        } else {
            (MAX_MEAN, MAX_BIG)
        };
        golden_tol(name, &cpu::render_png(&mut r), m, b);
    }
}

#[test]
fn level_of_detail_by_on_screen_width() {
    let (mut r, _) = load(&layout_fixture(), Theme::Day);
    let a = id_of(2);
    for (z, want) in [
        (0.1, Lod::Boxes),
        (0.3, Lod::Bars),
        (0.5, Lod::NoBlur),
        (1.0, Lod::Full),
    ] {
        r.set_camera(Camera {
            zoom: z,
            ..r.camera
        });
        assert_eq!(r.lod_of(&a), Some(want), "zoom {z}");
    }
    // screen B is 220 wide: > 200 so a candidate too; a 100 pt wide frame never is
    let small = tree(page(vec![
        json!({"type": "frame", "props": {"w": 100, "h": 40}, "children": []}),
    ]));
    let (mut r2, _) = load(&small, Theme::Day);
    r2.set_camera(Camera {
        zoom: 0.1,
        ..r2.camera
    });
    assert_eq!(r2.lod_of(&id_of(2)), Some(Lod::Full));
}

#[test]
fn live_blur_budget_keeps_the_biggest_screens_blurred() {
    let s = synth::app(3, 3); // 4 glass panels per screen
    let res = resolve(
        synth::DOC_ID,
        &s.doc,
        Some((synth::SYSTEM_ID, &s.system)),
        Theme::Day,
    )
    .unwrap();
    let mut r = Renderer::new(fonts(), assets());
    r.load(&res, 0);
    r.set_camera(Camera {
        zoom: 0.9,
        pan: (0.0, 0.0),
        view: (1400.0, 900.0),
        scale: 1.0,
    });
    let ids: Vec<String> = res.pages[0].children.iter().map(|c| c.id.clone()).collect();
    let full = |r: &Renderer| {
        ids.iter()
            .filter(|i| r.lod_of(i) == Some(Lod::Full))
            .count()
    };
    assert_eq!(full(&r), 2, "budget 8 = two screens of 4 panels");
    r.cfg.max_live_blurs = 4;
    assert_eq!(full(&r), 1);
    r.cfg.max_live_blurs = 0;
    assert_eq!(full(&r), 1, "the first always keeps its blur");
}

#[test]
fn hit_testing_finds_the_deepest_visible_node() {
    let (r, _) = load(&layout_fixture(), Theme::Day);
    let icon = r.node_rect(&id_of(4)).unwrap();
    let h = r.hit(icon.center_x(), icon.center_y()).unwrap();
    assert_eq!(h.id, id_of(4));
    assert_eq!(h.path, vec![id_of(2), id_of(3), id_of(4)]);
    // screen B's first child is invisible: the point hits its parent frame instead
    let b = r.node_rect(&id_of(28)).unwrap();
    let h = r.hit(b.left + 15.0, b.top + 15.0).unwrap();
    assert_eq!(
        h.id,
        id_of(28),
        "the hidden child (29) is not hit, its parent is"
    );
    // clip: the glass child's rect pokes nowhere here, but a point outside every artboard hits nothing
    assert!(r.hit(5000.0, 5000.0).is_none());
}
