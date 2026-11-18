//! V6-03 acceptance: an exported screen, shot by Chromium, against the engine's own frame of it, on the render
//! crate's golden fixtures (layout, glass, gradients, shadows, images, text in the fallback and in library fonts).
//! Gate: at most 1 % of pixels differ (`fidelity::TOLERANCE`).
//!
//! The Chromium half needs a browser: set `AINKRAD_CHROMIUM` to a `chrome-headless-shell` (or Chrome) binary, as on
//! the runner hosts; without it those tests say so and pass, and `cargo test` stays hermetic. Chromium runs here
//! unsandboxed on files this test wrote; the runner's bwrap profile is `design.shot`'s, tested in the runner crate.

#[path = "../../render/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command as Process;

use ainkrad_design::{export::export, fidelity::fidelity, ops, run};
use ainkrad_proto::v2::{
    Command, DesignDoc, DesignExport, DesignFidelity, DesignFile, DesignRender,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use design_model::Doc;
use serde_json::json;

const REGULAR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOLD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MISSING: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn font(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../render/tests/fonts")
            .join(name),
    )
    .unwrap()
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn job(doc: &Doc, theme: &str) -> DesignDoc {
    DesignDoc {
        doc_id: "dd_t".into(),
        doc: serde_json::to_value(doc).unwrap(),
        system_id: None,
        system: None,
        theme: theme.into(),
        page: 0,
        fonts: vec![
            DesignFile {
                sha256: REGULAR.into(),
                data: b64(&font("Roboto-Regular.ttf")),
            },
            DesignFile {
                sha256: BOLD.into(),
                data: b64(&font("Roboto-Bold.ttf")),
            },
        ],
        images: vec![DesignFile {
            sha256: common::IMG.into(),
            data: b64(&design_render::synth::png(3)),
        }],
        fallback_font: Some(REGULAR.into()),
    }
}

/// The layout fixture, with its one missing image replaced by the one the job carries (the renderer draws a grey
/// placeholder for a missing image, a page draws nothing; that is not what is being measured).
fn layout() -> Doc {
    let s = serde_json::to_string(&common::layout_fixture())
        .unwrap()
        .replace(MISSING, common::IMG);
    serde_json::from_str(&s).unwrap()
}

fn library_text() -> Doc {
    let t = |s: &str, size: f32, weight: u32, asset: &str| {
        json!({"type": "text", "text": s, "props": {"type": {"font": {"asset": asset}, "size": size, "weight": weight, "line": size * 1.4},
            "fill": common::solid("#16181f")}})
    };
    common::tree(common::page(vec![
        json!({"type": "frame", "props": {"w": 320, "h": 150, "fill": common::solid("#ffffff"),
        "layout": {"dir": "column", "gap": 8, "pad": [14, 14, 14, 14]}},
        "children": [
            t("Library fonts, bold", 22.0, 700, BOLD),
            t("Regular weight in the second face, set at fourteen points.", 14.0, 400, REGULAR),
            {let mut x = t("Tracked uppercase caption", 11.0, 400, REGULAR); x["props"]["type"]["tracking"] = json!(0.08); x["props"]["type"]["transform"] = json!("uppercase"); x}]}),
    ]))
}

fn chromium() -> Option<PathBuf> {
    std::env::var_os("AINKRAD_CHROMIUM")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ainkrad-fidelity-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The export of screen `at` of `doc`, shot by Chromium, against the engine's frame of it: the percent that differ.
fn measure(chrome: &Path, doc: &Doc, theme: &str, at: usize, tag: &str) -> f64 {
    let d = job(doc, theme);
    let screen = Some(top_level(doc)[at].clone());
    let ex = export(&DesignExport {
        doc: d.clone(),
        screen,
    })
    .unwrap();
    let dir = tmp(tag);
    let pkg = dir.join("pkg");
    std::fs::create_dir_all(pkg.join("fonts")).unwrap();
    std::fs::create_dir_all(pkg.join("assets")).unwrap();
    std::fs::write(pkg.join("index.html"), &ex.html).unwrap();
    std::fs::write(pkg.join("style.css"), &ex.css).unwrap();
    for f in d.fonts.iter().filter(|f| ex.fonts.contains(&f.sha256)) {
        std::fs::write(
            pkg.join("fonts").join(&f.sha256),
            STANDARD.decode(&f.data).unwrap(),
        )
        .unwrap();
    }
    for f in d.images.iter().filter(|f| ex.images.contains(&f.sha256)) {
        std::fs::write(
            pkg.join("assets").join(&f.sha256),
            STANDARD.decode(&f.data).unwrap(),
        )
        .unwrap();
    }
    let shot = dir.join("shot.png");
    let out = Process::new(chrome)
        .args([
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=1",
        ])
        .arg(format!("--window-size={},{}", ex.width, ex.height))
        .arg("--virtual-time-budget=3000")
        .arg(format!("--user-data-dir={}", dir.join("profile").display()))
        .arg(format!("--screenshot={}", shot.display()))
        .arg(format!("file://{}", pkg.join("index.html").display()))
        .output()
        .expect("start chromium");
    assert!(
        shot.is_file(),
        "no screenshot: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let frame = ops::render(&DesignRender {
        doc: d,
        node: Some(ex.screen.clone()),
        scale: 1.0,
    })
    .unwrap();
    assert_eq!((frame.width, frame.height), (ex.width, ex.height));
    let s = fidelity(&DesignFidelity {
        a: frame.png,
        b: b64(&std::fs::read(&shot).unwrap()),
    })
    .unwrap();
    println!(
        "fidelity {tag}: {:.3} % ({} of {} px)",
        s.percent, s.changed, s.total
    );
    let _ = std::fs::remove_dir_all(&dir);
    s.percent
}

fn top_level(doc: &Doc) -> Vec<String> {
    let r = design_model::resolve("dd_t", doc, None, design_model::Theme::Day).unwrap();
    r.pages[0].children.iter().map(|c| c.id.clone()).collect()
}

#[test]
fn golden_screens_export_within_one_percent() {
    let Some(chrome) = chromium() else {
        eprintln!("AINKRAD_CHROMIUM is not set: the Chromium fidelity check is skipped");
        return;
    };
    let mut worst: f64 = 0.0;
    let cases: Vec<(&str, Doc, usize)> = vec![
        ("layout-a", layout(), 0),
        ("layout-b", layout(), 1),
        ("text-fallback", common::text_fixture(), 0),
        ("text-library", library_text(), 0),
    ];
    for (name, doc, at) in &cases {
        for theme in ["day", "night"] {
            let p = measure(&chrome, doc, theme, *at, &format!("{name}-{theme}"));
            assert!(
                p <= 1.0,
                "{name} {theme}: {p:.3} % of pixels differ (gate 1 %)"
            );
            worst = worst.max(p);
        }
    }
    println!("worst fidelity: {worst:.3} %");
}

#[test]
fn export_reports_the_screen_and_its_size_and_runs_as_a_job() {
    let doc = layout();
    let d = job(&doc, "day");
    let ex = export(&DesignExport {
        doc: d.clone(),
        screen: None,
    })
    .unwrap();
    // screen A is 360 x 480 in the fixture
    assert_eq!((ex.width, ex.height), (360, 480));
    assert_eq!(ex.screen, top_level(&doc)[0]);
    assert!(ex.html.contains("data-theme=\"day\""));
    assert!(ex.fonts.contains(&REGULAR.to_owned()) && ex.images == vec![common::IMG.to_owned()]);
    let b = export(&DesignExport {
        doc: d.clone(),
        screen: Some(top_level(&doc)[1].clone()),
    })
    .unwrap();
    assert_eq!((b.width, b.height), (220, 160));
    // the same through the one entry point the sandbox calls
    let job = serde_json::to_vec(&Command::DesignExport(DesignExport {
        doc: d,
        screen: None,
    }))
    .unwrap();
    let out: serde_json::Value = serde_json::from_str(&run(&job).unwrap()).unwrap();
    assert_eq!(out["width"], 360);
    // a screen that is not on the page, a theme that is not one
    let mut bad = job(&doc, "day");
    assert!(
        export(&DesignExport {
            doc: bad.clone(),
            screen: Some("n_zzzzzzzzzzzz".into())
        })
        .is_err()
    );
    bad.theme = "dusk".into();
    assert!(
        export(&DesignExport {
            doc: bad,
            screen: None
        })
        .is_err()
    );
}

#[test]
fn fidelity_is_zero_for_one_image_and_sees_a_shift() {
    let doc = layout();
    let d = job(&doc, "day");
    let png = |scale: f32, node: Option<String>| {
        ops::render(&DesignRender {
            doc: d.clone(),
            node,
            scale,
        })
        .unwrap()
    };
    let a = png(1.0, Some(top_level(&doc)[0].clone()));
    let same = fidelity(&DesignFidelity {
        a: a.png.clone(),
        b: a.png.clone(),
    })
    .unwrap();
    assert_eq!((same.percent, same.changed), (0.0, 0));
    // another screen of another size: not comparable, so wholly different
    let b = png(1.0, Some(top_level(&doc)[1].clone()));
    let other = fidelity(&DesignFidelity {
        a: a.png.clone(),
        b: b.png,
    })
    .unwrap();
    assert_eq!(other.percent, 100.0);
    // the same screen at another scale is another size too
    let half = png(0.5, Some(top_level(&doc)[0].clone()));
    assert_eq!(
        fidelity(&DesignFidelity {
            a: a.png.clone(),
            b: half.png
        })
        .unwrap()
        .percent,
        100.0
    );
    // a frame that is not a PNG is refused, not decoded
    assert!(
        fidelity(&DesignFidelity {
            a: a.png.clone(),
            b: b64(b"not a png")
        })
        .is_err()
    );
    assert!(
        fidelity(&DesignFidelity {
            a: a.png,
            b: "!!".into()
        })
        .is_err()
    );
}
