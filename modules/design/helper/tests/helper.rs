//! V6-01, helper half: the ops on real and hostile input, in-process (the runner tests run the same
//! binary in its sandbox). Every hostile file is refused or drawn as a placeholder, never a panic.

use std::io::Write;

use ainkrad_design::{icon, ops, run};
use ainkrad_proto::v2::{Command, DesignCheck, DesignDoc, DesignFile, DesignRender};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

fn roboto() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../render/tests/fonts/Roboto-Regular.ttf"
    ))
    .unwrap()
}

/// A zip of `(name, bytes, deflate?)`; `lie` adds to every stated size.
fn zip(files: &[(&str, &[u8], bool)], lie: u32) -> Vec<u8> {
    let (mut out, mut cd) = (Vec::new(), Vec::new());
    for (name, data, deflate) in files {
        let body = if *deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        } else {
            data.to_vec()
        };
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let (method, off) = (if *deflate { 8u16 } else { 0 }, out.len() as u32);
        let head = |sig: u32, central: bool| {
            let mut h = sig.to_le_bytes().to_vec();
            if central {
                h.extend(20u16.to_le_bytes());
            }
            h.extend(20u16.to_le_bytes());
            h.extend(0u16.to_le_bytes());
            h.extend(method.to_le_bytes());
            h.extend([0; 4]);
            h.extend(crc.sum().to_le_bytes());
            h.extend((body.len() as u32).to_le_bytes());
            h.extend((data.len() as u32 + lie).to_le_bytes());
            h.extend((name.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes());
            if central {
                // comment length, disk, internal and external attributes
                h.extend([0; 10]);
                h.extend(off.to_le_bytes());
            }
            h.extend(name.as_bytes());
            h
        };
        let l = head(0x0403_4b50, false);
        cd.extend(head(0x0201_4b50, true));
        out.extend(l);
        out.extend(&body);
    }
    let (cd_off, cd_len) = (out.len() as u32, cd.len() as u32);
    out.extend(cd);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0; 4]);
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend(cd_len.to_le_bytes());
    out.extend(cd_off.to_le_bytes());
    out.extend([0; 2]);
    out
}

fn png() -> Vec<u8> {
    design_render::synth::png(1)
}

#[test]
fn a_real_font_passes_and_hostile_ones_are_refused() {
    assert_eq!(ops::check_font(&roboto()), Ok(()));
    let mut damaged = roboto();
    let mid = damaged.len() / 2;
    damaged[mid..mid + 4096].fill(0xff);
    let mut tables_lie = vec![0, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0];
    tables_lie.extend([0x41; 64]);
    for (name, b) in [
        ("empty", vec![]),
        ("truncated", roboto()[..1000].to_vec()),
        ("tables-lie", tables_lie),
        ("otto-empty", b"OTTO\0\0\0\0".to_vec()),
        ("woff2-truncated", b"wOF2\0\x01\0\0\0\0\0\0".to_vec()),
        ("png-as-font", png()),
    ] {
        assert!(ops::check_font(&b).is_err(), "{name} passed");
    }
    // A damaged glyph table may still load (FreeType reads lazily): it must not panic either way.
    let _ = ops::check_font(&damaged);
}

#[test]
fn icon_zips_pass_only_when_whole_and_plain() {
    let j = br#"{"groups":[]}"#;
    let good = zip(
        &[
            ("App.icon/icon.json", j, true),
            ("App.icon/Assets/a.png", &png(), false),
        ],
        0,
    );
    assert_eq!(icon::check(&good), Ok(()));
    let svg = b"<svg xmlns='http://www.w3.org/2000/svg'/>";
    assert_eq!(
        icon::check(&zip(&[("icon.json", j, false), ("a.svg", svg, true)], 0)),
        Ok(())
    );
    let bomb = vec![0u8; 80 << 20];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("traversal", zip(&[("../icon.json", j, false)], 0)),
        ("absolute", zip(&[("/icon.json", j, false)], 0)),
        ("no-manifest", zip(&[("a.png", &png(), false)], 0)),
        ("bad-json", zip(&[("icon.json", b"{", false)], 0)),
        ("size-lie", zip(&[("icon.json", j, true)], 7)),
        (
            "bomb",
            zip(&[("icon.json", j, false), ("b.png", &bomb, true)], 0),
        ),
        (
            "bad-layer",
            zip(
                &[
                    ("icon.json", j, false),
                    ("a.png", b"\x89PNG\r\n\x1a\nxx", false),
                ],
                0,
            ),
        ),
        ("not-zip", b"PK\x03\x04 nothing".to_vec()),
        ("truncated", good[..good.len() - 30].to_vec()),
    ];
    for (name, z) in cases {
        assert!(icon::check(&z).is_err(), "{name} passed");
    }
    let mut crc = zip(&[("icon.json", j, false)], 0);
    let at = crc.windows(4).position(|w| w == b"{\"gr").unwrap();
    crc[at] ^= 1;
    assert!(
        icon::check(&crc).is_err(),
        "a stored entry with a bad CRC passed"
    );
}

fn doc(images: Vec<DesignFile>, fonts: Vec<DesignFile>) -> DesignDoc {
    let d = json!({
        "meta": {},
        "nodes": {
            "n_aaaaaaaaaaaa": {"type": "page", "parent": null, "order": "a", "clock": 1, "name": "P", "props": {}},
            "n_bbbbbbbbbbbb": {"type": "frame", "parent": "n_aaaaaaaaaaaa", "order": "a", "clock": 1, "name": "S",
                "props": {"x": 0, "y": 0, "w": 200, "h": 100}},
            "n_cccccccccccc": {"type": "image", "parent": "n_bbbbbbbbbbbb", "order": "a", "clock": 1, "name": "I",
                "props": {"x": 150, "y": 0, "w": 100, "h": 50, "asset": "e".repeat(64)}},
            "n_dddddddddddd": {"type": "text", "parent": "n_bbbbbbbbbbbb", "order": "b", "clock": 1, "name": "T",
                "text": "Hello", "props": {"x": 0, "y": 60, "w": 10, "h": 10, "type": {"font": {"asset": "f".repeat(64)}}}}
        }
    });
    DesignDoc {
        doc_id: "dd_t".into(),
        doc: d,
        system_id: None,
        system: None,
        theme: "night".into(),
        page: 0,
        fonts,
        images,
        fallback_font: None,
    }
}

fn file(c: char, b: &[u8]) -> DesignFile {
    DesignFile {
        sha256: c.to_string().repeat(64),
        data: STANDARD.encode(b),
    }
}

#[test]
fn render_measure_review_work_and_hostile_images_draw_placeholders() {
    let mut huge = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    huge.extend(100_000u32.to_be_bytes());
    huge.extend(100_000u32.to_be_bytes());
    huge.extend([8, 6, 0, 0, 0, 0, 0, 0, 0]);
    let laughs = br#"<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><svg>&b;</svg>"#;
    for (name, img) in [
        ("good", png()),
        ("huge", huge),
        ("laughs", laughs.to_vec()),
        ("junk", vec![7; 999]),
    ] {
        let r = ops::render(&DesignRender {
            doc: doc(vec![file('e', &img)], vec![]),
            node: None,
            scale: 2.0,
        })
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            r.width >= 400 && r.height >= 200,
            "{name}: {}x{}",
            r.width,
            r.height
        );
        assert!(r.metrics_differ, "no library font was supplied");
    }
    let with_font = ops::render(&DesignRender {
        doc: doc(vec![], vec![file('f', &roboto())]),
        node: Some("n_dddddddddddd".into()),
        scale: 1.0,
    })
    .unwrap();
    assert!(
        !with_font.metrics_differ,
        "the text's library font was supplied"
    );
    let boxes = ops::measure(&doc(vec![], vec![])).unwrap();
    assert!(
        boxes
            .nodes
            .iter()
            .any(|b| b.id == "n_cccccccccccc" && b.x == 150.0),
        "{boxes:?}"
    );
    let f = ops::review(&doc(vec![], vec![file('f', &roboto())])).unwrap();
    let rules: Vec<_> = f
        .findings
        .iter()
        .map(|f| (f.rule.as_str(), f.node.as_str()))
        .collect();
    assert!(
        rules.contains(&("geometry.outside", "n_cccccccccccc")),
        "{rules:?}"
    );
    assert!(
        rules.contains(&("geometry.text_overflow", "n_dddddddddddd")),
        "{rules:?}"
    );
}

#[test]
fn bad_jobs_are_errors_not_panics() {
    for job in [
        b"".to_vec(),
        b"{".to_vec(),
        json!({"op": "exec.run", "program": "/bin/sh"})
            .to_string()
            .into_bytes(),
        json!({"op": "design.render", "doc_id": "d", "doc": [], "theme": "day"})
            .to_string()
            .into_bytes(),
        json!({"op": "design.render", "doc_id": "d", "doc": {}, "theme": "dusk"})
            .to_string()
            .into_bytes(),
        json!({"op": "design.render", "doc_id": "d", "doc": {}, "theme": "day", "scale": 1000})
            .to_string()
            .into_bytes(),
        json!({"op": "design.render", "doc_id": "d", "doc": {}, "theme": "day", "node": "n_x"})
            .to_string()
            .into_bytes(),
    ] {
        assert!(run(&job).is_err(), "{}", String::from_utf8_lossy(&job));
    }
    let job = serde_json::to_vec(&Command::DesignCheck(DesignCheck {
        kind: "font".into(),
        data: STANDARD.encode(roboto()),
    }))
    .unwrap();
    assert_eq!(run(&job).unwrap(), r#"{"ok":true}"#);
}
