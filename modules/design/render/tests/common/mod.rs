//! Shared helpers for the render acceptance tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use design_model::{Doc, Resolved, Theme, resolve};
use design_render::{Assets, Fonts, Renderer, cpu, synth};
use serde_json::{Value, json};
use skia_safe::{AlphaType, ColorType, Data, Image, ImageInfo, image::CachingHint};

pub const IMG: &str = "1111111111111111111111111111111111111111111111111111111111111111";

pub fn here() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

pub fn fonts() -> Fonts {
    let mut f = Fonts::new();
    let b = std::fs::read(here().join("tests/fonts/Roboto-Regular.ttf")).unwrap();
    assert!(f.set_fallback(&b));
    f
}

pub fn assets() -> Assets {
    let mut a = Assets::default();
    a.add(IMG, &synth::png(3));
    a
}

/// A nested `{type, name, props, text, children}` tree -> a flat document (ids `n_aaaaaaaaaaaa`...).
pub fn tree(root: Value) -> Doc {
    fn walk(
        v: &Value,
        parent: Option<&str>,
        n: &mut usize,
        out: &mut serde_json::Map<String, Value>,
        order: usize,
    ) {
        *n += 1;
        let id = format!("n_{}", synth_id(*n));
        let mut node = json!({
            "type": v["type"], "parent": parent, "order": format!("{:04}1", order), "clock": 1,
            "name": v.get("name").cloned().unwrap_or(json!("")), "props": v.get("props").cloned().unwrap_or(json!({})),
        });
        if let Some(t) = v.get("text") {
            node["text"] = t.clone();
        }
        out.insert(id.clone(), node);
        for (i, c) in v
            .get("children")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            walk(c, Some(&id), n, out, i + 1);
        }
    }
    fn synth_id(mut v: usize) -> String {
        let a = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut s = vec![b'a'; 12];
        for i in (0..12).rev() {
            s[i] = a[v % 32];
            v /= 32;
        }
        String::from_utf8(s).unwrap()
    }
    let mut out = serde_json::Map::new();
    let mut n = 0;
    walk(&root, None, &mut n, &mut out, 1);
    serde_json::from_value(json!({"meta": {"version": 1}, "nodes": Value::Object(out)})).unwrap()
}

pub fn id_of(n: usize) -> String {
    let a = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut v, mut s) = (n, vec![b'a'; 12]);
    for i in (0..12).rev() {
        s[i] = a[v % 32];
        v /= 32;
    }
    format!("n_{}", String::from_utf8(s).unwrap())
}

pub fn rect(w: f32, h: f32, c: &str) -> Value {
    json!({"type": "rect", "props": {"w": w, "h": h, "fill": [{"type": "solid", "color": c}]}})
}

pub fn solid(c: &str) -> Value {
    json!([{"type": "solid", "color": c}])
}

pub fn text(s: &str, size: f32, extra: Value) -> Value {
    let mut t = json!({"font": "system", "size": size, "weight": 400});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        t[k] = v;
    }
    json!({"type": "text", "text": s, "props": {"type": t, "fill": solid("#16181f")}})
}

pub fn load(doc: &Doc, theme: Theme) -> (Renderer, Resolved) {
    let res = resolve("dd_t", doc, None, theme).unwrap();
    assert!(res.diagnostics.is_empty(), "{:?}", res.diagnostics);
    let mut r = Renderer::new(fonts(), assets());
    r.load(&res, 0);
    (r, res)
}

pub fn page(children: Vec<Value>) -> Value {
    json!({"type": "page", "props": {}, "children": children})
}

// ------------------------------------------------------------------------------------------------ fixtures

pub fn layout_fixture() -> Doc {
    let screen_a = json!({"type": "frame", "name": "A", "props": {
      "x": 0, "y": 0, "w": 360, "h": 480, "clip": true, "fill": solid("#f4f5f8"),
      "layout": {"dir": "column", "gap": 12, "pad": [16, 16, 16, 16]}},
    "children": [
      {"type": "frame", "name": "bar", "props": {"sizing": {"w": "fill"}, "h": 44, "radius": 10, "fill": solid("#ffffff"),
          "layout": {"dir": "row", "gap": 8, "align": "center", "pad": [0, 12, 0, 12]}},
       "children": [
          {"type": "rect", "props": {"w": 28, "h": 28, "radius": 8, "fill": solid("#2f6fed")}},
          text("Title", 16.0, json!({"weight": 700})),
          {"type": "rect", "props": {"sizing": {"w": "fill"}, "h": 4, "fill": solid("#c9ced9")}},
          {"type": "ellipse", "props": {"w": 20, "h": 20, "fill": [{"type": "linear", "angle": 90,
              "stops": [{"at": 0, "color": "#ff7a59"}, {"at": 1, "color": "#7a5cff"}]}]}}]},
      {"type": "frame", "name": "wrap", "props": {"sizing": {"w": "fill"}, "layout": {"dir": "row", "wrap": true, "gap": 6}},
       "children": (0..7).map(|i| rect(80.0, 30.0, ["#ef4444", "#f59e0b", "#10b981", "#3b82f6", "#8b5cf6", "#ec4899", "#14b8a6"][i])).collect::<Vec<_>>()},
      {"type": "frame", "name": "between", "props": {"sizing": {"w": "fill"}, "h": 40, "layout": {"dir": "row", "justify": "between", "align": "center"}},
       "children": [text("One", 14.0, json!({})), text("Two", 14.0, json!({"transform": "uppercase", "tracking": 0.1})), text("Three", 14.0, json!({}))]},
      {"type": "text", "text": "A longer paragraph that has to wrap inside its fixed width and centre each line.",
       "props": {"w": 220, "type": {"font": "system", "size": 14, "weight": 400, "line": 20, "align": "center"}, "fill": solid("#16181f")}},
      {"type": "frame", "name": "card", "props": {"sizing": {"w": "fill"}, "h": 90, "radius": [16, 16, 4, 4], "fill": solid("#ffffff"),
          "shadow": [{"x": 0, "y": 3, "blur": 10, "spread": 0, "color": "#00000033"}], "stroke": {"color": "#c9ced9", "width": 1}},
       "children": [
          {"type": "rect", "props": {"x": 10, "y": 10, "w": 60, "h": 60, "opacity": 0.5, "fill": solid("#ef4444")}},
          {"type": "vector", "props": {"x": 90, "y": 10, "path": "M0 0 L60 0 L30 50 Z", "fill": solid("#f59e0b"), "stroke": {"color": "#16181f", "width": 2}}},
          {"type": "image", "props": {"x": 170, "y": 10, "w": 80, "h": 60, "radius": 8, "asset": IMG, "fit": "fill"}}]},
      {"type": "frame", "name": "glass", "props": {"sizing": {"w": "fill"}, "h": 100, "clip": true, "radius": 12,
          "fill": [{"type": "linear", "angle": 135, "stops": [{"at": 0, "color": "#ff7a59"}, {"at": 1, "color": "#3b82f6"}]}]},
       "children": [
          {"type": "frame", "props": {"x": 20, "y": 20, "w": 200, "h": 60, "radius": 16, "material": "glass",
              "layout": {"dir": "row", "align": "center", "justify": "center"}},
           "children": [text("Glass", 15.0, json!({"weight": 700}))]}]}
    ]});
    let screen_b = json!({"type": "frame", "name": "B", "props": {"x": 420, "y": 0, "w": 220, "h": 160, "fill": solid("#16181f"), "radius": 14},
      "children": [
        {"type": "rect", "props": {"x": 10, "y": 10, "w": 100, "h": 40, "visible": false, "fill": solid("#ffffff")}},
        {"type": "rect", "props": {"x": 20, "y": 20, "w": 100, "h": 60, "blend": "multiply", "fill": solid("#ff7a59")}},
        {"type": "frame", "props": {"x": 130, "y": 20, "w": 80, "h": 40, "radius": 8, "material": "well"}},
        {"type": "frame", "props": {"x": 130, "y": 70, "w": 80, "h": 40, "radius": 8, "material": "clear"}},
        {"type": "image", "props": {"x": 20, "y": 100, "w": 60, "h": 40, "asset": "2222222222222222222222222222222222222222222222222222222222222222"}}]});
    tree(page(vec![screen_a, screen_b]))
}

pub fn text_fixture() -> Doc {
    tree(page(vec![
        json!({"type": "frame", "props": {"x": 0, "y": 0, "w": 300, "h": 120, "fill": solid("#ffffff"),
        "layout": {"dir": "column", "gap": 6, "pad": [12, 12, 12, 12]}},
      "children": [text("Hamburgefonstiv 0123", 24.0, json!({"weight": 700})),
                   text("The quick brown fox jumps over the lazy dog", 13.0, json!({})),
                   text("small caption text 9px", 9.0, json!({}))]}),
    ]))
}

// ------------------------------------------------------------------------------------------------ compare

pub fn pixels(png: &[u8]) -> (Vec<u8>, i32, i32) {
    let img = Image::from_encoded(Data::new_copy(png)).expect("decode png");
    let (w, h) = (img.width(), img.height());
    let info = ImageInfo::new((w, h), ColorType::RGBA8888, AlphaType::Premul, None);
    let mut px = vec![0u8; (w * h * 4) as usize];
    assert!(img.read_pixels(
        &info,
        &mut px,
        (w * 4) as usize,
        (0, 0),
        CachingHint::Disallow
    ));
    (px, w, h)
}

/// (mean abs diff over RGB, share of pixels whose worst channel differs by > 48)
pub fn diff(a: &[u8], b: &[u8]) -> (f64, f64) {
    let (pa, w, h) = pixels(a);
    let (pb, w2, h2) = pixels(b);
    assert_eq!((w, h), (w2, h2), "size differs");
    let n = (w * h) as usize;
    let (mut sum, mut big) = (0u64, 0usize);
    for i in 0..n {
        let mut worst = 0i32;
        for c in 0..3 {
            let d = (pa[i * 4 + c] as i32 - pb[i * 4 + c] as i32).abs();
            sum += d as u64;
            worst = worst.max(d);
        }
        big += (worst > 48) as usize;
    }
    (sum as f64 / (n * 3) as f64, big as f64 / n as f64)
}

/// Tolerance across machines: FreeType (Linux) and CoreText (Mac) rasterise glyph edges differently.
pub const MAX_MEAN: f64 = 1.5;
pub const MAX_BIG: f64 = 0.01;

pub fn golden(name: &str, png: &[u8]) {
    golden_tol(name, png, MAX_MEAN, MAX_BIG);
}

/// Large glyphs are mostly edge: FreeType and CoreText place those edges a fraction of a pixel apart, so the text
/// close-ups (>= 100 %) get a wider band than the layout shots. Layout (rects, gradients, glass) stays tight.
pub fn golden_tol(name: &str, png: &[u8], max_mean: f64, max_big: f64) {
    let path = here().join("tests/golden").join(format!("{name}.png"));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, png).unwrap();
        return;
    }
    let want = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("missing golden {} (UPDATE_GOLDEN=1)", path.display()));
    let (mean, big) = diff(png, &want);
    println!(
        "golden {name}: mean {mean:.3}/255, >48: {:.4}%",
        big * 100.0
    );
    assert!(
        mean <= max_mean && big <= max_big,
        "{name}: mean {mean:.3} (max {max_mean}), big {big:.5} (max {max_big})"
    );
}

pub fn shot(r: &mut Renderer, w: f32, h: f32) -> Vec<u8> {
    r.set_view(w, h, 1.0);
    r.fit_all();
    cpu::render_png(r)
}
