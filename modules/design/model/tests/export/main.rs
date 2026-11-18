//! V6-03: the HTML/CSS export. Every schema prop changes the export and says what the renderer does with it; the
//! package is inert; both themes live in one sheet. Pixel fidelity against the renderer is the helper's test
//! (`helper/tests/fidelity.rs`), because it needs Skia and Chromium and this crate has neither.
use design_model::{Doc, ExportOpts, Exported, Resolved, Theme, export, resolve};
use serde_json::{Value, json};
const HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const FONT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
fn id(n: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut v, mut s) = (n, vec![b'a'; 12]);
    for i in (0..12).rev() {
        s[i] = A[v % 32];
        v /= 32;
    }
    format!("n_{}", String::from_utf8(s).unwrap())
}
/// A nested `{type, name, props, text, children}` tree as a flat document; ids come in pre-order.
fn tree(root: Value, tokens: Value) -> Doc {
    fn walk(
        v: &Value,
        parent: Option<&str>,
        n: &mut usize,
        out: &mut serde_json::Map<String, Value>,
        o: usize,
    ) {
        *n += 1;
        let me = id(*n);
        let mut node = json!({
            "type": v["type"], "parent": parent, "order": format!("{o:04}1"), "clock": 1,
            "name": v.get("name").cloned().unwrap_or(json!("")),
            "props": v.get("props").cloned().unwrap_or(json!({})),
        });
        if let Some(t) = v.get("text") {
            node["text"] = t.clone();
        }
        out.insert(me.clone(), node);
        for (i, c) in v
            .get("children")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            walk(c, Some(&me), n, out, i + 1);
        }
    }
    let mut out = serde_json::Map::new();
    walk(&root, None, &mut 0, &mut out, 1);
    serde_json::from_value(json!({"meta": {"version": 1}, "nodes": out, "tokens": tokens})).unwrap()
}
fn both(doc: &Doc) -> (Resolved, Resolved) {
    (
        resolve("dd_main", doc, None, Theme::Day).unwrap(),
        resolve("dd_main", doc, None, Theme::Night).unwrap(),
    )
}
/// A page holding one screen with `props` and `children`.
fn run(props: Value, children: Vec<Value>, tokens: Value) -> Exported {
    let doc = tree(
        json!({"type": "page", "children": [{"type": "frame", "name": "Home", "props": props, "children": children}]}),
        tokens,
    );
    let (d, n) = both(&doc);
    assert!(d.diagnostics.is_empty(), "{:?}", d.diagnostics);
    export(&d, &n, &ExportOpts::new(Theme::Day)).unwrap()
}
fn screen(props: Value, children: Vec<Value>) -> Exported {
    run(props, children, json!({}))
}
/// The declarations of `sel` in `css` (the first rule that names it).
fn rule<'a>(css: &'a str, sel: &str) -> Vec<&'a str> {
    let head = format!("{sel}{{");
    let line = css
        .lines()
        .find(|l| l.starts_with(&head))
        .unwrap_or_else(|| panic!("no rule {sel} in\n{css}"));
    line[head.len()..line.len() - 1].split(';').collect()
}
fn has(css: &str, sel: &str, decl: &str) {
    let r = rule(css, sel);
    assert!(r.contains(&decl), "{sel} lacks `{decl}`: {r:?}");
}
fn solid(c: &str) -> Value {
    json!([{"type": "solid", "color": c}])
}
#[test]
fn the_screen_is_absolute_at_the_origin_with_its_size() {
    let e = screen(json!({"w": 390, "h": 844.5}), vec![]);
    for d in [
        "position:absolute",
        "left:0",
        "top:0",
        "width:390px",
        "height:844.5px",
    ] {
        has(&e.css, ".n0", d);
    }
    assert!(e.html.contains("data-name=\"Home\"") && e.html.contains("data-type=\"frame\""));
    assert!(e.html.contains("data-theme=\"day\""));
}
#[test]
fn x_y_place_children_of_a_frame_without_layout() {
    let e = screen(
        json!({"w": 100, "h": 100}),
        vec![json!({"type": "rect", "props": {"x": 12, "y": -7.25, "w": 5, "h": 5}})],
    );
    for d in ["position:absolute", "left:12px", "top:-7.25px"] {
        has(&e.css, ".n1", d);
    }
}
#[test]
fn sizing_fixed_hug_fill() {
    let row = json!({"layout": {"dir": "row"}, "w": 200, "h": 100});
    let kid =
        |sizing: Value| json!({"type": "rect", "props": {"w": 10, "h": 10, "sizing": sizing}});
    let e = screen(
        row,
        vec![
            kid(json!({"w": "fill", "h": "fill"})),
            kid(json!({"w": "hug", "h": "fixed"})),
        ],
    );
    // main axis of a row: grow from zero; cross axis: stretch
    has(&e.css, ".n1", "flex:1 1 0px");
    has(&e.css, ".n1", "align-self:stretch");
    // hug ignores w; fixed uses h
    assert!(!rule(&e.css, ".n2").iter().any(|d| d.starts_with("width:")));
    has(&e.css, ".n2", "height:10px");
    let col = screen(
        json!({"layout": {"dir": "column"}, "w": 50, "h": 50}),
        vec![kid(json!({"w": "fill", "h": "fill"}))],
    );
    has(&col.css, ".n1", "flex:1 1 0px");
    let free = screen(
        json!({"w": 50, "h": 50}),
        vec![kid(json!({"w": "fill", "h": "fill"}))],
    );
    has(&free.css, ".n1", "width:100%");
    has(&free.css, ".n1", "height:100%");
}
#[test]
fn layout_dir_gap_pad_align_justify_wrap() {
    let e = screen(
        json!({"w": 10, "h": 10, "layout": {"dir": "column", "gap": 8, "pad": [1, 2, 3, 4], "align": "center", "justify": "between", "wrap": true}}),
        vec![],
    );
    for d in [
        "display:flex",
        "flex-direction:column",
        "gap:8px",
        "padding:1px 2px 3px 4px",
        "align-items:center",
        "justify-content:space-between",
        "flex-wrap:wrap",
    ] {
        has(&e.css, ".n0", d);
    }
    let e = screen(
        json!({"layout": {"align": "end", "justify": "end"}}),
        vec![],
    );
    has(&e.css, ".n0", "flex-direction:row");
    has(&e.css, ".n0", "align-items:flex-end");
    has(&e.css, ".n0", "justify-content:flex-end");
    let e = screen(
        json!({"layout": {"align": "stretch", "justify": "center"}}),
        vec![],
    );
    has(&e.css, ".n0", "align-items:stretch");
    has(&e.css, ".n0", "justify-content:center");
}
#[test]
fn clip_visible_opacity_blend() {
    let kid = json!({"type": "rect", "props": {"w": 1, "h": 1}});
    let e = screen(json!({"clip": true, "w": 5, "h": 5}), vec![kid.clone()]);
    has(&e.css, ".n0", "overflow:hidden");
    // nothing to clip, nothing to say
    let e = screen(json!({"clip": true, "w": 5, "h": 5}), vec![]);
    assert!(
        !e.css.contains("overflow:hidden;") && !rule(&e.css, ".n0").contains(&"overflow:hidden")
    );
    let e = screen(
        json!({"w": 5, "h": 5, "visible": false, "opacity": 0.5, "blend": "multiply"}),
        vec![],
    );
    for d in [
        "visibility:hidden",
        "opacity:0.5",
        "mix-blend-mode:multiply",
    ] {
        has(&e.css, ".n0", d);
    }
    let e = screen(
        json!({"w": 5, "h": 5, "blend": "normal", "opacity": 1}),
        vec![],
    );
    assert!(!e.css.contains("mix-blend-mode") && !e.css.contains("opacity"));
}
#[test]
fn radius_number_array_and_ellipse() {
    let e = screen(
        json!({"w": 9, "h": 9}),
        vec![
            json!({"type": "rect", "props": {"w": 4, "h": 4, "radius": 6}}),
            json!({"type": "rect", "props": {"w": 4, "h": 4, "radius": [1, 2, 3, 4]}}),
            json!({"type": "ellipse", "props": {"w": 4, "h": 4}}),
        ],
    );
    has(&e.css, ".n1", "border-radius:6px 6px 6px 6px");
    has(&e.css, ".n2", "border-radius:1px 2px 3px 4px");
    has(&e.css, ".n3", "border-radius:50%");
}

mod inert;
mod paint;
