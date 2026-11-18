use super::*;

#[test]
fn fills_stack_with_the_last_one_on_top() {
    let e = screen(
        json!({"w": 9, "h": 9, "fill": [
            {"type": "solid", "color": "#ff0000"},
            {"type": "linear", "angle": 90, "stops": [{"at": 0, "color": "#00ff0080"}, {"at": 1, "color": "#0000ff"}]},
            {"type": "image", "asset": HASH, "mode": "tile"}
        ]}),
        vec![],
    );
    let r = rule(&e.css, ".n0");
    let bg = r
        .iter()
        .find(|d| d.starts_with("background-image:"))
        .unwrap();
    let want = format!(
        "background-image:url(\"assets/{HASH}\"),linear-gradient(90deg,#00ff0080 0%,#0000ff 100%),linear-gradient(#ff0000,#ff0000)"
    );
    assert_eq!(*bg, want);
    has(
        &e.css,
        ".n0",
        "background-repeat:repeat,no-repeat,no-repeat",
    );
    has(&e.css, ".n0", "background-size:auto,auto,auto");
    assert_eq!(e.images, vec![HASH.to_owned()]);
}
#[test]
fn image_node_asset_and_fit() {
    let img =
        |fit: &str| json!({"type": "image", "props": {"w": 8, "h": 8, "asset": HASH, "fit": fit}});
    let e = screen(
        json!({"w": 9, "h": 9}),
        vec![img("fill"), img("crop"), img("fit"), img("tile")],
    );
    has(&e.css, ".n1", "background-size:cover");
    has(&e.css, ".n2", "background-size:cover");
    has(&e.css, ".n3", "background-size:contain");
    has(&e.css, ".n4", "background-repeat:repeat");
    has(&e.css, ".n1", "background-position:center");
    has(&e.css, ".n4", "background-position:0 0");
    assert_eq!(e.images, vec![HASH.to_owned()]);
}
#[test]
fn stroke_is_inside_and_shadows_keep_their_order() {
    let e = screen(
        json!({"w": 9, "h": 9, "stroke": {"color": "#112233", "width": 2, "role": "focus"},
        "shadow": [{"x": 0, "y": 1, "blur": 2, "spread": 3, "color": "#00000040"}, {"x": 4, "y": 5, "blur": 6, "spread": 0, "color": "#ff000080"}]}),
        vec![],
    );
    has(
        &e.css,
        ".n0",
        "box-shadow:inset 0 0 0 2px #112233,4px 5px 6px 0px #ff000080,0px 1px 2px 3px #00000040",
    );
    assert!(e.html.contains("data-stroke-role=\"focus\""));
    let e = screen(
        json!({"w": 9, "h": 9, "stroke": {"color": "#112233", "width": 0}}),
        vec![],
    );
    assert!(!e.css.contains("box-shadow"));
}
#[test]
fn materials_are_layers_behind_the_children_and_themed() {
    let e = screen(
        json!({"w": 9, "h": 9, "material": "glass", "fill": solid("#ff0000"), "stroke": {"color": "#00ff00", "width": 1}}),
        vec![json!({"type": "rect", "props": {"w": 1, "h": 1}})],
    );
    has(&e.css, ".n0", "isolation:isolate");
    for p in [".n0::before", ".n0::after"] {
        for d in [
            "content:\"\"",
            "position:absolute",
            "inset:0",
            "border-radius:inherit",
        ] {
            has(&e.css, p, d);
        }
    }
    has(&e.css, ".n0::before", "z-index:-2");
    has(&e.css, ".n0::after", "z-index:-1");
    has(&e.css, ".n0::before", "backdrop-filter:blur(16px)");
    // fills and the stroke sit above the material
    has(
        &e.css,
        ".n0::after",
        "background-image:linear-gradient(#ff0000,#ff0000)",
    );
    has(&e.css, ".n0::after", "box-shadow:inset 0 0 0 1px #00ff00");
    // day and night tints differ: one variable each side
    let r = rule(&e.css, ".n0::before");
    let tint = r
        .iter()
        .find(|d| d.starts_with("background-color:var("))
        .expect("tint is themed");
    let v = tint
        .trim_start_matches("background-color:var(")
        .trim_end_matches(')');
    assert!(
        e.css.contains(&format!(":root,[data-theme=\"day\"]{{"))
            && e.css.contains(&format!("{v}:#ffffff4c"))
    );
    assert!(e.css.contains(&format!("{v}:#ffffff1a")));
    let well = screen(json!({"w": 9, "h": 9, "material": "well"}), vec![]);
    assert!(well.css.contains(":#0000000e") && well.css.contains(":#00000046"));
    assert!(!well.css.contains("backdrop-filter"));
    let clear = screen(json!({"w": 9, "h": 9, "material": "clear"}), vec![]);
    assert!(clear.css.contains(":#ffffff50") && clear.css.contains(":#ffffff24"));
    assert!(
        !rule(&clear.css, ".n0::before")
            .iter()
            .any(|d| d.starts_with("background-color:")),
        "clear has a rim and no tint"
    );
}
fn text(t: &str, ty: Value, extra: Value) -> Value {
    let mut props = json!({"type": ty});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        props[k] = v;
    }
    json!({"type": "text", "text": t, "props": props})
}
#[test]
fn text_type_props() {
    let e = screen(
        json!({"w": 300, "h": 100}),
        vec![text(
            "hello world",
            json!({"font": "system", "size": 20, "weight": 700, "line": 28, "tracking": 0.05, "transform": "capitalize", "align": "center"}),
            json!({"fill": solid("#112233")}),
        )],
    );
    for d in [
        "font-size:20px",
        "font-weight:700",
        "line-height:28px",
        "letter-spacing:1px",
        "text-align:center",
        "color:#112233",
        "white-space:pre-wrap",
    ] {
        has(&e.css, ".n1", d);
    }
    assert!(e.html.contains(">Hello World</div>"), "{}", e.html);
    assert!(
        rule(&e.css, ".n1")
            .iter()
            .any(|d| d.starts_with("font-family:\"SF Pro\""))
    );
    let up = screen(
        json!({}),
        vec![text(
            "ab\ncd",
            json!({"transform": "uppercase", "align": "right"}),
            json!({}),
        )],
    );
    assert!(up.html.contains(">AB\nCD</div>"));
    has(&up.css, ".n1", "text-align:right");
    let lo = screen(
        json!({}),
        vec![text(
            "AB",
            json!({"transform": "lowercase", "align": "justify"}),
            json!({}),
        )],
    );
    assert!(lo.html.contains(">ab</div>"));
    has(&lo.css, ".n1", "text-align:justify");
    // no fill: black by day, white by night (a variable)
    assert!(
        rule(&lo.css, ".n1")
            .iter()
            .any(|d| d.starts_with("color:var("))
    );
    assert!(lo.css.contains(":#000000") && lo.css.contains(":#ffffff"));
}
#[test]
fn library_fonts_are_faces_and_the_fallback_is_the_system_font() {
    let doc = tree(
        json!({"type": "page", "children": [{"type": "frame", "props": {}, "children": [
            text("a", json!({"font": {"asset": FONT, "family": "Brand Sans", "weight": 600}, "size": 12}), json!({}))]}]}),
        json!({}),
    );
    let (d, n) = both(&doc);
    let mut o = ExportOpts::new(Theme::Night);
    let e = export(&d, &n, &o).unwrap();
    assert_eq!(e.fonts, vec![FONT.to_owned()]);
    assert!(e.css.contains(&format!(
        "@font-face{{font-family:\"asset-{FONT}\";src:url(\"fonts/{FONT}\");font-weight:1 1000}}"
    )));
    assert!(
        rule(&e.css, ".n1")
            .iter()
            .any(|d| d.starts_with(&format!("font-family:\"asset-{FONT}\",\"SF Pro\"")))
    );
    assert!(e.html.contains("data-theme=\"night\""));
    o.fallback_font = Some(HASH);
    let e = export(&d, &n, &o).unwrap();
    assert_eq!(e.fonts, vec![HASH.to_owned(), FONT.to_owned()]);
    has(
        &e.css,
        ".n1",
        &format!("font-family:\"asset-{FONT}\",\"design-system-fallback\""),
    );
    assert!(e.css.contains(&format!(
        "font-family:\"design-system-fallback\";src:url(\"fonts/{HASH}\")"
    )));
    // a hash that is not a hash is not a file name
    o.fallback_font = Some("../../etc/passwd");
    assert!(!export(&d, &n, &o).unwrap().css.contains("passwd"));
}
#[test]
fn vectors_are_svg_with_paint_and_a_size_from_their_path() {
    let vec = |extra: Value| {
        let mut p = json!({"path": "M0 0 L60 0 L30 50 Z", "fill": solid("#f59e0b"), "stroke": {"color": "#16181f", "width": 2}});
        for (k, v) in extra.as_object().cloned().unwrap_or_default() {
            p[k] = v;
        }
        json!({"type": "vector", "props": p})
    };
    let e = screen(json!({"w": 99, "h": 99}), vec![vec(json!({}))]);
    assert!(e.html.contains("<svg class=\"n n1\""), "{}", e.html);
    assert!(
        e.html
            .contains("<path class=\"n1p0\" d=\"M0 0 L60 0 L30 50 Z\"/>")
    );
    assert!(
        e.html
            .contains("<path class=\"n1k\" d=\"M0 0 L60 0 L30 50 Z\"/>")
    );
    has(&e.css, ".n1p0", "fill:#f59e0b");
    has(&e.css, ".n1k", "stroke:#16181f");
    has(&e.css, ".n1k", "stroke-width:2px");
    has(&e.css, ".n1k", "fill:none");
    has(&e.css, ".n1", "overflow:visible");
    // a hugging vector is as big as its path says (the host measures it); unmeasured it is empty, not 300 x 150
    has(&e.css, ".n1", "width:0px");
    let b = |_: &str| Some((60.0, 50.0));
    let doc = tree(
        json!({"type": "page", "children": [{"type": "frame", "props": {"w": 99, "h": 99}, "children": [vec(json!({}))]}]}),
        json!({}),
    );
    let (d, n) = both(&doc);
    let mut o = ExportOpts::new(Theme::Day);
    o.path_bounds = Some(&b);
    let e = export(&d, &n, &o).unwrap();
    has(&e.css, ".n1", "width:60px");
    has(&e.css, ".n1", "height:50px");
    // a linear fill on a known box is a gradient along the CSS line
    let g = screen(
        json!({"w": 99, "h": 99}),
        vec![vec(
            json!({"w": 60, "h": 50, "fill": [{"type": "linear", "angle": 90, "stops": [{"at": 0, "color": "#ff0000"}, {"at": 1, "color": "#0000ff"}]}]}),
        )],
    );
    assert!(g.html.contains("<linearGradient id=\"g1_0\" gradientUnits=\"userSpaceOnUse\" x1=\"0\" y1=\"25\" x2=\"60\" y2=\"25\">"), "{}", g.html);
    has(&g.css, ".n1p0", "fill:url(#g1_0)");
    has(&g.css, ".n1s0_1", "stop-color:#0000ff");
}
#[test]
fn tokens_become_variables_per_theme() {
    let tokens = json!({"color.fg": {"kind": "color", "day": "#111111", "night": "#eeeeee"}, "space.pad": {"kind": "space", "day": 4, "night": 4}});
    let e = run(
        json!({"w": 9, "h": 9, "fill": [{"type": "solid", "color": {"token": "color.fg"}}], "layout": {"pad": [{"token": "space.pad"}, 0, 0, 0]}}),
        vec![],
        tokens,
    );
    let bg = rule(&e.css, ".n0")
        .into_iter()
        .find(|d| d.starts_with("background-image:"))
        .unwrap();
    assert!(bg.starts_with("background-image:var(--v"), "{bg}");
    let v = bg
        .trim_start_matches("background-image:var(")
        .trim_end_matches(')');
    let day = e
        .css
        .lines()
        .find(|l| l.starts_with(":root,[data-theme=\"day\"]{"))
        .unwrap();
    let night = e
        .css
        .lines()
        .find(|l| l.starts_with("[data-theme=\"night\"]{"))
        .unwrap();
    assert!(
        day.contains("#111111") && night.contains("#eeeeee"),
        "{day} / {night} ({v})"
    );
    // equal in both themes: stays a plain value
    has(&e.css, ".n0", "padding:4px 0px 0px 0px");
}
#[test]
fn the_page_background_follows_the_page_fill_and_the_theme() {
    let e = screen(json!({"w": 9, "h": 9}), vec![]);
    assert!(e.css.contains(":#e9ecf2") && e.css.contains(":#16171b"));
    let doc = tree(
        json!({"type": "page", "props": {"fill": solid("#abcdef")}, "children": [{"type": "frame", "props": {"w": 1, "h": 1}}]}),
        json!({}),
    );
    let (d, n) = both(&doc);
    let e = export(&d, &n, &ExportOpts::new(Theme::Day)).unwrap();
    has(&e.css, "body", "background-color:#abcdef");
}
