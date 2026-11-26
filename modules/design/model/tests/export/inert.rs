use super::*;

#[test]
fn link_role_name_and_component_are_data_attributes() {
    let target = id(2);
    let e = screen(
        json!({"w": 9, "h": 9}),
        vec![
            json!({"type": "rect", "name": "Go", "props": {"w": 1, "h": 1, "role": "control", "link": {"to": target, "transition": "fade"}}}),
        ],
    );
    for a in [
        "data-role=\"control\"",
        &format!("data-link=\"{target}\""),
        "data-transition=\"fade\"",
        "data-name=\"Go\"",
    ] {
        assert!(e.html.contains(a), "{a} in {}", e.html);
    }
    assert!(!e.html.contains("<a ") && !e.html.contains("href=\"#"));
}
#[test]
fn instances_expand_their_component_and_overrides_apply() {
    let comp = id(4);
    let doc = tree(
        json!({"type": "page", "children": [
            {"type": "frame", "props": {"w": 100, "h": 100}, "children": [
                {"type": "instance", "props": {"component": format!("dd_main/{comp}"), "x": 5, "y": 6,
                    "overrides": {".": {"opacity": 0.25}, (id(5)): {"fill": solid("#00ff00")}}}}]},
            {"type": "component", "props": {"x": 300, "y": 0, "w": 20, "h": 20}, "children": [
                {"type": "rect", "props": {"w": 20, "h": 20, "fill": solid("#ff0000")}}]}]}),
        json!({}),
    );
    let (d, n) = both(&doc);
    let e = export(&d, &n, &ExportOpts::new(Theme::Day)).unwrap();
    assert!(
        e.html
            .contains(&format!("data-component=\"dd_main/{comp}\"")),
        "{}",
        e.html
    );
    has(&e.css, ".n1", "opacity:0.25");
    has(&e.css, ".n1", "left:5px");
    // the override of the component's child wins over its own fill
    has(
        &e.css,
        ".n2",
        "background-image:linear-gradient(#00ff00,#00ff00)",
    );
}
#[test]
fn the_screen_is_chosen_by_id_and_a_missing_one_is_an_error() {
    let doc = tree(
        json!({"type": "page", "children": [{"type": "frame", "name": "A", "props": {"w": 1, "h": 1}}, {"type": "frame", "name": "B", "props": {"w": 2, "h": 2}}]}),
        json!({}),
    );
    let (d, n) = both(&doc);
    let mut o = ExportOpts::new(Theme::Day);
    let b = id(3);
    o.screen = Some(b.as_str());
    let e = export(&d, &n, &o).unwrap();
    assert_eq!(e.screen, b);
    assert!(e.html.contains("<title>B</title>"));
    o.screen = Some("n_zzzzzzzzzzzz");
    assert_eq!(
        export(&d, &n, &o).unwrap_err(),
        design_model::ExportError::NoScreen
    );
    o.screen = None;
    o.page = 4;
    assert_eq!(
        export(&d, &n, &o).unwrap_err(),
        design_model::ExportError::NoPage
    );
}
/// Every prop of the schema, as (key, node type, value). Each must change the export; the list is checked against
/// the validator's own table so a new prop cannot be added without a row here.
fn props() -> Vec<(&'static str, &'static str, Value)> {
    let tgt = json!(id(2));
    vec![
        ("x", "rect", json!(3)),
        ("y", "rect", json!(3)),
        ("w", "rect", json!(30)),
        ("h", "rect", json!(30)),
        ("sizing", "rect", json!({"w": "fill"})),
        ("layout", "frame", json!({"dir": "column", "gap": 3})),
        ("clip", "frame", json!(true)),
        ("fill", "rect", solid("#123456")),
        ("stroke", "rect", json!({"color": "#123456", "width": 3})),
        ("radius", "rect", json!(5)),
        (
            "shadow",
            "rect",
            json!([{"x": 1, "y": 1, "blur": 1, "spread": 0, "color": "#000000"}]),
        ),
        ("material", "rect", json!("glass")),
        ("opacity", "rect", json!(0.4)),
        ("blend", "rect", json!("screen")),
        ("visible", "rect", json!(false)),
        ("link", "rect", json!({"to": tgt})),
        ("role", "rect", json!("card")),
        ("type", "text", json!({"size": 33})),
        ("path", "vector", json!("M0 0 L5 5")),
        ("asset", "image", json!(HASH)),
        ("fit", "image", json!("tile")),
        ("rotation", "rect", json!(30)),
        ("blur", "rect", json!(8)),
        ("backdrop_blur", "rect", json!(8)),
    ]
}
#[test]
fn every_schema_prop_changes_the_export() {
    let all = [
        "fill",
        "x",
        "y",
        "w",
        "h",
        "sizing",
        "opacity",
        "blend",
        "visible",
        "link",
        "role",
        "stroke",
        "shadow",
        "layout",
        "clip",
        "radius",
        "material",
        "type",
        "path",
        "asset",
        "fit",
        "component",
        "overrides",
        "rotation",
        "blur",
        "backdrop_blur",
        // `locked` is an editor prop: it never changes the export
    ];
    for k in all {
        assert!(
            design_model::validate::applies(k, design_model::NodeType::Frame).is_some(),
            "{k} is not a prop any more"
        );
    }
    let covered: Vec<&str> = props()
        .iter()
        .map(|p| p.0)
        .chain(["component", "overrides"])
        .collect();
    for k in all {
        assert!(covered.contains(&k), "no export test for the prop `{k}`");
    }
    for (key, ty, value) in props() {
        let node = |props: Value| {
            let mut n = json!({"type": ty, "props": props});
            if ty == "text" {
                n["text"] = json!("t");
            }
            if ty == "frame" {
                n["children"] = json!([{"type": "rect", "props": {"w": 1, "h": 1}}]);
            }
            n
        };
        // a base every prop is tried on: some props only show beside others (a stroke needs a size, a fit an asset)
        let mut base = json!({"w": 10, "h": 10});
        if ty == "image" {
            base["asset"] = json!(FONT);
        }
        if ty == "vector" {
            base["path"] = json!("M0 0 L1 1");
            // a vector draws one `<path>` per fill or stroke: with neither, its path changes nothing
            base["fill"] = solid("#336699");
        }
        let with = {
            let mut p = base.clone();
            p[key] = value.clone();
            p
        };
        let a = screen(json!({"w": 99, "h": 99}), vec![node(base)]);
        let b = screen(json!({"w": 99, "h": 99}), vec![node(with)]);
        assert_ne!(
            (&a.html, &a.css),
            (&b.html, &b.css),
            "the prop `{key}` on a {ty} changes nothing"
        );
    }
}
#[test]
fn the_package_is_inert() {
    let evil = "<script>alert(1)</script>\"><img src=x onerror=alert(1)>&'";
    let e = screen(
        json!({"w": 99, "h": 99}),
        vec![
            json!({"type": "text", "name": evil, "text": evil, "props": {"type": {"size": 12}}}),
            json!({"type": "image", "name": evil, "props": {"w": 4, "h": 4, "asset": HASH}}),
            json!({"type": "vector", "name": evil, "props": {"path": "M0 0 L4 4", "fill": solid("#ff0000")}}),
            json!({"type": "rect", "props": {"w": 4, "h": 4, "link": {"to": id(2)}, "fill": [{"type": "image", "asset": HASH}]}}),
        ],
    );
    let html = e.html.to_ascii_lowercase();
    for bad in [
        "<script",
        "<a ",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "<link rel=\"import",
        "javascript:",
        "<img",
        "<meta http-equiv=\"refresh",
    ] {
        assert!(!html.contains(bad), "`{bad}` in {html}");
    }
    // the hostile text is there, as text
    assert!(e.html.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(1)&gt;&amp;&#39;"));
    // no event attribute on any tag
    for tag in html.split('<').skip(1) {
        let head = tag.split('>').next().unwrap();
        // quoted values are escaped (no raw `"` inside), so every even piece is outside a value
        let outside = head.split('"').step_by(2).collect::<Vec<_>>().join("");
        let attrs: Vec<&str> = outside.split(' ').skip(1).collect();
        assert!(
            attrs.iter().all(|a| !a.starts_with("on")),
            "event attribute in <{head}>"
        );
    }
    assert!(e.html.contains("script-src 'none'") && e.html.contains("connect-src 'none'"));
    // the only links are the stylesheet, and every URL is package-local and built from a hash
    assert_eq!(e.html.matches("href=").count(), 1);
    assert!(e.html.contains("href=\"style.css\""));
    let mut rest = e.css.as_str();
    while let Some(i) = rest.find("url(") {
        rest = &rest[i + 4..];
        let u = rest.split(')').next().unwrap();
        let ok = u
            .strip_prefix("\"fonts/")
            .or_else(|| u.strip_prefix("\"assets/"))
            .and_then(|s| s.strip_suffix('"'))
            .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(ok || u.starts_with('#'), "unexpected url({u})");
    }
    for bad in [
        "@import",
        "http:",
        "https:",
        "//",
        "expression(",
        "javascript:",
        "</style",
    ] {
        assert!(!e.css.contains(bad), "`{bad}` in the css");
    }
}
