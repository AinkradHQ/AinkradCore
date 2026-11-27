use super::*;
use crate::apply::{mint, resolve_temps};
use crate::compose_build::{Built, build_ops};
use design_model::NodeType;

/// Every op the build makes is accepted by the doc model (its validators run in `apply_ops`), links included.
fn applies(b: &Built) -> design_doc::Live {
    let (mut ops, ids) = resolve_temps(b.ops.clone(), &|_| false, &mut mint).unwrap();
    for (from, to) in &b.links {
        ops.push(json!({"op": "set", "id": ids[from], "key": "link", "value": {"to": ids[to]}}));
    }
    let ops: Vec<design_doc::Op> = serde_json::from_value(Value::Array(ops)).unwrap();
    let mut live = design_doc::Live::new();
    live.apply_ops(&ops).unwrap();
    live
}

fn answer(n: usize) -> String {
    let d = r##"{"name":"Calm","summary":"Soft","background":"#F5F7FB","elements":[
        {"kind":"text","x":24,"y":80,"w":300,"text":"Hi","size":34,"weight":700,"fill":"#14213D"},
        {"kind":"rect","x":24,"y":540,"w":312,"h":52,"radius":14,"fill":"#2F7BEF"},
        {"kind":"star"}]}"##;
    format!(
        "Here you go:\n{{\"directions\":[{}]}}",
        vec![d; n].join(",")
    )
}

#[test]
fn keeps_the_first_n_and_accepts_fewer() {
    assert_eq!(parse(&answer(3), 3, false).unwrap().len(), 3);
    assert_eq!(
        parse(&answer(4), 3, false).unwrap().len(),
        3,
        "the first three kept"
    );
    assert_eq!(
        parse(&answer(2), 3, false).unwrap().len(),
        2,
        "fewer accepted"
    );
    assert_eq!(parse(&answer(3), 1, false).unwrap().len(), 1);
    assert!(parse("no json", 3, false).is_err());
    assert!(parse("{\"directions\":[]}", 3, false).is_err());
    // a bare direction is read as one
    assert_eq!(
        parse(r#"{"name":"x","elements":[]}"#, 1, false)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn plain_ops_are_valid_and_unknown_kinds_dropped() {
    let dirs = parse(&answer(3), 3, false).unwrap();
    let b = build_ops(&dirs, None, None, 0.0, (360.0, 630.0));
    assert_eq!(b.frames.len(), 3);
    // page + 3 frames + 3 x 2 known elements
    assert_eq!(b.ops.len(), 1 + 3 + 6);
    assert!(b.links.is_empty());
    let frame = &b.ops[1]["props"];
    assert_eq!(
        (frame["radius"].clone(), frame["clip"].clone()),
        (json!(0), json!(true))
    );
    applies(&b);
}

#[test]
fn hostile_numbers_and_colours_are_clamped() {
    let d = parse(
        r##"{"directions":[{"background":"red; drop","elements":[
            {"kind":"rect","x":1e300,"w":"wide","fill":"javascript:"},
            {"kind":"text","x":-5,"y":10,"text":"x","size":9999,"opacity":-3,"stroke":{"color":"#zz"}}]}]}"##,
        1,
        false,
    )
    .unwrap();
    let b = build_ops(&d, Some("n_aaaaaaaaaaaa"), Some("a"), 400.0, (360.0, 630.0));
    assert_eq!(b.ops[0]["props"]["fill"][0]["color"], "#F5F7FB");
    assert_eq!(b.ops[0]["props"]["x"], 400.0);
    assert_eq!(b.ops[1]["props"]["x"], 360.0);
    assert_eq!(b.ops[1]["props"]["w"], 80.0);
    assert_eq!(b.ops[1]["props"]["fill"][0]["color"], "#D6E6FF");
    assert_eq!(b.ops[2]["props"]["type"]["size"], 96.0);
    assert_eq!(b.ops[2]["props"]["opacity"], 0.05);
    assert!(b.ops[2]["props"].get("stroke").is_none());
}

#[test]
fn text_height_follows_the_wrapped_lines() {
    // 200 wide at 16: about 22 characters a line
    assert_eq!(text_height("Hello", 200.0, 16.0, 400, 21.0), 21.0);
    let long = "The quick brown fox jumps over the lazy dog and keeps running far away";
    let h = text_height(long, 200.0, 16.0, 400, 21.0);
    assert!((63.0..=105.0).contains(&h), "{h}");
    assert_eq!(text_height("a\nb\nc", 200.0, 16.0, 400, 20.0), 60.0);
    assert!(text_height(&"x".repeat(100), 100.0, 10.0, 400, 13.0) >= 13.0 * 5.0);
    assert!(
        text_height(long, 200.0, 16.0, 700, 21.0) >= h,
        "bold is wider"
    );
}

#[test]
fn a_wrapped_text_pushes_down_what_is_under_it() {
    let d = parse(
        r##"{"directions":[{"elements":[
            {"kind":"text","x":24,"y":40,"w":160,"size":20,"text":"A long headline that wraps over several lines here"},
            {"kind":"rect","x":24,"y":70,"w":160,"h":40},
            {"kind":"rect","x":250,"y":70,"w":60,"h":40}]}]}"##,
        1,
        false,
    )
    .unwrap();
    let b = build_ops(&d, None, None, 0.0, (360.0, 630.0));
    let text = &b.ops[2]["props"];
    let bottom = text["y"].as_f64().unwrap() + text["h"].as_f64().unwrap();
    assert!(text["h"].as_f64().unwrap() > 26.0 * 2.0);
    assert!(
        b.ops[3]["props"]["y"].as_f64().unwrap() >= bottom,
        "pushed below the text"
    );
    assert_eq!(b.ops[4]["props"]["y"], 70.0, "not under the text: stays");
}

#[test]
fn rich_kinds_become_valid_nodes() {
    let d = parse(
        r##"{"directions":[{"background":{"from":"#101828","to":"#1D2939","angle":180},"elements":[
            {"kind":"group","name":"Card","x":16,"y":100,"w":328,"fill":"#FFFFFF","radius":12,
             "stroke":{"color":"#E4E7EC","width":1},"shadow":{"y":4,"blur":16,"color":"#1018281A"},
             "layout":{"dir":"column","gap":8,"pad":16,"align":"stretch"},
             "children":[
                {"kind":"image","label":"Beach","h":140,"radius":8},
                {"kind":"text","text":"Weekend in Lisbon","size":18,"weight":600,"line":24},
                {"kind":"group","layout":{"dir":"row","gap":6,"align":"center"},"children":[
                    {"kind":"icon","icon":"star","size":16,"fill":"#F79009"},
                    {"kind":"text","text":"4.8","size":14}]}]},
            {"kind":"icon","icon":"no-such-icon","x":10,"y":10},
            {"kind":"rect","x":16,"y":560,"w":328,"h":48,"radius":12,"opacity":0.9,"next":true,
             "fill":{"from":"#2F7BEF","to":"#5B9BFF"}}]}]}"##,
        1,
        false,
    )
    .unwrap();
    let b = build_ops(&d, None, None, 0.0, (360.0, 630.0));
    let live = applies(&b);
    let doc = live.read();
    let by = |name: &str| doc.nodes.values().find(|n| n.name == name).unwrap().clone();
    let card = by("Card");
    assert_eq!(card.props["layout"]["dir"], "column");
    assert_eq!(card.props["layout"]["pad"], json!([16.0, 16.0, 16.0, 16.0]));
    assert!(
        card.props["h"].as_f64().unwrap() > 140.0 + 24.0,
        "hugs its children"
    );
    assert_eq!(card.props["shadow"][0]["blur"], 16.0);
    let img = by("Image: Beach");
    assert_eq!(img.ty, NodeType::Frame);
    assert_eq!(img.props["w"], 296.0, "the card's inner width");
    let star = by("Icon star");
    assert_eq!(
        (star.ty, star.props["w"].clone()),
        (NodeType::Vector, json!(16.0))
    );
    assert!(
        doc.nodes.values().all(|n| n.name != "Icon no-such-icon"),
        "unknown icon skipped"
    );
    let button = doc.nodes.values().find(|n| n.ty == NodeType::Rect).unwrap();
    assert_eq!(button.props["fill"][0]["type"], "linear");
    assert_eq!(button.props["opacity"], 0.9);
}

#[test]
fn every_icon_is_valid_path_data() {
    for (name, _) in ICONS {
        for size in [12.0, 24.0, 48.0] {
            let p = icon_path(name, size).unwrap();
            design_model::svgpath::validate(&p).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
    }
}

#[test]
fn a_flow_places_screens_in_a_row_and_links_them_in_order() {
    let a = r##"{"directions":[{"name":"Sign up","screens":[
        {"name":"Welcome","elements":[{"kind":"rect","x":16,"y":560,"w":328,"h":48,"next":true}]},
        {"name":"Details","elements":[]},
        {"name":"Done","elements":[]}]}]}"##;
    let d = parse(a, 1, true).unwrap();
    assert_eq!(d[0].screens.len(), 3);
    let b = build_ops(&d, None, None, 100.0, (360.0, 630.0));
    assert_eq!(b.frames.len(), 1);
    assert_eq!(b.frames[0].len(), 3);
    let xs: Vec<f64> = b
        .ops
        .iter()
        .filter(|o| o["type"] == "frame")
        .map(|o| o["props"]["x"].as_f64().unwrap())
        .collect();
    assert_eq!(xs, [100.0, 520.0, 940.0]);
    assert_eq!(b.links.len(), 2);
    let button = b.ops.iter().find(|o| o["type"] == "rect").unwrap()["id"].clone();
    assert_eq!(json!(b.links[0].0), button, "from the next element");
    assert_eq!(b.links[1].0, b.frames[0][1], "else from the frame");
    assert_eq!(b.links[1].1, b.frames[0][2]);
    applies(&b);
    // without flow only the first screen is drawn; a flow keeps at most six
    assert_eq!(parse(a, 1, false).unwrap()[0].screens.len(), 1);
    let many = format!("{{\"screens\":[{}]}}", ["{\"elements\":[]}"; 9].join(","));
    assert_eq!(parse(&many, 1, true).unwrap()[0].screens.len(), MAX_SCREENS);
}

#[test]
fn the_element_cap_follows_the_screen_width() {
    let els = vec![r#"{"kind":"rect","x":0,"y":0,"w":10,"h":10}"#; 80].join(",");
    let d = parse(&format!("{{\"elements\":[{els}]}}"), 1, false).unwrap();
    let rects = |w: f64| {
        build_ops(&d, None, None, 0.0, (w, 900.0))
            .ops
            .iter()
            .filter(|o| o["type"] == "rect")
            .count()
    };
    assert_eq!((rects(360.0), rects(800.0), rects(1440.0)), (24, 40, 60));
}
