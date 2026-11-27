use super::*;
use design_model::schema::Meta;
use std::collections::BTreeMap;

const PHONE: Dim = (360.0, 630.0);

fn node(
    ty: NodeType,
    parent: Option<&str>,
    order: &str,
    name: &str,
    props: Value,
    text: Option<&str>,
) -> Node {
    Node {
        ty,
        parent: parent.map(str::to_owned),
        order: order.into(),
        clock: 0,
        prev: None,
        name: name.into(),
        props: props.as_object().unwrap().clone(),
        text: text.map(str::to_owned),
    }
}

fn doc() -> Doc {
    let mut nodes = BTreeMap::new();
    nodes.insert(
        "n_page00000000".into(),
        node(NodeType::Page, None, "a", "Page 1", json!({}), None),
    );
    nodes.insert(
        "n_frame0000000".into(),
        node(NodeType::Frame, Some("n_page00000000"), "b", "Home",
            json!({"x": 0, "y": 0, "w": 390, "h": 844, "fill": [{"type": "solid", "color": "#FAFAFA"}]}), None),
    );
    nodes.insert(
        "n_card00000000".into(),
        node(
            NodeType::Frame,
            Some("n_frame0000000"),
            "a",
            "Card",
            json!({"x": 16, "y": 100, "w": 358, "h": 120, "layout": {"dir": "column", "gap": 8}}),
            None,
        ),
    );
    nodes.insert(
        "n_title0000000".into(),
        node(NodeType::Text, Some("n_card00000000"), "a", "Text",
            json!({"w": 300, "h": 30, "type": {"size": 22, "weight": 700}, "fill": [{"type": "solid", "color": "#101828"}]}),
            Some("Your trips")),
    );
    nodes.insert(
        "n_star00000000".into(),
        node(NodeType::Vector, Some("n_card00000000"), "b", "Icon star",
            json!({"w": 16, "h": 16, "path": "M0 0 L1 1", "stroke": {"color": "#F79009", "width": 1}}), None),
    );
    let mut tokens = BTreeMap::new();
    tokens.insert(
        "color.primary".into(),
        Token {
            kind: TokenKind::Color,
            day: json!("#2F7BEF"),
            night: json!("#5B9BFF"),
        },
    );
    tokens.insert(
        "space.md".into(),
        Token {
            kind: TokenKind::Space,
            day: json!(16),
            night: json!(16),
        },
    );
    tokens.insert(
        "type.body".into(),
        Token {
            kind: TokenKind::Type,
            day: json!({"size": 16, "weight": 400, "line": 24}),
            night: json!({}),
        },
    );
    Doc {
        meta: Meta::default(),
        nodes,
        tokens,
    }
}

#[test]
fn the_prompt_carries_tokens_brand_and_sibling_screens() {
    let d = doc();
    let ctx = Context {
        tokens: tokens_of(&d),
        brand: Some("\"Acme\", colours #112233, #AABBCC".into()),
        frames: top_frames(&d)
            .iter()
            .filter_map(|f| summary(&d, f))
            .collect(),
        edit: None,
    };
    assert_eq!(ctx.tokens[0], "color.primary #2F7BEF", "colours first");
    assert!(
        ctx.tokens
            .contains(&"type.body size 16 weight 400 line 24".to_owned())
    );
    let p = prompt("a travel app home", 3, PHONE, &ctx);
    assert!(
        p.contains("color.primary #2F7BEF") && p.contains("space.md 16"),
        "{p}"
    );
    assert!(p.contains("#112233, #AABBCC"));
    assert!(
        p.contains("\"name\":\"Home\"") && p.contains("Your trips") && p.contains("#FAFAFA"),
        "{p}"
    );
    assert!(
        p.contains("exactly 3 directions") && p.contains("Phone rules") && p.contains("status bar")
    );
    assert!(p.contains("same language as the request") && p.contains("never lorem ipsum"));
    assert!(!p.contains("`screens`"), "no flow with three directions");
    assert!(prompt("x", 1, PHONE, &Context::default()).contains("`screens`"));
    assert!(!prompt("x", 1, PHONE, &Context::default()).contains("design system"));
}

#[test]
fn the_platform_rules_follow_the_size() {
    let c = Context::default();
    let d = prompt("x", 3, (1440.0, 900.0), &c);
    assert!(
        d.contains("one desktop screen, 1440 wide and 900 tall") && d.contains("at most 1200 wide")
    );
    assert!(d.contains("12-column") && d.contains("footer") && d.contains("At most 60 elements"));
    assert!(prompt("x", 3, (800.0, 600.0), &c).contains("Tablet rules"));
    assert!(prompt("x", 3, PHONE, &c).contains("At most 24 elements"));
}

#[test]
fn an_edit_sends_the_frame_in_the_answer_shape() {
    let d = doc();
    let f = frame_json(&d, "n_frame0000000").unwrap();
    assert_eq!(f["background"], "#FAFAFA");
    let card = &f["elements"][0];
    assert_eq!(
        (card["kind"].clone(), card["layout"]["dir"].clone()),
        (json!("group"), json!("column"))
    );
    assert_eq!(card["children"][0]["text"], "Your trips");
    assert_eq!(card["children"][0]["size"], 22);
    assert_eq!(
        card["children"][1],
        json!({"kind": "icon", "icon": "star", "size": 16.0, "fill": "#F79009", "w": 16.0, "h": 16.0})
    );
    assert!(frame_json(&d, "n_card00000000").is_some(), "any frame");
    assert!(
        frame_json(&d, "n_title0000000").is_none(),
        "a text is no frame"
    );
    assert!(frame_json(&d, "n_nope00000000").is_none());
    assert_eq!(frame_size(&d, "n_frame0000000"), Some((390.0, 844.0)));
    let ctx = Context {
        edit: Some(f),
        ..Context::default()
    };
    let p = prompt("make the title bigger", 1, (390.0, 844.0), &ctx);
    assert!(
        p.contains("Keep every element") && p.contains("Your trips") && !p.contains("`screens`")
    );
    // the edited answer round-trips into the same element kinds
    let a = format!("{{\"directions\":[{}]}}", ctx.edit.unwrap());
    let dirs = crate::compose_answer::parse(&a, 1, false).unwrap();
    let b = crate::compose_build::build_ops(&dirs, None, None, 0.0, (390.0, 844.0));
    assert!(b.ops.iter().any(|o| o["name"] == "Icon star"));
    assert!(b.ops.iter().any(|o| o["text"] == "Your trips"));
}
