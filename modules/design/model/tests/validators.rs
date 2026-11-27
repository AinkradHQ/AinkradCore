//! Validator behaviour on good and hostile values (the unit-level half of the V1-02 acceptance).

use design_model::NodeType;
use design_model::schema::{Doc, Token, TokenKind as K};
use design_model::validate::{Cx, doc, prop, token};
use serde_json::{Value, json};

fn ok(ty: NodeType, k: &str, v: Value) -> bool {
    prop(ty, k, &v, &mut Cx::raw()).is_ok()
}

#[test]
fn accepts_schema_values() {
    use NodeType::*;
    assert!(ok(
        Frame,
        "layout",
        json!({"dir":"row","gap":8,"pad":[1,2,3,4],"align":"center","wrap":true})
    ));
    assert!(ok(
        Rect,
        "radius",
        json!([6, 8, 12, {"token":"radius.control"}])
    ));
    assert!(ok(
        Rect,
        "fill",
        json!([{"type":"solid","color":"#aabbcc"},{"type":"linear","stops":[{"at":0,"color":"#000000ff"},{"at":1,"color":{"token":"color.bg"}}]}])
    ));
    assert!(ok(
        Text,
        "type",
        json!({"font":"system","size":13,"weight":500,"transform":"none"})
    ));
    assert!(ok(Vector, "path", json!("M0 0L5 5z")));
    assert!(ok(Image, "asset", json!("a".repeat(64))));
    assert!(ok(
        Instance,
        "overrides",
        json!({".": {"opacity":0.5}, "n_aaaaaaaaaaaa/n_bbbbbbbbbbbb": {"text":"Ok","fill":null}})
    ));
}

#[test]
fn refuses_hostile_values() {
    use NodeType::*;
    for (ty, k, v) in [
        (Rect, "bogus", json!(1)),
        (Rect, "path", json!("M0 0")),
        (Page, "x", json!(1)),
        (Rect, "x", json!(1e300)),
        (Rect, "x", json!("1")),
        (Rect, "w", json!(-1)),
        (Rect, "fill", json!([{"type":"solid","color":"red"}])),
        (
            Rect,
            "fill",
            json!([{"type":"image","asset":"../../etc/passwd"}]),
        ),
        (
            Rect,
            "fill",
            json!([{"type":"solid","color":"#000000","extra":1}]),
        ),
        (Rect, "opacity", json!(2)),
        (Rect, "radius", json!([1, 2])),
        (
            Rect,
            "fill",
            json!(vec![json!({"type":"solid","color":"#000000"}); 17]),
        ),
        (Text, "type", json!({"font":{"asset":"zz"}})),
        (Text, "type", json!({"font":"Comic Sans"})),
        (Vector, "path", json!("M0 0 <script>")),
        (Frame, "layout", json!({"dir":"diagonal"})),
        (Frame, "link", json!({"to":"https://evil"})),
        (Instance, "component", json!("../../x")),
        (Instance, "overrides", json!({"../x": {}})),
        (
            Instance,
            "overrides",
            json!({".": {"component": "dd_a/n_aaaaaaaaaaaa"}}),
        ),
        (
            Rect,
            "fill",
            json!([{"type":"solid","color":{"token":"Bad Name"}}]),
        ),
    ] {
        assert!(!ok(ty, k, v.clone()), "{ty:?}.{k} = {v} should be refused");
    }
    // refs are refused once resolved
    assert!(
        prop(
            NodeType::Rect,
            "radius",
            &json!({"token":"radius.control"}),
            &mut Cx::resolved()
        )
        .is_err()
    );
}

#[test]
fn tokens_by_kind() {
    let t = |kind, day, night| token(&Token { kind, day, night });
    assert!(t(K::Color, json!("#fff"), json!("#000000")).is_err()); // 3-digit refused
    assert!(t(K::Color, json!("#ffff00"), json!("#0000ff")).is_ok());
    assert!(t(K::Radius, json!(8), json!(8)).is_ok());
    assert!(t(K::Radius, json!(8), json!({"token":"x"})).is_err());
    assert!(t(K::Material, json!("glass"), json!("well")).is_ok());
}

#[test]
fn doc_limits_and_ids() {
    let d: Doc = serde_json::from_value(
        json!({"nodes": {"bad": {"type":"rect","parent":null,"order":"a0","name":"\u{0}"}}}),
    )
    .unwrap();
    let v = doc(&d);
    assert_eq!(v.len(), 3, "{v:?}"); // id, order (ends in 0), name
}

#[test]
fn rotation_lock_effects_and_strokes() {
    use NodeType::*;
    assert!(ok(Rect, "rotation", json!(-45.5)));
    assert!(ok(Text, "locked", json!(true)));
    assert!(ok(Frame, "blur", json!(8)));
    assert!(ok(Frame, "backdrop_blur", json!(20)));
    assert!(ok(
        Rect,
        "shadow",
        json!([{"x":0,"y":2,"blur":4,"color":"#00000040","inset":true}])
    ));
    // one stroke (the old shape) or a list, each with an alignment and dashes
    assert!(ok(Rect, "stroke", json!({"color":"#ff0000","width":2})));
    assert!(ok(
        Ellipse,
        "stroke",
        json!([{"color":"#ff0000","width":2,"align":"outside","dash":[4,2]},{"color":{"token":"color.bg"},"align":"center"}])
    ));
    for (ty, k, v) in [
        (Page, "rotation", json!(10)),
        (Rect, "rotation", json!(361)),
        (Rect, "rotation", json!("10")),
        (Rect, "locked", json!(1)),
        (Rect, "blur", json!(-1)),
        (Rect, "backdrop_blur", json!(1001)),
        (Rect, "shadow", json!([{"color":"#000000","inset":"yes"}])),
        (Rect, "stroke", json!({"color":"#000000","align":"middle"})),
        (Rect, "stroke", json!({"color":"#000000","dash":[-1]})),
        (
            Rect,
            "stroke",
            json!({"color":"#000000","dash":vec![1; 17]}),
        ),
        (Rect, "stroke", json!(vec![json!({"color":"#000000"}); 9])),
        (Rect, "stroke", json!([{"color":"#000000","bogus":1}])),
    ] {
        assert!(!ok(ty, k, v.clone()), "{k} {v} on {ty:?} accepted");
    }
}
