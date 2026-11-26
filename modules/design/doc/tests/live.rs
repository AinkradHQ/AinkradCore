//! V2-02: the live document.

use design_doc::{Error, Live, parse_ops};
use serde_json::json;

const PAGE: &str = "n_aaaaaaaaaaaa";
const FRAME: &str = "n_bbbbbbbbbbbb";
const LABEL: &str = "n_cccccccccccc";

fn ops(v: serde_json::Value) -> Vec<design_doc::Op> {
    parse_ops(v.to_string().as_bytes()).unwrap()
}

fn seed(l: &mut Live) {
    l.apply_ops(&ops(json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": FRAME, "type": "frame", "parent": PAGE, "order": "a", "name": "Screen",
         "props": {"w": 360, "h": 640}},
        {"op": "add", "id": LABEL, "type": "text", "parent": FRAME, "order": "a", "text": "Hi"},
    ])))
    .unwrap();
}

#[test]
fn ops_write_one_undo_step_and_read_back() {
    let mut l = Live::new();
    seed(&mut l);
    let d = l.read();
    assert_eq!(d.nodes.len(), 3);
    assert_eq!(d.nodes[FRAME].props["w"], json!(360));
    assert_eq!(d.nodes[LABEL].text.as_deref(), Some("Hi"));
    l.apply_ops(&ops(json!([
        {"op": "set", "id": FRAME, "key": "w", "value": 400},
        {"op": "text", "id": LABEL, "text": "Hello"},
        {"op": "name", "id": FRAME, "name": "Home"},
    ])))
    .unwrap();
    let d = l.read();
    assert_eq!(
        (
            d.nodes[FRAME].props["w"].clone(),
            d.nodes[FRAME].name.as_str(),
            d.nodes[LABEL].text.as_deref()
        ),
        (json!(400), "Home", Some("Hello"))
    );
    assert!(l.undo());
    let d = l.read();
    assert_eq!(
        (
            d.nodes[FRAME].props["w"].clone(),
            d.nodes[LABEL].text.as_deref()
        ),
        (json!(360), Some("Hi"))
    );
    assert!(l.redo());
    assert_eq!(l.read().nodes[FRAME].props["w"], json!(400));
}

#[test]
fn a_refused_batch_writes_nothing() {
    let mut l = Live::new();
    seed(&mut l);
    let before = l.read();
    l.outbox(true);
    for bad in [
        json!([{"op": "set", "id": FRAME, "key": "w", "value": 1}, {"op": "set", "id": FRAME, "key": "nope", "value": 1}]),
        json!([{"op": "move", "id": FRAME, "parent": LABEL, "order": "b"}]),
        json!([{"op": "move", "id": PAGE, "parent": FRAME, "order": "b"}]),
        json!([{"op": "add", "id": "bad", "type": "rect", "parent": FRAME, "order": "b"}]),
        json!([{"op": "add", "id": "n_dddddddddddd", "type": "rect", "parent": null, "order": "b"}]),
        json!([{"op": "text", "id": FRAME, "text": "x"}]),
        json!([{"op": "delete", "id": "n_zzzzzzzzzzzz"}]),
    ] {
        assert!(
            matches!(l.apply_ops(&ops(bad.clone())), Err(Error::Refused(_))),
            "{bad}"
        );
    }
    assert!(parse_ops(br#"[{"op":"set","id":"x","key":"w","value":1,"extra":1}]"#).is_err());
    assert!(parse_ops(b"not json").is_err());
    assert_eq!(l.read(), before);
    assert!(l.outbox(false).is_empty());
}

#[test]
fn delete_takes_the_subtree_and_move_reparents() {
    let mut l = Live::new();
    seed(&mut l);
    l.apply_ops(&ops(
        json!([{"op": "move", "id": LABEL, "parent": PAGE, "order": "b"}]),
    ))
    .unwrap();
    // a page holds any node
    assert_eq!(l.read().nodes[LABEL].parent.as_deref(), Some(PAGE));
    l.apply_ops(&ops(json!([{"op": "delete", "id": PAGE}])))
        .unwrap();
    assert!(l.read().nodes.is_empty());
    assert!(l.undo());
    assert_eq!(l.read().nodes.len(), 3);
}

#[test]
fn two_replicas_converge_through_sync_bytes() {
    let (mut a, mut b) = (Live::new(), Live::new());
    seed(&mut a);
    b.apply_remote(&a.diff(&b.state_vector()).unwrap()).unwrap();
    assert_eq!(a.read(), b.read());
    assert!(b.outbox(false).is_empty(), "remote updates are not echoed");
    b.apply_ops(&ops(
        json!([{"op": "set", "id": FRAME, "key": "w", "value": 500}]),
    ))
    .unwrap();
    a.apply_ops(&ops(json!([{"op": "name", "id": FRAME, "name": "A"}])))
        .unwrap();
    let (ua, ub) = (a.outbox(true), b.outbox(true));
    assert!(a.outbox(true).is_empty());
    a.apply_remote(&ub).unwrap();
    b.apply_remote(&ua).unwrap();
    assert_eq!(a.read(), b.read());
    assert_eq!(a.read().nodes[FRAME].props["w"], json!(500));
    // undo on b only undoes b's own edit
    assert!(b.undo());
    assert_eq!(b.read().nodes[FRAME].name, "A");
}

#[test]
fn hostile_bytes_are_refused() {
    let mut l = Live::new();
    for b in [
        &b"\xff\xff\xff\xff"[..],
        b"\x01",
        b"\x00\x00\x01",
        &[0x7f; 64],
    ] {
        let _ = l.apply_remote(b);
        let _ = l.diff(b);
        let _ = l.presence().apply(b);
    }
    assert!(matches!(
        l.apply_remote(&vec![0; design_doc::MAX_UPDATE_BYTES + 1]),
        Err(Error::TooLarge)
    ));
    assert!(l.read().nodes.is_empty());
}

#[test]
fn presence_round_trip() {
    let (mut a, mut b) = (Live::new(), Live::new());
    assert!(a.presence().encode_local().is_empty());
    assert!(a.presence().set_local("[1]").is_err());
    assert!(a.presence().set_local(&"x".repeat(5000)).is_err());
    a.presence()
        .set_local(r#"{"label":"Ahmed","sel":["n_bbbbbbbbbbbb"]}"#)
        .unwrap();
    let u = a.presence().encode_local();
    b.presence().apply(&u).unwrap();
    let peers = b.presence().peers();
    let one = peers.as_object().unwrap().values().next().unwrap();
    assert_eq!(one["label"], json!("Ahmed"));
    // our own state relayed back is ignored
    a.presence().apply(&u).unwrap();
    assert!(a.presence().peers().as_object().unwrap().is_empty());
}

#[test]
fn token_ops_set_replace_remove_undo_and_sync_through_the_gate() {
    use design_doc::Replica;
    let mut l = Live::new();
    let tok = |day: &str, night: &str| json!({"kind": "color", "day": day, "night": night});
    l.apply_ops(&ops(json!([
        {"op": "token", "name": "color.primary", "value": tok("#2F7BEF", "#5B9BFF")},
        {"op": "token", "name": "space.md", "value": {"kind": "space", "day": 16, "night": 16}},
    ])))
    .unwrap();
    let d = l.read();
    assert_eq!(d.tokens.len(), 2);
    assert_eq!(d.tokens["color.primary"].day, json!("#2F7BEF"));
    // replace: one undo step puts the first value back
    l.apply_ops(&ops(json!([
        {"op": "token", "name": "color.primary", "value": tok("#111111", "#EEEEEE")},
    ])))
    .unwrap();
    assert_eq!(l.read().tokens["color.primary"].day, json!("#111111"));
    assert!(l.undo());
    assert_eq!(l.read().tokens["color.primary"].day, json!("#2F7BEF"));
    // remove
    l.apply_ops(&ops(
        json!([{"op": "token", "name": "space.md", "value": null}]),
    ))
    .unwrap();
    assert_eq!(l.read().tokens.len(), 1);
    assert!(l.undo());
    assert_eq!(l.read().tokens.len(), 2);
    // the Core's replica (the sync gate) accepts the whole thing
    let mut r = Replica::new();
    r.apply_remote(&l.outbox(true)).expect("tokens sync");
    assert_eq!(r.read().unwrap().tokens.len(), 2);
}

#[test]
fn bad_token_ops_are_refused_and_write_nothing() {
    let mut l = Live::new();
    let bad = [
        json!({"op": "token", "name": "Color.Primary", "value": {"kind": "color", "day": "#fff", "night": "#000"}}),
        json!({"op": "token", "name": "color..x", "value": {"kind": "color", "day": "#fff", "night": "#000"}}),
        json!({"op": "token", "name": "color.x", "value": {"kind": "color", "day": "red", "night": "#000000"}}),
        json!({"op": "token", "name": "color.x", "value": {"kind": "color", "day": {"token": "color.y"}, "night": "#000000"}}),
        json!({"op": "token", "name": "space.x", "value": {"kind": "space", "day": -4, "night": 4}}),
        json!({"op": "token", "name": "color.x", "value": {"kind": "nope", "day": "#fff", "night": "#000"}}),
        json!({"op": "token", "name": "color.x", "value": {"kind": "color", "day": "#ffffff", "night": "#000000", "extra": 1}}),
    ];
    for b in bad {
        let r = l.apply_ops(&ops(json!([b.clone()])));
        assert!(matches!(r, Err(Error::Refused(_))), "{b}: {r:?}");
    }
    assert!(l.read().tokens.is_empty());
}
