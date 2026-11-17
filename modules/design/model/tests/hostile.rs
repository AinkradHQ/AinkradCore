//! Security-review regressions: byte budget, attacker-sized ids, string charsets, system scoping, clock bounds,
//! order exhaustion.

use std::time::{Duration, Instant};

use design_model::ids::{between, is_order, rebalance};
use design_model::resolve::ResolveError;
use design_model::tree::{MoveError, MoveRecord, forest};
use design_model::validate::{self, Cx};
use design_model::{Doc, Node, NodeType, Theme, lint, resolve};
use serde_json::{Value, json};

const PAGE: &str = "n_pageaaaaaaaa";

fn node(
    ty: NodeType,
    parent: Option<&str>,
    order: &str,
    props: Value,
    text: Option<String>,
) -> Node {
    Node {
        ty,
        parent: parent.map(str::to_string),
        order: order.into(),
        clock: 1,
        name: String::new(),
        props: props.as_object().unwrap().clone(),
        text,
    }
}

fn base() -> Doc {
    let mut d = Doc::default();
    d.nodes.insert(
        PAGE.into(),
        node(NodeType::Page, None, "a", json!({}), None),
    );
    d
}

#[test]
fn byte_budget_refuses_a_text_bomb_fast() {
    // 2 texts of 100 000 chars in one component, 500 instances: 100 MB expanded from a ~300 KB document
    let mut d = base();
    let comp = "n_compaaaaaaaa";
    d.nodes.insert(
        comp.into(),
        node(NodeType::Component, Some(PAGE), "a", json!({}), None),
    );
    for (i, id) in ["n_textaaaaaaaa", "n_textbaaaaaaa"].into_iter().enumerate() {
        d.nodes.insert(
            id.into(),
            node(
                NodeType::Text,
                Some(comp),
                &format!("{}1", (b'a' + i as u8) as char),
                json!({}),
                Some("x".repeat(100_000)),
            ),
        );
    }
    for i in 0..500usize {
        let id = format!(
            "n_aaaaaaaaaa{}{}",
            (b'a' + (i / 26) as u8) as char,
            (b'a' + (i % 26) as u8) as char
        );
        d.nodes.insert(
            id,
            node(
                NodeType::Instance,
                Some(PAGE),
                &format!("{}1", (b'a' + (i % 26) as u8) as char),
                json!({"component": format!("dd_main/{comp}")}),
                None,
            ),
        );
    }
    assert!(serde_json::to_vec(&d).unwrap().len() < 500_000);
    // debug build, shared 2-vCPU box: the budget stops the work at ~64 MB of text, about 4 s here (release: well under a second)
    let t = Instant::now();
    assert_eq!(
        resolve("dd_main", &d, None, Theme::Day).unwrap_err(),
        ResolveError::TooLarge
    );
    assert!(
        lint("dd_main", &d, None, None)
            .iter()
            .any(|f| f.rule == "resolve.too-large")
    );
    assert!(
        t.elapsed() < Duration::from_secs(20),
        "refused slowly: {:?}",
        t.elapsed()
    );
}

#[test]
fn huge_ids_never_reach_the_output() {
    let big = format!("n_{}", "a".repeat(1_000_000));
    let mut d = base();
    d.nodes.insert(
        big.clone(),
        node(NodeType::Frame, Some(PAGE), "b", json!({}), None),
    );
    d.nodes.insert(
        "n_aaaaaaaaaaaa".into(),
        node(NodeType::Frame, Some(&big), "a", json!({}), None),
    );
    d.nodes.insert(
        "n_aaaaaaaaaaab".into(),
        node(
            NodeType::Instance,
            Some(PAGE),
            "c",
            json!({"component": format!("dd_main/{big}")}),
            None,
        ),
    );
    for v in validate::doc(&d) {
        assert!(v.path.len() < 200 && v.msg.len() < 200, "{}", v.path.len());
    }
    let r = resolve("dd_main", &d, None, Theme::Day).unwrap();
    assert!(r.diagnostics.iter().any(|x| x.code == "node.id"));
    assert!(
        r.diagnostics
            .iter()
            .all(|x| x.node.len() <= 256 && x.msg.len() <= 256)
    );
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.len() < 10_000, "{}", json.len());
    let findings = lint("dd_main", &d, None, None);
    assert!(findings.iter().any(|f| f.rule == "schema.invalid"));
    assert!(serde_json::to_string(&findings).unwrap().len() < 10_000);
    // a huge component ref is refused, not echoed
    let mut e = base();
    e.nodes.insert(
        "n_aaaaaaaaaaab".into(),
        node(
            NodeType::Instance,
            Some(PAGE),
            "c",
            json!({"component": "dd_main/".to_string() + &"n".repeat(1_000_000)}),
            None,
        ),
    );
    let r = resolve("dd_main", &e, None, Theme::Day).unwrap();
    assert!(serde_json::to_string(&r).unwrap().len() < 10_000);
    assert!(r.pages[0].children[0].component.is_none());
}

#[test]
fn font_family_charset() {
    let ok = |f: &str| {
        validate::prop(
            NodeType::Text,
            "type",
            &json!({"font": {"asset": "a".repeat(64), "family": f}}),
            &mut Cx::raw(),
        )
        .is_ok()
    };
    assert!(ok("Inter Tight-2_x"));
    for bad in [
        "",
        "Evil<script>",
        "a/b",
        "a;b",
        "caf\u{e9}",
        "a\u{202e}b",
        "\"x\"",
        &"a".repeat(101),
    ] {
        assert!(!ok(bad), "{bad:?}");
    }
}

#[test]
fn invisible_formatting_characters_are_refused() {
    assert!(validate::name_str("Button").is_ok());
    for bad in [
        "a\u{202e}b",
        "a\u{200b}b",
        "\u{feff}x",
        "a\u{2028}b",
        "a\u{e0041}b",
        "a\nb",
    ] {
        assert!(validate::name_str(bad).is_err(), "{bad:?}");
    }
    assert!(validate::text_str("family \u{1F468}\u{200D}\u{1F469}, \u{200C}ok\nline\ttab").is_ok());
    for bad in [
        "a\u{202e}b",
        "a\u{200b}b",
        "\u{feff}x",
        "a\u{2066}b",
        "a\u{0}b",
    ] {
        assert!(validate::text_str(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn only_the_named_system_is_used() {
    let mut sys = Doc::default();
    sys.nodes.insert(
        "n_aaaaaaaaaaaa".into(),
        node(NodeType::Component, None, "a", json!({"w": 77}), None),
    );
    let mut d = base();
    d.nodes.insert(
        "n_aaaaaaaaaaab".into(),
        node(
            NodeType::Instance,
            Some(PAGE),
            "a",
            json!({"component": "dd_sys/n_aaaaaaaaaaaa"}),
            None,
        ),
    );
    // the design names no system: a document handed in anyway is not read
    let r = resolve("dd_main", &d, Some(("dd_sys", &sys)), Theme::Day).unwrap();
    assert!(r.diagnostics.iter().any(|x| x.code == "instance.missing"));
    // it names another one
    d.meta.system = Some("dd_other".into());
    let r = resolve("dd_main", &d, Some(("dd_sys", &sys)), Theme::Day).unwrap();
    assert!(r.diagnostics.iter().any(|x| x.code == "system.missing"));
    assert!(r.pages[0].children[0].props.is_empty());
    // and the one it names works
    d.meta.system = Some("dd_sys".into());
    let r = resolve("dd_main", &d, Some(("dd_sys", &sys)), Theme::Day).unwrap();
    assert_eq!(r.pages[0].children[0].props["w"], 77);
}

#[test]
fn remote_clocks_are_bounded() {
    let mut d = base();
    d.nodes.insert(
        "n_aaaaaaaaaaaa".into(),
        node(NodeType::Frame, Some(PAGE), "a", json!({}), None),
    );
    let id = "n_aaaaaaaaaaaa";
    let before = d.clone();
    let rec = |clock| MoveRecord {
        parent: Some(PAGE.into()),
        order: "z".into(),
        clock,
    };
    assert!(!d.apply_remote_move(id, rec(u64::MAX)));
    assert!(!d.apply_remote_move(id, rec(design_model::limits::MAX_CLOCK_JUMP + 10)));
    assert!(!d.apply_remote_move("n_nothere", rec(2)));
    assert_eq!(d, before, "a refused move changes nothing");
    assert_eq!(
        d.move_node(id, Some(PAGE), "z", u64::MAX),
        Err(MoveError::ClockTooHigh)
    );
    assert!(d.apply_remote_move(id, rec(design_model::limits::MAX_CLOCK_JUMP)));
    assert_eq!(d.nodes[id].order, "z");
    // a batch counts the valid ones only
    let n = d.apply_remote_moves([
        (id.to_string(), rec(u64::MAX)),
        (
            id.to_string(),
            rec(design_model::limits::MAX_CLOCK_JUMP + 5),
        ),
    ]);
    assert_eq!(n, 1);
}

#[test]
fn a_thousand_front_inserts_survive_order_exhaustion() {
    let mut d = base();
    let mut rebalances = 0;
    for i in 0..1000usize {
        let kids = forest(&d).children.get(PAGE).cloned().unwrap_or_default();
        let first = kids.first().map(|k| d.nodes[k].order.clone());
        let order = match between(None, first.as_deref()) {
            Some(o) => o,
            None => {
                d.rebalance_children(PAGE).unwrap();
                rebalances += 1;
                let first = forest(&d).children[PAGE]
                    .first()
                    .map(|k| d.nodes[k].order.clone());
                between(None, first.as_deref()).expect("room after a rebalance")
            }
        };
        let id = format!(
            "n_aaaaaaaaa{}{}{}",
            (b'a' + (i / 676) as u8) as char,
            (b'a' + (i / 26 % 26) as u8) as char,
            (b'a' + (i % 26) as u8) as char
        );
        let mut n = node(NodeType::Frame, Some(PAGE), &order, json!({}), None);
        n.clock = d.next_clock();
        d.nodes.insert(id, n);
    }
    assert!(rebalances > 0, "the test must reach exhaustion");
    let f = forest(&d);
    let orders: Vec<&str> = f.children[PAGE]
        .iter()
        .map(|k| d.nodes[k].order.as_str())
        .collect();
    assert_eq!(orders.len(), 1000);
    assert!(
        orders.windows(2).all(|w| w[0] < w[1]),
        "strictly increasing, no ties"
    );
    assert!(orders.iter().all(|o| is_order(o)));
}

#[test]
fn rebalance_spaces_orders() {
    for n in [0, 1, 2, 35, 36, 37, 1000, 20_000] {
        let v = rebalance(n).unwrap();
        assert_eq!(v.len(), n);
        assert!(v.iter().all(|o| is_order(o)), "n={n}");
        assert!(v.windows(2).all(|w| w[0] < w[1]), "n={n}");
        if n > 0 {
            assert!(
                between(None, Some(&v[0])).is_some() && between(Some(&v[n - 1]), None).is_some()
            );
        }
        if n > 1 {
            assert!(
                between(Some(&v[0]), Some(&v[1])).is_some(),
                "room between neighbours, n={n}"
            );
        }
    }
    assert!(rebalance(design_model::limits::MAX_NODES + 1).is_none());
}

#[test]
fn a_huge_token_value_is_refused_not_cloned() {
    // a 1 MB colour token used by 20 rects: invalid tokens are treated as missing, nothing is copied
    let mut sys = Doc::default();
    let huge = format!("#{}", "a".repeat(1_000_000));
    sys.tokens.insert(
        "color.big".into(),
        design_model::Token {
            kind: design_model::TokenKind::Color,
            day: json!(huge),
            night: json!("#000000"),
        },
    );
    sys.tokens.insert(
        "color.ok".into(),
        design_model::Token {
            kind: design_model::TokenKind::Color,
            day: json!("#ffffff"),
            night: json!("#000000"),
        },
    );
    let mut d = base();
    d.meta.system = Some("dd_sys".into());
    for i in 0..20usize {
        let id = format!("n_aaaaaaaaaaa{}", (b'a' + i as u8) as char);
        d.nodes.insert(id, node(NodeType::Rect, Some(PAGE), &format!("{}1", (b'a' + i as u8) as char), json!({"fill": [{"type": "solid", "color": {"token": "color.big"}}], "stroke": {"color": {"token": "color.ok"}}}), None));
    }
    let t = Instant::now();
    let r = resolve("dd_main", &d, Some(("dd_sys", &sys)), Theme::Day).unwrap();
    assert!(r.diagnostics.iter().any(|x| x.code == "token.invalid"));
    assert!(r.diagnostics.iter().any(|x| x.code == "token.missing"));
    assert!(serde_json::to_string(&r).unwrap().len() < 20_000);
    assert_eq!(
        r.pages[0].children[0].props["stroke"]["color"], "#ffffff",
        "valid tokens still work"
    );
    let findings = lint("dd_main", &d, Some(("dd_sys", &sys)), None);
    assert!(findings.iter().any(|f| f.rule == "token.invalid"));
    assert!(serde_json::to_string(&findings).unwrap().len() < 50_000);
    assert!(t.elapsed() < Duration::from_secs(5));
}
