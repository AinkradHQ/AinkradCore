#![no_main]
//! V1-02: every validator, the resolver, the lint and the move logic on arbitrary bytes. The first byte picks the
//! entry point (`sel % 5`). Properties: no panic or hang, and
//!  - whatever the resolver returns re-validates (props against the schema with refs refused) and stays in budget;
//!  - `forest` reaches every node exactly once, whatever the parent links say;
//!  - `between` is strictly between its bounds and always a valid order; `rebalance` is increasing;
//!  - local moves never create a cycle, whatever the remote moves did; a rebalance keeps parents and makes orders
//!    strictly increasing; a remote clock above the cap is refused without a change.
use std::collections::BTreeSet;

use design_model::limits::MAX_RESOLVED_NODES;
use design_model::tree::{MoveRecord, forest};
use design_model::validate::{self, Cx};
use design_model::{Doc, Node, NodeType, ResolvedNode, Theme, ids, lint, resolve, svgpath};
use libfuzzer_sys::fuzz_target;

const TYPES: [NodeType; 9] = [
    NodeType::Page,
    NodeType::Frame,
    NodeType::Text,
    NodeType::Rect,
    NodeType::Ellipse,
    NodeType::Image,
    NodeType::Vector,
    NodeType::Component,
    NodeType::Instance,
];

/// Same ids as the committed seeds (tests/fixtures use them too), so instances and tokens really resolve.
const DOC: &str = "dd_main";
const SYS: &str = "dd_sys";

fn covers_once(d: &Doc) {
    let f = forest(d);
    let mut seen = BTreeSet::new();
    let mut stack: Vec<&str> = f
        .pages
        .iter()
        .chain(&f.detached)
        .map(String::as_str)
        .collect();
    while let Some(i) = stack.pop() {
        assert!(seen.insert(i), "node reached twice");
        stack.extend(f.children.get(i).into_iter().flatten().map(String::as_str));
    }
    assert_eq!(seen.len(), d.nodes.len(), "a node is unreachable");
}

fn revalidates(n: &ResolvedNode, count: &mut usize) {
    *count += 1;
    for (k, v) in &n.props {
        validate::prop(n.ty, k, v, &mut Cx::resolved())
            .expect("a resolved prop must be valid and token-free");
    }
    for c in &n.children {
        revalidates(c, count);
    }
}

fn frame(parent: &str, order: &str) -> Node {
    Node {
        ty: NodeType::Frame,
        parent: Some(parent.into()),
        order: order.into(),
        clock: 1,
        name: String::new(),
        props: Default::default(),
        text: None,
    }
}

fn is_descendant(d: &Doc, node: &str, of: &str) -> bool {
    let mut cur = d.nodes.get(node).and_then(|n| n.parent.as_deref());
    for _ in 0..=d.nodes.len() {
        match cur {
            Some(c) if c == of => return true,
            Some(c) => cur = d.nodes.get(c).and_then(|n| n.parent.as_deref()),
            None => return false,
        }
    }
    false
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel % 5 {
        0 => {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = svgpath::validate(s);
            }
        }
        1 => {
            // one prop map against a node type, raw (token refs allowed) and resolved, and as overrides
            if let Ok(serde_json::Value::Object(m)) = serde_json::from_slice(rest) {
                let ty = TYPES[usize::from(sel / 5) % TYPES.len()];
                let _ = validate::props(ty, &m, &mut Cx::raw());
                let _ = validate::props(ty, &m, &mut Cx::resolved());
                let _ = validate::override_props(&serde_json::Value::Object(m), &mut Cx::raw());
            }
        }
        2 => {
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = (
                    ids::is_node_id(s),
                    ids::is_doc_id(s),
                    ids::is_token_name(s),
                    ids::parse_component_ref(s),
                );
                let _ = (validate::name_str(s), validate::text_str(s));
                let (a, b) = s.split_once('|').unwrap_or((s, ""));
                if ids::is_order(a) && ids::is_order(b) {
                    if let Some(m) = ids::between(Some(a), Some(b)) {
                        assert!(
                            ids::is_order(&m) && a < m.as_str() && m.as_str() < b,
                            "{a} {m} {b}"
                        );
                    }
                    if let Some(m) = ids::between(None, Some(b)) {
                        assert!(ids::is_order(&m) && m.as_str() < b);
                    }
                    if let Some(m) = ids::between(Some(a), None) {
                        assert!(ids::is_order(&m) && a < m.as_str());
                    }
                }
                let v = ids::rebalance(rest.len() % 200).expect("within the cap");
                assert!(v.windows(2).all(|w| w[0] < w[1]) && v.iter().all(|o| ids::is_order(o)));
            }
        }
        3 => {
            // the design and its system, split by a 2-byte length; sel >= 128 forces the design to name the system
            let (head, tail) = rest.split_at(rest.len().min(2));
            let n = head.iter().fold(0usize, |a, &b| a << 8 | usize::from(b));
            let (d, s) = tail.split_at(n.min(tail.len()));
            let Ok(mut doc) = Doc::from_json(d) else {
                return;
            };
            let sys = Doc::from_json(s).ok();
            if sel >= 128 {
                doc.meta.system = Some(SYS.into());
            }
            let system = sys.as_ref().map(|s| (SYS, s));
            let _ = validate::doc(&doc);
            let _ = lint(DOC, &doc, system, None);
            covers_once(&doc);
            for theme in [Theme::Day, Theme::Night] {
                if let Ok(r) = resolve(DOC, &doc, system, theme) {
                    assert!(r.diagnostics.len() <= 1000);
                    let mut count = 0;
                    for p in r.pages.iter().chain(&r.detached) {
                        revalidates(p, &mut count);
                    }
                    assert!(count <= MAX_RESOLVED_NODES);
                }
            }
        }
        _ => {
            // moves: a few frames under a page, then local moves (cycle-checked) mixed with remote ones (not)
            let Some((&b0, ops)) = rest.split_first() else {
                return;
            };
            let n = 2 + usize::from(b0 % 8);
            let name = |i: usize| format!("n_aaaaaaaaaa{}a", (b'a' + i as u8) as char);
            let page = "n_pageaaaaaaaa";
            let mut d = Doc::default();
            d.nodes.insert(
                page.into(),
                Node {
                    ty: NodeType::Page,
                    parent: None,
                    order: "a".into(),
                    clock: 0,
                    name: String::new(),
                    props: Default::default(),
                    text: None,
                },
            );
            for i in 0..n {
                d.nodes.insert(
                    name(i),
                    frame(page, &format!("{}1", (b'a' + i as u8) as char)),
                );
            }
            let mut any_remote = false;
            for op in ops.chunks_exact(3).take(64) {
                let (node, parent) = (name(usize::from(op[0]) % n), usize::from(op[1]) % (n + 1));
                let pid = if parent == n {
                    page.to_string()
                } else {
                    name(parent)
                };
                let order = format!("{}1", (b'a' + op[2] % 26) as char);
                if op[0] & 0x80 != 0 {
                    // rebalance the page's children: strictly increasing orders, the same parents, no node lost
                    let parents: Vec<_> = d.nodes.values().map(|n| n.parent.clone()).collect();
                    d.rebalance_children(page).unwrap();
                    assert_eq!(
                        parents,
                        d.nodes
                            .values()
                            .map(|n| n.parent.clone())
                            .collect::<Vec<_>>()
                    );
                    let f = forest(&d);
                    let kids = f.children.get(page).map_or(&[][..], |k| &k[..]);
                    assert!(
                        kids.windows(2)
                            .all(|w| d.nodes[&w[0]].order < d.nodes[&w[1]].order)
                    );
                } else if op[2] & 0xC0 == 0xC0 {
                    // a remote clock far above the document's: refused, nothing changes
                    any_remote = true;
                    let before = d.clone();
                    let rec = MoveRecord {
                        parent: Some(pid),
                        order,
                        clock: u64::MAX - u64::from(op[1]),
                    };
                    assert!(
                        !d.apply_remote_move(&node, rec),
                        "a clock above the cap was accepted"
                    );
                    assert_eq!(d, before);
                } else if op[2] & 0x80 == 0 {
                    let clock = d.next_clock();
                    let before = d.clone();
                    let into_desc = pid == node || is_descendant(&d, &pid, &node);
                    match d.move_node(&node, Some(&pid), &order, clock) {
                        Ok(()) => assert!(!into_desc, "a move into a descendant was accepted"),
                        Err(_) => assert_eq!(d, before, "a refused move changed the document"),
                    }
                    if !any_remote {
                        assert!(forest(&d).broken.is_empty(), "a local move made a cycle");
                    }
                } else {
                    any_remote = true;
                    let _ = d.apply_remote_move(
                        &node,
                        MoveRecord {
                            parent: Some(pid),
                            order,
                            clock: u64::from(op[2] & 0x7f),
                        },
                    );
                }
                covers_once(&d);
            }
        }
    }
});
