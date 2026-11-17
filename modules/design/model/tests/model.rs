//! V1-02 acceptance: golden fixtures, crossing-move properties, resolver limits, no-Skia check.
//! Regenerate the goldens with `UPDATE_GOLDEN=1 cargo test` and read the diff before committing.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use design_model::tree::{MoveError, MoveRecord, forest};
use design_model::{Doc, Node, NodeType, Theme, lint, resolve};
use proptest::prelude::*;
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load(dir: &Path, name: &str) -> Option<Doc> {
    let bytes = fs::read(dir.join(name)).ok()?;
    let doc =
        Doc::from_json(&bytes).unwrap_or_else(|e| panic!("{}: {e}", dir.join(name).display()));
    Some(doc)
}

fn check(dir: &Path, name: &str, got: Value) {
    let path = dir.join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        return;
    }
    let want: Value = serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|_| panic!("missing golden {}", path.display())),
    )
    .unwrap();
    assert_eq!(
        got,
        want,
        "golden mismatch: {} (UPDATE_GOLDEN=1 to regenerate)",
        path.display()
    );
}

#[test]
fn fixtures_resolve_to_the_expected_json() {
    let mut seen = 0;
    for entry in fs::read_dir(fixtures()).unwrap() {
        let dir = entry.unwrap().path();
        let doc = load(&dir, "doc.json").unwrap();
        let sys = load(&dir, "system.json");
        let system = sys.as_ref().map(|s| ("dd_sys", s));
        for (theme, file) in [
            (Theme::Day, "expected.day.json"),
            (Theme::Night, "expected.night.json"),
        ] {
            let r = resolve("dd_main", &doc, system, theme).unwrap();
            check(&dir, file, serde_json::to_value(r).unwrap());
        }
        check(
            &dir,
            "expected.lint.json",
            serde_json::to_value(lint("dd_main", &doc, system, None)).unwrap(),
        );
        seen += 1;
    }
    assert!(seen >= 2);
}

#[test]
fn night_differs_from_day_only_in_token_values() {
    let dir = fixtures().join("basic");
    let (doc, sys) = (
        load(&dir, "doc.json").unwrap(),
        load(&dir, "system.json").unwrap(),
    );
    let day =
        serde_json::to_value(resolve("dd_main", &doc, Some(("dd_sys", &sys)), Theme::Day).unwrap())
            .unwrap();
    let night = serde_json::to_value(
        resolve("dd_main", &doc, Some(("dd_sys", &sys)), Theme::Night).unwrap(),
    )
    .unwrap();
    assert_ne!(day, night);
    fn shape(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .filter(|(k, _)| *k != "theme")
                    .map(|(k, x)| (k.clone(), shape(x)))
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(shape).collect()),
            _ => Value::Null,
        }
    }
    // same ids, types, children and prop keys in both themes
    assert_eq!(shape(&day), shape(&night));
}

// ---- moves -----------------------------------------------------------------------------------------------------

fn id(i: usize) -> String {
    format!(
        "n_aaaaaaaaaa{}{}",
        (b'a' + (i / 26) as u8) as char,
        (b'a' + (i % 26) as u8) as char
    )
}

const PAGE: &str = "n_pageaaaaaaaa";

fn frame(parent: &str, order: &str) -> Node {
    Node {
        ty: NodeType::Frame,
        parent: Some(parent.into()),
        order: order.into(),
        clock: 1,
        prev: None,
        name: String::new(),
        props: Default::default(),
        text: None,
    }
}

fn base_doc(n: usize) -> Doc {
    let mut d = Doc::default();
    d.nodes.insert(
        PAGE.into(),
        Node {
            ty: NodeType::Page,
            parent: None,
            order: "a".into(),
            clock: 0,
            prev: None,
            name: String::new(),
            props: Default::default(),
            text: None,
        },
    );
    for i in 0..n {
        d.nodes.insert(
            id(i),
            frame(PAGE, &format!("{}1", (b'a' + i as u8) as char)),
        );
    }
    d
}

/// Every node reached exactly once from the roots, no matter what the parent links say.
fn assert_covers_once(d: &Doc) {
    let f = forest(d);
    let mut seen = BTreeSet::new();
    let mut stack: Vec<&str> = f
        .pages
        .iter()
        .chain(&f.detached)
        .map(String::as_str)
        .collect();
    while let Some(i) = stack.pop() {
        assert!(seen.insert(i.to_string()), "{i} reached twice");
        stack.extend(f.children.get(i).into_iter().flatten().map(String::as_str));
    }
    assert_eq!(seen.len(), d.nodes.len(), "a node is unreachable");
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

#[test]
fn moving_into_own_descendant_is_refused() {
    let mut d = base_doc(3);
    let c = d.next_clock();
    d.move_node(&id(1), Some(&id(0)), "b", c).unwrap();
    let c = d.next_clock();
    d.move_node(&id(2), Some(&id(1)), "b", c).unwrap(); // 0 > 1 > 2
    let before = d.clone();
    let c = d.next_clock();
    assert_eq!(
        d.move_node(&id(0), Some(&id(2)), "b", c),
        Err(MoveError::Cycle)
    );
    assert_eq!(
        d.move_node(&id(0), Some(&id(0)), "b", c),
        Err(MoveError::Cycle)
    );
    assert_eq!(
        d.move_node(&id(0), Some(&id(1)), "b", c),
        Err(MoveError::Cycle)
    );
    assert_eq!(d, before, "a refused move changes nothing");
}

#[test]
fn crossing_moves_break_the_same_way_in_either_order() {
    let mut a = base_doc(2);
    let mut b = a.clone();
    a.move_node(&id(0), Some(&id(1)), "b", 5).unwrap(); // device 1: 0 under 1
    b.move_node(&id(1), Some(&id(0)), "b", 5).unwrap(); // device 2: 1 under 0
    let (ma, mb) = (move_of(&a, &id(0)), move_of(&b, &id(1)));
    a.apply_remote_move(&id(1), mb.clone());
    b.apply_remote_move(&id(0), ma.clone());
    assert_eq!(a, b, "replicas converge");
    let f = forest(&a);
    assert_eq!(
        f.broken,
        vec![id(1)],
        "equal clocks: the higher id loses its link"
    );
    assert_eq!(f.reverted, vec![id(1)], "the losing move is reverted");
    assert!(f.detached.is_empty(), "nothing is detached");
    assert!(
        f.children[PAGE].contains(&id(1)),
        "back under its old parent"
    );
    assert_eq!(
        f.children[&id(1)],
        vec![id(0)],
        "the earlier-winning move is kept"
    );
    assert_covers_once(&a);
    // idempotent and commutative
    a.apply_remote_move(&id(1), mb);
    assert_eq!(a, b);
}

fn move_of(d: &Doc, i: &str) -> MoveRecord {
    let n = &d.nodes[i];
    MoveRecord {
        parent: n.parent.clone(),
        order: n.order.clone(),
        clock: n.clock,
        prev: n.prev.clone(),
    }
}

fn ops(n: usize) -> impl Strategy<Value = Vec<(usize, Option<usize>)>> {
    // parent index n = the page
    proptest::collection::vec((0..n, proptest::option::weighted(0.9, 0..=n)), 0..24)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn local_moves_never_make_a_cycle(n in 2usize..9, seq in ops(8)) {
        let mut d = base_doc(n);
        for (node, parent) in seq {
            let (node, parent) = (node % n, parent.map(|p| p % (n + 1)));
            let parent_id = parent.map(|p| if p == n { PAGE.to_string() } else { id(p) });
            let clock = d.next_clock();
            let into_self_or_desc = parent_id.as_deref().is_some_and(|p| p == id(node) || is_descendant(&d, p, &id(node)));
            let before = d.clone();
            let r = d.move_node(&id(node), parent_id.as_deref(), "m", clock);
            match (r, into_self_or_desc) {
                (Err(MoveError::Cycle), true) => prop_assert_eq!(&d, &before),
                (Ok(()), false) => {}
                (Err(MoveError::NoParent), _) if parent_id.is_none() => prop_assert_eq!(&d, &before),
                (other, d_) => prop_assert!(false, "move {node} -> {parent_id:?}: {other:?}, descendant={d_}"),
            }
            prop_assert!(forest(&d).broken.is_empty(), "local moves must never need a cycle cut");
            assert_covers_once(&d);
        }
    }

    #[test]
    fn concurrent_moves_converge_and_stay_a_forest(n in 2usize..9, sa in ops(8), sb in ops(8)) {
        let base = base_doc(n);
        let run = |seq: Vec<(usize, Option<usize>)>| {
            let mut d = base.clone();
            let mut log = vec![];
            for (node, parent) in seq {
                let (node, parent) = (node % n, parent.map(|p| p % (n + 1)).unwrap_or(n));
                let pid = if parent == n { PAGE.to_string() } else { id(parent) };
                let clock = d.next_clock();
                if d.move_node(&id(node), Some(&pid), "m", clock).is_ok() {
                    log.push((id(node), move_of(&d, &id(node))));
                }
            }
            (d, log)
        };
        let ((mut r1, la), (mut r2, lb)) = (run(sa), run(sb));
        for (i, m) in &lb { r1.apply_remote_move(i, m.clone()); }
        for (i, m) in la.iter().rev() { r2.apply_remote_move(i, m.clone()); }
        prop_assert_eq!(&r1, &r2);
        prop_assert_eq!(forest(&r1), forest(&r2));
        assert_covers_once(&r1);
        // every cut was a real cycle: the cut node is an ancestor of itself through the stored links
        for b in forest(&r1).broken {
            prop_assert!(is_descendant(&r1, &b, &b));
        }
    }

    #[test]
    fn order_between_is_strict_and_valid(a in "[0-9a-z]{0,6}", b in "[0-9a-z]{0,6}") {
        use design_model::ids::{between, is_order};
        let (lo, hi) = (Some(a.as_str()).filter(|s| is_order(s)), Some(b.as_str()).filter(|s| is_order(s)));
        if let Some(m) = between(lo, hi) {
            prop_assert!(is_order(&m));
            if let Some(l) = lo { prop_assert!(l < m.as_str()); }
            if let Some(h) = hi { prop_assert!(m.as_str() < h); }
        }
    }

    #[test]
    fn validators_are_total(s in "\\PC{0,200}", ty in 0usize..9) {
        let _ = design_model::svgpath::validate(&s);
        let _ = Doc::from_json(s.as_bytes());
        let tys = [NodeType::Page, NodeType::Frame, NodeType::Text, NodeType::Rect, NodeType::Ellipse, NodeType::Image, NodeType::Vector, NodeType::Component, NodeType::Instance];
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&s) {
            let _ = design_model::validate::props(tys[ty], &m, &mut design_model::validate::Cx::raw());
        }
    }
}

// ---- resolver limits (hostile documents) ------------------------------------------------------------------------

fn n(ty: NodeType, parent: &str, order: &str, props: Value) -> Node {
    Node {
        ty,
        parent: Some(parent.into()),
        order: order.into(),
        clock: 1,
        prev: None,
        name: String::new(),
        props: props.as_object().unwrap().clone(),
        text: None,
    }
}

#[test]
fn nested_instances_cannot_blow_up_the_output() {
    // component k holds 10 instances of component k-1: 10^6 nodes if expanded. Must stop at the budget.
    let mut d = base_doc(0);
    let comp = |k: usize| format!("n_aaaaaaaaaz{}a", (b'a' + k as u8) as char);
    let inst = |k: usize, j: usize| {
        format!(
            "n_aaaaaaaaay{}{}",
            (b'a' + k as u8) as char,
            (b'a' + j as u8) as char
        )
    };
    d.nodes
        .insert(comp(0), n(NodeType::Component, PAGE, "a", json!({})));
    for k in 1..8 {
        d.nodes.insert(
            comp(k),
            n(
                NodeType::Component,
                PAGE,
                &format!("{}1", (b'a' + k as u8) as char),
                json!({}),
            ),
        );
        for j in 0..10 {
            let r = format!("dd_main/{}", comp(k - 1));
            d.nodes.insert(
                inst(k, j),
                n(
                    NodeType::Instance,
                    &comp(k),
                    &format!("{}1", (b'a' + j as u8) as char),
                    json!({ "component": r }),
                ),
            );
        }
    }
    d.nodes.insert(
        "n_aaaaaaaaaaua".to_string(),
        n(
            NodeType::Instance,
            PAGE,
            "z",
            json!({"component": format!("dd_main/{}", comp(7))}),
        ),
    );
    assert_eq!(
        resolve("dd_main", &d, None, Theme::Day).unwrap_err(),
        design_model::resolve::ResolveError::TooLarge
    );
    assert!(
        lint("dd_main", &d, None, None)
            .iter()
            .any(|f| f.rule == "resolve.too-large")
    );
}

#[test]
fn deep_nesting_is_cut_not_overflowed() {
    let mut d = base_doc(0);
    let mut parent = PAGE.to_string();
    for i in 0..5000 {
        let me = format!(
            "n_aaaaaaaaa{}{}",
            (b'a' + (i / 26 % 26) as u8) as char,
            (b'a' + (i % 26) as u8) as char
        );
        let me = format!("{me}{}", (b'a' + (i / 676) as u8) as char);
        d.nodes
            .insert(me.clone(), n(NodeType::Frame, &parent, "a", json!({})));
        parent = me;
    }
    let r = resolve("dd_main", &d, None, Theme::Day).unwrap();
    assert!(r.diagnostics.iter().any(|x| x.code == "tree.depth"));
    assert!(
        lint("dd_main", &d, None, None)
            .iter()
            .any(|f| f.rule == "tree.depth")
    );
}

#[test]
fn designs_cannot_read_other_documents() {
    let mut d = base_doc(0);
    d.nodes.insert(
        "n_aaaaaaaaaaua".into(),
        n(
            NodeType::Instance,
            PAGE,
            "a",
            json!({"component": "dd_other/n_aaaaaaaaaaaa"}),
        ),
    );
    d.meta.system = Some("dd_sys".into());
    let mut sys = Doc::default();
    sys.nodes.insert(
        "n_aaaaaaaaaaaa".into(),
        n(NodeType::Component, "n_none", "a", json!({"w": 77})),
    );
    // a component with that very id exists, but in the system doc: `dd_other/...` names neither this doc nor its system
    let r = resolve("dd_main", &d, Some(("dd_sys", &sys)), Theme::Day).unwrap();
    assert!(r.diagnostics.iter().any(|x| x.code == "instance.missing"));
    assert!(
        r.pages[0].children[0].props.is_empty(),
        "nothing was read from the other document"
    );
}

#[test]
fn documents_from_json_are_bounded_and_strict() {
    assert!(Doc::from_json(br#"{"nodes":{},"extra":1}"#).is_err());
    assert!(
        Doc::from_json(
            br#"{"nodes":{"n_aaaaaaaaaaaa":{"type":"rect","parent":null,"order":"a","bogus":1}}}"#
        )
        .is_err()
    );
    assert!(Doc::from_json(&vec![b' '; design_model::limits::MAX_DOC_BYTES + 1]).is_err());
    assert!(Doc::from_json(&b"[".repeat(100_000)).is_err()); // serde_json's recursion limit, not a stack overflow
}

// ---- no Skia ------------------------------------------------------------------------------------------------------

#[test]
fn the_crate_does_not_depend_on_skia() {
    let manifest = include_str!("../Cargo.toml");
    let deps: BTreeSet<&str> = manifest
        .split("\n[")
        .filter(|s| s.starts_with("dependencies]") || s.starts_with("dev-dependencies]"))
        .flat_map(|s| s.lines().skip(1))
        .filter_map(|l| l.split('=').next().map(str::trim))
        .filter(|n| !n.is_empty() && !n.starts_with('#'))
        .collect();
    assert_eq!(
        deps,
        BTreeSet::from(["serde", "serde_json", "proptest"]),
        "a new dependency needs a conscious review"
    );
    // and the real graph, transitive included
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args([
            "tree",
            "--offline",
            "-p",
            "design-model",
            "-e",
            "normal,dev",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        tree.contains("serde_json"),
        "cargo tree printed nothing useful: {tree}"
    );
    for banned in ["skia", "metal", "wgpu", "tokio", "sqlx"] {
        assert!(
            !tree.contains(banned),
            "design-model must not depend on {banned}"
        );
    }
}

#[test]
fn a_losing_move_is_never_reverted_under_a_leaf() {
    // a crossing pair whose loser claims a rect as its previous parent (a hostile stored `prev`): it surfaces
    // detached instead of putting children under a leaf
    let mut a = base_doc(2);
    a.nodes.insert(
        "n_leafaaaaaaaa".into(),
        Node {
            ty: NodeType::Rect,
            parent: Some(PAGE.into()),
            order: "z".into(),
            clock: 1,
            prev: None,
            name: String::new(),
            props: Default::default(),
            text: None,
        },
    );
    // the crossing pair as two replicas' moves merged (a local move would refuse the cycle)
    for (n, parent) in [(0, 1), (1, 0)] {
        let node = a.nodes.get_mut(&id(n)).unwrap();
        node.parent = Some(id(parent));
        node.clock = 5;
    }
    a.nodes.get_mut(&id(1)).unwrap().prev = Some("n_leafaaaaaaaa".into());
    let f = forest(&a);
    assert_eq!(f.broken, vec![id(1)]);
    assert!(f.reverted.is_empty(), "not reverted under a leaf");
    assert_eq!(f.detached, vec![id(1)]);
    assert!(!f.children.contains_key("n_leafaaaaaaaa"));
}
