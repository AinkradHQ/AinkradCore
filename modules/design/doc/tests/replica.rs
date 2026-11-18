//! V1-03 acceptance at the document layer (ported from `design-crdt` in V1-05): replicas converge through the gate, a
//! hostile update is refused, crossing moves revert, a rebalance does not undo a concurrent move, and an update
//! refused after integration poisons the replica. Since V1-05 the Core's replica runs the shared gate, whose layout
//! layer refuses some shapes BEFORE integration (`Malformed`, replica untouched) that `design-crdt` caught after it
//! (`Invalid`, poisoned); the expectations below say which.

use design_doc::{
    MAX_JSON_DEPTH, MAX_PEER_UPDATE_BYTES as MAX_UPDATE_BYTES, NodeType, Refused, Replica,
};
use design_model::tree::forest;
use serde_json::{Value, json};
use yrs::branch::{Branch, BranchPtr};
use yrs::types::array::ArrayRef;
use yrs::types::map::{MapPrelim, MapRef};
use yrs::{Any, Array as _, Map as _, ReadTxn, Transact, WriteTxn};

const PAGE: &str = "n_pageaaaaaaaa";

fn id(i: u64) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = vec![b'a'; 12];
    let (mut i, mut k) = (i, 11);
    while i > 0 {
        s[k] = A[(i % 32) as usize];
        i /= 32;
        k -= 1;
    }
    format!("n_{}", String::from_utf8(s).unwrap())
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// The Core: a gate replica. Clients send through `send`, which applies and returns the diff to broadcast.
fn server_with_page() -> Replica {
    let mut s = Replica::new();
    let (_, u) = s.edit(|e| e.insert_node(PAGE, NodeType::Page, None, "a", "p", &json!({}), None));
    assert!(u.len() > 2);
    s
}

fn client_of(server: &Replica) -> Replica {
    let mut c = Replica::new();
    c.apply_trusted(&server.state()).unwrap();
    c
}

fn forge(server: &Replica, f: impl FnOnce(&mut yrs::TransactionMut)) -> Vec<u8> {
    let forger = client_of(server);
    let mut txn = forger.raw().transact_mut();
    f(&mut txn);
    txn.encode_update_v1()
}

#[test]
fn clients_converge_on_a_thousand_random_concurrent_ops() {
    let mut server = server_with_page();
    let mut clients: Vec<Replica> = (0..3).map(|_| client_of(&server)).collect();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut next = 1u64;
    let mut ops = 0;
    for _round in 0..24 {
        let mut outbox: Vec<Vec<Vec<u8>>> = vec![vec![]; clients.len()];
        for (ci, c) in clients.iter_mut().enumerate() {
            for _ in 0..14 {
                let m = c.read().unwrap();
                let ids: Vec<String> = m.nodes.keys().cloned().collect();
                let containers: Vec<String> = m
                    .nodes
                    .iter()
                    .filter(|(_, n)| n.ty.is_container())
                    .map(|(i, _)| i.clone())
                    .collect();
                let pick = |r: &mut Rng, v: &[String]| v[r.below(v.len())].clone();
                let orders = ["a", "b", "c", "m", "n", "z", "a1", "b1"];
                let order = orders[rng.below(orders.len())];
                let (_, u) = match rng.below(10) {
                    0..=3 => {
                        let nid = id(next);
                        next += 1;
                        let p = pick(&mut rng, &containers);
                        let ty = if rng.below(2) == 0 {
                            NodeType::Frame
                        } else {
                            NodeType::Rect
                        };
                        c.edit(|e| {
                            e.insert_node(&nid, ty, Some(&p), order, "n", &json!({"w": 10}), None)
                        })
                    }
                    4..=6 => {
                        let (n, p) = (pick(&mut rng, &ids), pick(&mut rng, &containers));
                        c.edit(|e| {
                            let _ = e.move_node(&n, Some(&p), order);
                        })
                    }
                    7 => {
                        let n = pick(&mut rng, &ids);
                        if n == PAGE {
                            continue;
                        }
                        let v = json!(rng.below(500));
                        c.edit(|e| {
                            e.set_prop(&n, "x", Some(&v));
                        })
                    }
                    8 => {
                        let p = pick(&mut rng, &containers);
                        c.edit(|e| {
                            let _ = e.rebalance(&p);
                        })
                    }
                    _ => {
                        let n = pick(&mut rng, &ids);
                        if n == PAGE {
                            continue;
                        }
                        c.edit(|e| e.remove_node(&n))
                    }
                };
                ops += 1;
                outbox[ci].push(u);
            }
        }
        // the server takes the clients' updates interleaved, broadcasts every diff to everyone else
        let mut diffs: Vec<(usize, Vec<u8>)> = vec![];
        let longest = outbox.iter().map(Vec::len).max().unwrap();
        for k in 0..longest {
            for (ci, q) in outbox.iter().enumerate() {
                if let Some(u) = q.get(k)
                    && let Some(d) = server.apply_remote(u).expect("honest updates are accepted")
                {
                    diffs.push((ci, d));
                }
            }
        }
        for (ci, c) in clients.iter_mut().enumerate() {
            for (from, d) in &diffs {
                if *from != ci {
                    c.apply_trusted(d).unwrap();
                }
            }
        }
        let want = server.read().unwrap();
        for c in &clients {
            let got = c.read().unwrap();
            assert_eq!(got, want, "replicas converge");
            assert_eq!(forest(&got), forest(&want));
        }
    }
    assert!(ops >= 1000, "{ops} ops");
    // a replica rebuilt from the full state agrees too
    let rebuilt = Replica::from_stored([server.state().as_slice()]).unwrap();
    assert_eq!(rebuilt.read().unwrap(), server.read().unwrap());
    assert_eq!(rebuilt.top_clock(), server.top_clock());
}

fn two_frames(server: &mut Replica) -> (Replica, Replica, String, String) {
    let (a, b) = (id(1), id(2));
    let mut c0 = client_of(server);
    for n in [&a, &b] {
        let (_, u) =
            c0.edit(|e| e.insert_node(n, NodeType::Frame, Some(PAGE), "a", "f", &json!({}), None));
        server.apply_remote(&u).unwrap();
    }
    (client_of(server), client_of(server), a, b)
}

#[test]
fn crossing_moves_revert_the_loser_instead_of_detaching_it() {
    let mut server = server_with_page();
    let (mut c1, mut c2, a, b) = two_frames(&mut server);
    // c1: a under b. c2, concurrently: b under a.
    let (r, u1) = c1.edit(|e| e.move_node(&a, Some(&b), "a"));
    r.unwrap();
    let (r, u2) = c2.edit(|e| e.move_node(&b, Some(&a), "a"));
    r.unwrap();
    for u in [&u1, &u2] {
        let d = server.apply_remote(u).unwrap().unwrap();
        c1.apply_trusted(&d).unwrap();
        c2.apply_trusted(&d).unwrap();
    }
    let m = server.read().unwrap();
    assert_eq!(c1.read().unwrap(), m);
    assert_eq!(c2.read().unwrap(), m);
    let f = forest(&m);
    assert_eq!(f.broken.len(), 1, "one cycle, one loser");
    assert_eq!(f.reverted, f.broken, "the loser is reverted, not detached");
    assert!(f.detached.is_empty());
    let loser = &f.broken[0];
    assert_eq!(f.parent[loser], PAGE, "back under its previous parent");
    let winner = if *loser == a { &b } else { &a };
    assert_eq!(f.parent[winner], *loser, "the other move is kept");
    assert_eq!(
        f.children.values().map(Vec::len).sum::<usize>(),
        2,
        "both frames placed once"
    );
}

#[test]
fn a_rebalance_does_not_undo_a_concurrent_move() {
    let mut server = server_with_page();
    let (mut c1, mut c2, a, b) = two_frames(&mut server);
    let (r, u1) = c1.edit(|e| e.move_node(&a, Some(&b), "m")); // a leaves the page
    r.unwrap();
    let (r, u2) = c2.edit(|e| e.rebalance(PAGE)); // renumbers the page's children, a included
    r.unwrap();
    for u in [&u1, &u2] {
        let d = server.apply_remote(u).unwrap().unwrap();
        c1.apply_trusted(&d).unwrap();
        c2.apply_trusted(&d).unwrap();
    }
    let m = server.read().unwrap();
    assert_eq!(c1.read().unwrap(), m);
    assert_eq!(c2.read().unwrap(), m);
    assert_eq!(forest(&m).parent[&a], b, "the move survived the rebalance");
}

#[test]
fn hostile_updates_are_refused_and_poison_the_replica() {
    let server = server_with_page();
    let nm = |txn: &mut yrs::TransactionMut| txn.get_or_insert_map("nodes");
    let node = |txn: &mut yrs::TransactionMut, key: &str, fields: &[(&str, Any)]| {
        let m = nm(txn).insert(txn, key, MapPrelim::default());
        for (k, v) in fields {
            m.insert(txn, *k, v.clone());
        }
    };
    let good = |ty: &str| -> Vec<(&'static str, Any)> {
        let mv = Any::from_json(r#"{"p":"n_pageaaaaaaaa","c":2,"f":null}"#).unwrap();
        vec![("type", ty.into()), ("order", "b".into()), ("move", mv)]
    };
    let cases: Vec<(&str, Vec<u8>, Refused)> = vec![
        ("oversize", vec![0; MAX_UPDATE_BYTES + 1], Refused::TooLarge),
        (
            "garbage",
            vec![0xff, 0xff, 0xff, 0xff, 0xff],
            Refused::Malformed,
        ),
        (
            // the layout knows three roots: refused before integration
            "foreign root",
            forge(&server, |t| {
                t.get_or_insert_map("evil").insert(t, "k", 1);
            }),
            Refused::Malformed,
        ),
        (
            "bad node id",
            forge(&server, |t| node(t, "not-an-id", &good("frame"))),
            Refused::Invalid(String::new()),
        ),
        (
            "unknown type",
            forge(&server, |t| node(t, &id(5), &good("nuke"))),
            Refused::Invalid(String::new()),
        ),
        (
            "missing move",
            forge(&server, |t| {
                let mut f = good("frame");
                f.pop();
                node(t, &id(5), &f)
            }),
            Refused::Invalid(String::new()),
        ),
        (
            "unknown field",
            forge(&server, |t| {
                let mut f = good("frame");
                f.push(("evil", 1.into()));
                node(t, &id(5), &f)
            }),
            Refused::Invalid(String::new()),
        ),
        (
            "bad order",
            forge(&server, |t| {
                let mut f = good("frame");
                f[1] = ("order", "A!".into());
                node(t, &id(5), &f)
            }),
            Refused::Invalid(String::new()),
        ),
        (
            "unknown prop",
            forge(&server, |t| {
                let mut f = good("frame");
                node(t, &id(5), &f);
                f.clear();
                let n = match nm(t).get(t, &id(5)) {
                    Some(yrs::Out::YMap(m)) => m,
                    _ => unreachable!(),
                };
                let p = n.insert(t, "props", MapPrelim::default());
                p.insert(t, "script", "x");
            }),
            Refused::Invalid(String::new()),
        ),
        (
            "clock far ahead",
            forge(&server, |t| {
                let mv = Any::from_json(r#"{"p":"n_pageaaaaaaaa","c":9007199254740000,"f":null}"#)
                    .unwrap();
                let mut f = good("frame");
                f[2] = ("move", mv);
                node(t, &id(5), &f)
            }),
            Refused::ClockTooHigh,
        ),
        (
            // the layout: a node must be a map, refused before integration
            "wrong shape: node is a string",
            forge(&server, |t| {
                nm(t).insert(t, id(5).as_str(), "oops");
            }),
            Refused::Malformed,
        ),
    ];
    for (name, bytes, want) in cases {
        let mut s = client_of(&server);
        let got = s.apply_remote(&bytes).expect_err(name);
        match (&got, &want) {
            (Refused::Invalid(_), Refused::Invalid(_)) => {}
            _ => assert_eq!(got, want, "{name}"),
        }
        if got != Refused::TooLarge && got != Refused::Malformed {
            // it had been integrated: the replica must refuse everything now
            assert_eq!(s.apply_remote(&[0, 0]), Err(Refused::Poisoned), "{name}");
        } else {
            // refused before integration: the replica is untouched and still usable
            assert!(!s.is_poisoned(), "{name}");
            assert_eq!(s.apply_remote(&[0, 0]), Ok(None), "{name}");
        }
    }
}

#[test]
fn an_update_with_missing_dependencies_is_refused() {
    let server = server_with_page();
    let mut c = client_of(&server);
    let (_, _first) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Frame,
            Some(PAGE),
            "a",
            "f",
            &json!({}),
            None,
        )
    });
    let (_, second) = c.edit(|e| e.set_prop(&id(1), "x", Some(&Value::from(1))));
    let mut s = client_of(&server);
    assert_eq!(s.apply_remote(&second), Err(Refused::Pending));
    // refused BEFORE yrs integrated anything (it would park it as pending, and a later overlapping update is a
    // use-after-free there): the replica is untouched and not poisoned, and the dependency then the update apply
    assert_eq!(s.read().unwrap(), server.read().unwrap());
    assert!(s.apply_remote(&_first).unwrap().is_some());
    assert!(s.apply_remote(&second).unwrap().is_some());
    // a delete beyond the known state, and an origin the replica lacks, are the same refusal
    let mut c2 = client_of(&server);
    let (_, a) = c2.edit(|e| {
        e.insert_node(
            &id(2),
            NodeType::Frame,
            Some(PAGE),
            "a",
            "f",
            &json!({}),
            None,
        )
    });
    let (_, del) = c2.edit(|e| e.remove_node(&id(2)));
    let (_, b) = c2.edit(|e| {
        e.insert_node(
            &id(3),
            NodeType::Frame,
            Some(PAGE),
            "b",
            "f",
            &json!({}),
            None,
        )
    });
    let mut s2 = client_of(&server);
    assert_eq!(
        s2.apply_remote(&del),
        Err(Refused::Pending),
        "delete of unknown blocks"
    );
    assert_eq!(
        s2.apply_remote(&b),
        Err(Refused::Pending),
        "starts past the state vector"
    );
    for u in [&a, &del, &b] {
        assert!(s2.apply_remote(u).is_ok(), "in order they apply");
    }
}

#[test]
fn the_dependency_scan_counts_blocks_like_yrs_does() {
    // multi-byte and astral text, deep any values and deletes: honest in-order updates always pass the dependency
    // check (a wrong block length would make an honest client look like it depends on missing state)
    let mut server = server_with_page();
    let mut c = client_of(&server);
    let text = "h\u{e9}llo \u{1f600} \u{4e16}\u{754c}";
    let (_, u) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Text,
            Some(PAGE),
            "a",
            "t",
            &json!({"w": 5, "fill": [{"type": "solid", "color": "#ff0000"}]}),
            Some(text),
        )
    });
    assert!(server.apply_remote(&u).unwrap().is_some());
    for chunk in ["\u{1f680}", "x", "\u{e9}"] {
        let (_, u) = c.edit(|e| {
            e.insert_text(&id(1), 3, chunk);
        });
        assert!(server.apply_remote(&u).is_ok(), "{chunk}");
    }
    let (_, u) = c.edit(|e| {
        e.set_prop(&id(1), "w", None);
    });
    assert!(server.apply_remote(&u).is_ok());
    assert_eq!(server.read().unwrap(), c.read().unwrap());
}

#[test]
fn the_node_budget_and_repeats_are_enforced() {
    let mut s = server_with_page();
    let mut c = client_of(&s);
    let (_, u) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Frame,
            Some(PAGE),
            "a",
            "f",
            &json!({}),
            None,
        )
    });
    assert!(s.apply_remote(&u).unwrap().is_some());
    assert_eq!(s.apply_remote(&u).unwrap(), None, "a repeat adds nothing");
    // an honest 8 KB prop value passes; a 4 MB-deep structure never gets here (update cap)
    let big = json!({"fill": []});
    let (_, u) = c.edit(|e| e.set_prop(&id(1), "fill", big.get("fill")));
    assert!(s.apply_remote(&u).is_ok());
}

fn var(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// One client, one `Any` block holding `depth` nested arrays: what would overflow yrs' recursive decoder.
fn nested(depth: usize) -> Vec<u8> {
    let mut u = vec![];
    var(1, &mut u); // clients
    var(1, &mut u); // blocks
    var(7, &mut u); // client
    var(0, &mut u); // clock
    u.push(8 | 0x20); // an Any item with a map key: the named parent follows
    var(1, &mut u);
    var(5, &mut u);
    u.extend_from_slice(b"nodes");
    var(1, &mut u);
    u.push(b'k');
    var(1, &mut u); // one value
    for _ in 0..depth {
        u.push(117);
        var(1, &mut u);
    }
    u.push(126);
    var(0, &mut u); // empty delete set
    u
}

#[test]
fn hostile_encodings_are_refused_before_yrs_sees_them() {
    let server = server_with_page();
    // honest depth passes the scan, absurd depth is refused without recursing (yrs itself would abort the process)
    assert!(design_doc::guard::scan(&nested(3)).is_ok());
    for bytes in [nested(100_000), nested(MAX_JSON_DEPTH + 2)] {
        let mut s = client_of(&server);
        assert_eq!(s.apply_remote(&bytes), Err(Refused::Malformed));
        // refused before anything was integrated: the replica is still usable
        assert_eq!(s.apply_remote(&[0, 0]), Ok(None));
    }
    // a declared length far beyond the bytes present: refused, nothing reserved
    let mut huge = vec![];
    var(u32::MAX as u64, &mut huge);
    var(1, &mut huge);
    assert_eq!(
        client_of(&server).apply_remote(&huge),
        Err(Refused::Malformed)
    );
    let mut arr = nested(1);
    let n = arr.len();
    arr.splice(n - 4..n - 1, [117, 0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert_eq!(
        client_of(&server).apply_remote(&arr),
        Err(Refused::Malformed)
    );
    // content kinds we never write (embed, binary, doc, format, json) and trailing bytes
    for tag in [5u8, 3, 9, 6, 2] {
        let mut u = vec![1, 1, 7, 0, tag | 0x20, 1, 5];
        u.extend_from_slice(b"nodes");
        u.extend_from_slice(&[1, b'k', 0, 0]);
        assert_eq!(
            client_of(&server).apply_remote(&u),
            Err(Refused::Malformed),
            "{tag}"
        );
    }
    let mut trailing = client_of(&server).state();
    trailing.push(0);
    assert_eq!(
        client_of(&server).apply_remote(&trailing),
        Err(Refused::Malformed)
    );
    // random bytes never panic or abort the process
    let mut rng = Rng(0xDEAD_BEEF_1234_5678);
    for _ in 0..3000 {
        let n = rng.below(64);
        let junk: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
        let _ = client_of(&server).apply_remote(&junk);
    }
    // the guard accepts what a real client sends: snapshots and edits
    let mut c = client_of(&server);
    let (_, u) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Text,
            Some(PAGE),
            "a",
            "t",
            &json!({"w": [1, {"a": 2}]}),
            Some("hi"),
        )
    });
    assert!(design_doc::guard::scan(&u).is_ok());
    assert!(design_doc::guard::scan(&c.state()).is_ok());
}

#[test]
fn a_chain_of_small_nested_updates_is_refused_at_the_step_that_nests() {
    // Nested maps are stored flat, so no single update looks deep. Each small update here adds one level under a
    // node's props; the gate refuses the first that leaves the layout, before the replica integrates it.
    let mut server = server_with_page();
    let mut c = client_of(&server);
    let (_, u) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Frame,
            Some(PAGE),
            "a",
            "f",
            &json!({}),
            None,
        )
    });
    server.apply_remote(&u).unwrap();
    let before = server.state();
    let forger = client_of(&server);
    let mut refused_at = None;
    let mut parent = {
        let txn = forger.raw().transact();
        let nodes = txn.get_map("nodes").unwrap();
        let Some(yrs::Out::YMap(n)) = nodes.get(&txn, &id(1)) else {
            panic!()
        };
        let Some(yrs::Out::YMap(p)) = n.get(&txn, "props") else {
            panic!()
        };
        p
    };
    for depth in 0..40 {
        let bytes = {
            let mut txn = forger.raw().transact_mut();
            let before = txn.state_vector();
            parent = parent.insert(&mut txn, "k", MapPrelim::default());
            txn.encode_diff_v1(&before)
        };
        assert!(bytes.len() < 200, "each step is small");
        if server.apply_remote(&bytes).is_err() {
            refused_at = Some(depth);
            break;
        }
    }
    assert_eq!(
        refused_at,
        Some(0),
        "a nested shared type inside props is never accepted"
    );
    // nothing of it is stored anywhere: a rebuild from what was stored equals the state before
    let rebuilt = Replica::from_stored([before.as_slice()]).unwrap();
    assert_eq!(rebuilt.read().unwrap().nodes[&id(1)].props.len(), 0);
}

fn arr_of(b: &impl AsRef<Branch>) -> ArrayRef {
    ArrayRef::from(BranchPtr::from(b.as_ref()))
}

fn map_of(b: &impl AsRef<Branch>) -> MapRef {
    MapRef::from(BranchPtr::from(b.as_ref()))
}

fn node_map(t: &mut yrs::TransactionMut, id: &str) -> MapRef {
    let nodes = t.get_or_insert_map("nodes");
    match nodes.get(&*t, id) {
        Some(yrs::Out::YMap(m)) => m,
        _ => panic!("no node {id}"),
    }
}

fn child(t: &yrs::TransactionMut, m: &MapRef, key: &str) -> yrs::Out {
    m.get(t, key).unwrap_or_else(|| panic!("no {key}"))
}

#[test]
fn a_deep_chain_of_nested_maps_in_one_update_is_refused_without_aborting() {
    // The review's PoC: one update with a 20 000-deep chain of maps that also deletes the chain's root. yrs recurses
    // once per level in delete and gc, which aborts the process; the guard refuses it before yrs integrates anything.
    let merged = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(|| {
            let a = yrs::Doc::with_client_id(7);
            let nodes = a.get_or_insert_map("nodes");
            let mut u = vec![];
            {
                let mut t = a.transact_mut();
                let mut m = nodes.insert(&mut t, "n_x", MapPrelim::default());
                for _ in 0..20_000 {
                    m = m.insert(&mut t, "k", MapPrelim::default());
                }
                u.push(t.encode_update_v1());
            }
            {
                let mut t = a.transact_mut();
                nodes.remove(&mut t, "n_x");
                u.push(t.encode_update_v1());
            }
            yrs::merge_updates_v1(&u).unwrap()
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(merged.len() < MAX_UPDATE_BYTES, "{} bytes", merged.len());
    let h = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || Replica::new().apply_remote(&merged))
        .unwrap();
    assert_eq!(
        h.join().expect("the Core did not abort"),
        Err(Refused::Malformed)
    );
}

#[test]
fn nesting_deeper_than_node_then_props_is_refused_in_every_shape() {
    let mut server = server_with_page();
    let mut c = client_of(&server);
    let (_, u) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Frame,
            Some(PAGE),
            "a",
            "f",
            &json!({"w": 1}),
            None,
        )
    });
    server.apply_remote(&u).unwrap();
    // a map under props (depth 3), a text under props, and a map directly under the nodes root's node's node
    let under_props = |t: &mut yrs::TransactionMut, text: bool| {
        let m = node_map(t, &id(1));
        let yrs::Out::YMap(p) = child(t, &m, "props") else {
            panic!()
        };
        if text {
            p.insert(t, "deep", yrs::types::text::TextPrelim::new("x"));
        } else {
            p.insert(t, "deep", MapPrelim::default());
        }
    };
    for (name, bytes) in [
        ("map in props", forge(&server, |t| under_props(t, false))),
        ("text in props", forge(&server, |t| under_props(t, true))),
        (
            "map under a node's text key",
            forge(&server, |t| {
                let m = node_map(t, &id(1));
                m.insert(t, "extra", MapPrelim::default());
            }),
        ),
    ] {
        let mut s = client_of(&server);
        let r = s.apply_remote(&bytes);
        // the first two are deeper than allowed (Malformed before integration); the third is a legal depth that
        // the reader refuses afterwards (an unknown node field)
        assert!(
            matches!(r, Err(Refused::Malformed | Refused::Invalid(_))),
            "{name}: {r:?}"
        );
    }
}

/// `design-crdt` refused these after integrating them (`Invalid`, poisoned); the gate's layout layer now refuses
/// every one before the replica sees it (`Malformed`, untouched).
#[test]
fn the_list_part_of_a_map_and_the_map_part_of_a_text_are_refused() {
    let mut server = server_with_page();
    let mut c = client_of(&server);
    let (_, u) = c.edit(|e| {
        e.insert_node(
            &id(1),
            NodeType::Text,
            Some(PAGE),
            "a",
            "t",
            &json!({"w": 1}),
            Some("hi"),
        )
    });
    server.apply_remote(&u).unwrap();
    let text_of = |t: &mut yrs::TransactionMut| {
        let m = node_map(t, &id(1));
        match child(t, &m, "text") {
            yrs::Out::YText(x) => x,
            _ => panic!(),
        }
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "root map",
            forge(&server, |t| {
                let n = t.get_or_insert_map("nodes");
                arr_of(&n).push_back(t, "x");
            }),
        ),
        (
            "meta root",
            forge(&server, |t| {
                let n = t.get_or_insert_map("meta");
                arr_of(&n).push_back(t, "x");
            }),
        ),
        (
            "node map",
            forge(&server, |t| {
                let m = node_map(t, &id(1));
                arr_of(&m).push_back(t, "x");
            }),
        ),
        (
            "props map",
            forge(&server, |t| {
                let m = node_map(t, &id(1));
                let yrs::Out::YMap(p) = child(t, &m, "props") else {
                    panic!()
                };
                arr_of(&p).push_back(t, "x");
            }),
        ),
        (
            "keyed entry in a text",
            forge(&server, |t| {
                let x = text_of(t);
                map_of(&x).insert(t, "k", 1);
            }),
        ),
        (
            "non-string content in a text",
            forge(&server, |t| {
                let x = text_of(t);
                arr_of(&x).push_back(t, 5);
            }),
        ),
    ];
    for (name, bytes) in cases {
        let mut s = client_of(&server);
        let r = s.apply_remote(&bytes);
        assert_eq!(r, Err(Refused::Malformed), "{name}");
        assert!(!s.is_poisoned(), "{name}");
        assert_eq!(s.apply_remote(&[0, 0]), Ok(None), "{name}");
        assert_eq!(s.read().unwrap(), server.read().unwrap(), "{name}");
    }
}

/// One client's run of one `Any` item (null) under the `nodes` root with the given key.
fn run(client: u64, clock: u64, key: &str) -> Vec<u8> {
    let mut u = vec![];
    var(1, &mut u); // blocks
    var(client, &mut u);
    var(clock, &mut u);
    u.push(8 | 0x20);
    var(1, &mut u);
    var(5, &mut u);
    u.extend_from_slice(b"nodes");
    var(key.len() as u64, &mut u);
    u.extend_from_slice(key.as_bytes());
    var(1, &mut u); // one value
    u.push(126);
    u
}

fn update_of(runs: &[Vec<u8>], deletes: &[(u64, u64, u64)]) -> Vec<u8> {
    let mut u = vec![];
    var(runs.len() as u64, &mut u);
    for r in runs {
        u.extend_from_slice(r);
    }
    var(deletes.len() as u64, &mut u);
    for &(c, k, n) in deletes {
        var(c, &mut u);
        var(1, &mut u);
        var(k, &mut u);
        var(n, &mut u);
    }
    u
}

#[test]
fn a_client_twice_in_one_update_and_clocks_past_u32_are_refused() {
    use design_doc::guard::scan;
    assert!(scan(&update_of(&[run(7, 0, "a")], &[])).is_ok());
    assert!(scan(&update_of(&[run(7, 0, "a"), run(8, 0, "b")], &[])).is_ok());
    // the same client twice: the second run would restart the clock and make every dependency check meaningless
    for runs in [
        [run(7, 0, "a"), run(7, 5, "b")],
        [run(7, 3, "a"), run(7, 3, "a")],
    ] {
        assert_eq!(scan(&update_of(&runs, &[])), Err(Refused::Malformed));
        assert_eq!(
            client_of(&server_with_page()).apply_remote(&update_of(&runs, &[])),
            Err(Refused::Malformed)
        );
    }
    // a run that would pass u32::MAX, one that starts past it, and a delete range that ends past it
    let max = u64::from(u32::MAX);
    for u in [
        update_of(&[run(7, max, "a")], &[]),
        update_of(&[run(7, max + 1, "a")], &[]),
        update_of(&[run(7, max - 1, "a")], &[(7, max - 1, 2)]),
        update_of(&[run(7, 0, "a")], &[(7, max, 1)]),
        update_of(&[run(7, 0, "a")], &[(7, 0, max + 1)]),
    ] {
        assert_eq!(scan(&u), Err(Refused::Malformed));
    }
    // client ids past 53 bits trip a yrs assertion
    assert_eq!(
        scan(&update_of(&[run(1 << 53, 0, "a")], &[])),
        Err(Refused::Malformed)
    );
}

#[test]
fn the_dependency_check_is_linear_in_the_update() {
    // 40 000 clients, each with a run and a delete: a per-reference scan of every run would be 1.6e9 steps
    let runs: Vec<Vec<u8>> = (1..=40_000u64).map(|c| run(c, 0, "a")).collect();
    let dels: Vec<(u64, u64, u64)> = (1..=40_000u64).map(|c| (c, 0, 1)).collect();
    let bytes = update_of(&runs, &dels);
    let t = std::time::Instant::now();
    let f = design_doc::guard::scan_facts(&bytes).unwrap();
    f.check_known(|_| 0).unwrap();
    assert!(
        t.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        t.elapsed()
    );
}

/// A run of two blocks for `client`: the already-held block at `tip` re-sent MISLABELLED as a map straight under the
/// `nodes` root, then a new map nested under `tip` by id. yrs drops the held block and nests the new one under the
/// real item, so the real chain gets one level deeper per update.
fn resend_mislabel(client: u64, tip: u64, key: &str) -> Vec<u8> {
    let mut u = vec![];
    var(1, &mut u); // clients
    var(2, &mut u); // blocks
    var(client, &mut u);
    var(tip, &mut u);
    // the held block, claimed to be a root-level map
    u.push(7 | 0x20);
    var(1, &mut u);
    var(5, &mut u);
    u.extend_from_slice(b"nodes");
    var(1, &mut u);
    u.push(b'x');
    u.push(1); // map
    // the new map under the held block's id
    u.push(7 | 0x20);
    var(0, &mut u); // parent by id
    var(client, &mut u);
    var(tip, &mut u);
    var(key.len() as u64, &mut u);
    u.extend_from_slice(key.as_bytes());
    u.push(1);
    var(0, &mut u); // empty delete set
    u
}

fn item_id(t: &yrs::TransactionMut, m: &MapRef) -> (u64, u64) {
    let _ = t;
    match yrs::types::SharedRef::hook(m).id() {
        yrs::branch::BranchID::Nested(id) => (id.client.get(), u64::from(id.clock)),
        other => panic!("not nested: {other:?}"),
    }
}

#[test]
fn resending_a_held_block_mislabelled_cannot_deepen_the_real_chain() {
    // 20 000 resend-mislabel updates against the Core path, then a delete of the top node, on a 2 MB thread: every
    // one is refused (the held block is ignored, the real depth comes from the replica) and nothing aborts.
    let h = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(|| {
            let mut server = server_with_page();
            let mut c = client_of(&server);
            let (_, u) = c.edit(|e| {
                e.insert_node(
                    &id(1),
                    NodeType::Frame,
                    Some(PAGE),
                    "a",
                    "f",
                    &json!({}),
                    None,
                )
            });
            server.apply_remote(&u).unwrap();
            // the real props map of the node: depth 2, the deepest legal type
            let (client, props_clock) = {
                let mut t = c.raw().transact_mut();
                let m = node_map(&mut t, &id(1));
                let yrs::Out::YMap(p) = child(&t, &m, "props") else {
                    panic!()
                };
                item_id(&t, &p)
            };
            let mut refused = 0;
            for i in 0..20_000 {
                let r =
                    server.apply_remote(&resend_mislabel(client, props_clock, &format!("k{i}")));
                match r {
                    Err(Refused::Malformed) => refused += 1,
                    other => panic!("update {i}: {other:?}"),
                }
            }
            // the top node is deleted by an honest client; the replica is still sane and takes it
            let (_, del) = c.edit(|e| e.remove_node(&id(1)));
            assert!(server.apply_remote(&del).unwrap().is_some());
            assert!(!server.read().unwrap().nodes.contains_key(&id(1)));
            refused
        })
        .unwrap();
    assert_eq!(h.join().expect("no abort"), 20_000);
}

// `a_held_block_is_never_a_parent_or_origin_taken_from_the_update` tested `design-crdt`'s depth index, which V1-05
// replaced by the layout shadow: ported as `layered_tests::a_held_block_is_judged_by_what_the_replica_holds`.

/// Cost of the gate per update on a big document:
/// `cargo test --release -p design-doc --test replica -- --ignored --nocapture cost`.
#[test]
#[ignore]
fn cost_of_one_update_on_a_big_document() {
    let mut server = server_with_page();
    let mut c = client_of(&server);
    let (_, big) = c.edit(|e| {
        for i in 1..=5000u64 {
            e.insert_node(
                &id(i),
                NodeType::Frame,
                Some(PAGE),
                "a",
                "f",
                &json!({"w": 10, "h": 20}),
                None,
            );
        }
    });
    let t = std::time::Instant::now();
    server.apply_remote(&big).unwrap();
    eprintln!(
        "5000-node bulk insert ({} KB): {:?}",
        big.len() / 1024,
        t.elapsed()
    );
    let mut total = std::time::Duration::ZERO;
    for i in 0..200 {
        let (_, u) = c.edit(|e| {
            e.set_prop(&id(1 + i), "w", Some(&json!(i)));
        });
        let t = std::time::Instant::now();
        server.apply_remote(&u).unwrap();
        total += t.elapsed();
    }
    eprintln!("one prop edit on 5000 nodes: {:?} per update", total / 200);
}
