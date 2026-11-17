//! V1-03 acceptance at the CRDT layer: replicas converge through the gate, a hostile update is refused, crossing moves
//! revert, a rebalance does not undo a concurrent move, and a refused update poisons the replica.

use design_crdt::{MAX_UPDATE_BYTES, NodeType, Refused, Replica};
use design_model::tree::forest;
use serde_json::{Value, json};
use yrs::types::map::MapPrelim;
use yrs::{Any, Map as _, Transact, WriteTxn};

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
            "foreign root",
            forge(&server, |t| {
                t.get_or_insert_map("evil").insert(t, "k", 1);
            }),
            Refused::Invalid(String::new()),
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
            "wrong shape: node is a string",
            forge(&server, |t| {
                nm(t).insert(t, id(5).as_str(), "oops");
            }),
            Refused::Invalid(String::new()),
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
