//! V2-02 review fixes: hostile peers. Deep nesting must be refused without aborting on a 512 KB stack (the App's
//! render thread); presence expires; `UPDATE_SEEDS=1` rewrites the `fuzz/seeds/apply` corpus from real updates.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use design_doc::{Error, Live, MAX_PEERS, PEER_TTL_MS, parse_ops};
use serde_json::json;
use yrs::sync::awareness::{AwarenessUpdate, AwarenessUpdateEntry};
use yrs::updates::encoder::Encode;
use yrs::{Any, Array, ClientID, Doc, Map, MapPrelim, Out, Transact};

const PAGE: &str = "n_aaaaaaaaaaaa";
const FRAME: &str = "n_bbbbbbbbbbbb";

/// Run `f` on a thread with the render thread's stack.
fn small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

/// A hostile replica in the T1 layout that records every update it makes.
fn hostile() -> (Doc, Arc<Mutex<Vec<Vec<u8>>>>) {
    let d = Doc::new();
    let log: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let l = log.clone();
    d.observe_update_v1("log", move |_, e| l.lock().unwrap().push(e.update.clone()))
        .unwrap();
    let nodes = d.get_or_insert_map("nodes");
    let mut t = d.transact_mut();
    for (id, ty, parent) in [(PAGE, "page", Any::Null), (FRAME, "frame", Any::from(PAGE))] {
        let n: MapPrelim = [
            ("type", yrs::In::Any(Any::from(ty))),
            ("parent", yrs::In::Any(parent)),
            ("order", yrs::In::Any(Any::from("a"))),
            ("props", yrs::In::Map(MapPrelim::default())),
        ]
        .into_iter()
        .collect();
        nodes.insert(&mut t, id, n);
    }
    drop(t);
    (d, log)
}

#[test]
fn a_deep_chain_of_maps_in_props_is_refused_on_a_small_stack() {
    let (d, log) = hostile();
    let nodes = d.get_or_insert_map("nodes");
    let mut cur = {
        let t = d.transact();
        match nodes.get(&t, FRAME) {
            Some(Out::YMap(n)) => match n.get(&t, "props") {
                Some(Out::YMap(p)) => p,
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    };
    // one small update per level, so no single update is deep
    for _ in 0..20_000 {
        let mut t = d.transact_mut();
        cur = cur.insert(&mut t, "k", MapPrelim::default());
    }
    let updates = std::mem::take(&mut *log.lock().unwrap());
    assert!(updates.len() > 20_000);
    let (refused, pages, frame) = small_stack(move || {
        let mut l = Live::new();
        l.apply_remote(&updates[0]).unwrap(); // the two nodes
        // the first level is a map inside props: refused by the layout; every later one builds on a refused block
        let refused = updates[1..]
            .iter()
            .filter(|u| l.apply_remote(u).is_err())
            .count();
        let doc = l.read();
        let _ = l.diff(&[]).unwrap();
        (
            refused,
            doc.nodes.contains_key(PAGE),
            doc.nodes.contains_key(FRAME),
        )
    });
    assert_eq!(refused, 20_000);
    assert!(
        pages && frame,
        "both nodes read; no level of the chain got in"
    );
}

/// The #301 review's PoC: ONE update holding a 20 000-deep chain of nested maps under a node, whose delete set
/// removes that node. yrs integrates and then deletes / garbage-collects the chain recursively, which overflows the
/// stack inside `apply_update` (an abort). The layout gate refuses it before yrs sees it.
#[test]
fn a_deep_chain_inside_one_update_is_refused_before_yrs() {
    // building (and dropping) the chain recurses in yrs too: do it on a big stack and leak the source document
    let merged = std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(|| {
            let a = Doc::with_client_id(7);
            let nodes = a.get_or_insert_map("nodes");
            let mut u = vec![];
            {
                let mut t = a.transact_mut();
                let mut m = nodes.insert(&mut t, "n_xxxxxxxxxxxx", MapPrelim::default());
                for _ in 0..20_000 {
                    m = m.insert(&mut t, "k", MapPrelim::default());
                }
                u.push(t.encode_update_v1());
            }
            {
                let mut t = a.transact_mut();
                nodes.remove(&mut t, "n_xxxxxxxxxxxx");
                u.push(t.encode_update_v1());
            }
            std::mem::forget(a);
            yrs::merge_updates_v1(&u).unwrap()
        })
        .unwrap()
        .join()
        .unwrap();
    let r = small_stack(move || Live::new().apply_remote(&merged));
    assert!(matches!(r, Err(Error::Malformed(_))), "{r:?}");
}

#[test]
fn list_side_content_in_a_map_and_rich_text_are_refused() {
    // an item with no key under the `nodes` root: invisible to every key-based read
    let c = Doc::with_client_id(9);
    let arr = c.get_or_insert_array("nodes");
    let hidden = {
        let mut t = c.transact_mut();
        arr.push_back(&mut t, "x".repeat(1000));
        t.encode_update_v1()
    };
    assert!(matches!(
        Live::new().apply_remote(&hidden),
        Err(Error::Malformed(_))
    ));
    // another root
    let d = Doc::with_client_id(10);
    let other = d.get_or_insert_map("elsewhere");
    let u = {
        let mut t = d.transact_mut();
        other.insert(&mut t, "k", 1.0);
        t.encode_update_v1()
    };
    assert!(matches!(
        Live::new().apply_remote(&u),
        Err(Error::Malformed(_))
    ));
    // a text node whose text carries formatting (not a plain string)
    let (d, log) = hostile();
    let nodes = d.get_or_insert_map("nodes");
    let text = {
        let mut t = d.transact_mut();
        let Some(Out::YMap(n)) = nodes.get(&t, FRAME) else {
            unreachable!()
        };
        n.insert(&mut t, "text", yrs::TextPrelim::new(""))
    };
    let mut l = Live::new();
    for u in log.lock().unwrap().drain(..) {
        l.apply_remote(&u).unwrap();
    }
    {
        let mut t = d.transact_mut();
        let attrs: yrs::types::Attrs = [(Arc::<str>::from("bold"), Any::Bool(true))]
            .into_iter()
            .collect();
        yrs::Text::insert_with_attributes(&text, &mut t, 0, "hi", attrs);
    }
    let rich = log.lock().unwrap().drain(..).collect::<Vec<_>>();
    assert!(rich.iter().any(|u| l.apply_remote(u).is_err()));
}

#[test]
fn a_hundred_thousand_clients_in_one_update_stay_linear() {
    // 100 000 clients, one GC block each: varint count, then per client (1 struct, client, clock 0, info 0, len 1)
    let mut u = vec![];
    let var = |u: &mut Vec<u8>, mut v: u64| loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            u.push(b);
            break;
        }
        u.push(b | 0x80);
    };
    var(&mut u, 100_000);
    for c in 1..=100_000u64 {
        var(&mut u, 1);
        var(&mut u, c);
        u.extend([0, 0, 1]);
    }
    u.push(0); // empty delete set
    let t = std::time::Instant::now();
    let _ = Live::new().apply_remote(&u);
    assert!(t.elapsed().as_secs() < 30, "{:?}", t.elapsed());
}

#[test]
fn deeply_nested_values_are_refused_at_decode() {
    let nest = |depth: usize| {
        let mut v = Any::from(1.0);
        for _ in 0..depth {
            v = Any::Array(vec![v].into());
        }
        v
    };
    let (d, log) = hostile();
    let meta = d.get_or_insert_map("meta");
    meta.insert(&mut d.transact_mut(), "ok", nest(10));
    meta.insert(&mut d.transact_mut(), "deep", nest(100));
    let u = log.lock().unwrap().clone();
    let (deep, u) = u.split_last().unwrap();
    let mut l = Live::new();
    for x in u {
        l.apply_remote(x).unwrap();
    }
    match l.apply_remote(deep) {
        Err(Error::Malformed(m)) => assert!(
            !m.contains("resync"),
            "refused for its depth, not a gap: {m}"
        ),
        r => panic!("{r:?}"),
    }
    let u = &u[u.len() - 1..];
    // a collection claiming more elements than there are bytes: 0x75 (array) with length 2^40
    let mut lie = u[0].clone();
    if let Some(p) = lie.windows(2).position(|w| w == [117, 1]) {
        lie.splice(p + 1..p + 2, [0x80, 0x80, 0x80, 0x80, 0x80, 0x20]);
        assert!(l.apply_remote(&lie).is_err());
    }
}

#[test]
fn an_update_listing_a_client_twice_is_refused() {
    // found by the `apply` fuzz target: yrs merged the overlapping block lists and freed a block still in use
    let base = include_bytes!("../fuzz/seeds/apply/base");
    let bad = include_bytes!("../fuzz/regressions/duplicate-client-uaf");
    let mut l = Live::new();
    l.apply_remote(base).unwrap();
    let before = l.read();
    assert!(matches!(l.apply_remote(bad), Err(Error::Malformed(_))));
    assert_eq!(l.read(), before);
}

/// yrs would keep this update as pending and then panic re-encoding it (`merge_pending_v1` unwrap; found by mutating
/// real updates). It starts past what the replica has, so it is refused before yrs sees it.
const PENDING_BAD: &[u8] = include_bytes!("../fuzz/regressions/pending-merge-panic");
const BASE: &[u8] = include_bytes!("../fuzz/seeds/apply/base");

#[test]
fn bad_pending_updates_are_refused_and_local_edits_survive() {
    let mut l = Live::new();
    let set_w = |l: &mut Live, w: u32| {
        let op = json!([{"op": "set", "id": FRAME, "key": "w", "value": w}]);
        l.apply_ops(&parse_ops(op.to_string().as_bytes()).unwrap())
    };
    l.apply_remote(BASE).unwrap();
    assert!(matches!(
        l.apply_remote(PENDING_BAD),
        Err(Error::Malformed(_))
    ));
    set_w(&mut l, 777).unwrap();
    assert!(matches!(
        l.apply_remote(PENDING_BAD),
        Err(Error::Malformed(_))
    ));
    set_w(&mut l, 778).unwrap();
    assert_eq!(l.read().nodes[FRAME].props["w"], json!(778));
    let mut peer = Live::new();
    peer.apply_remote(BASE).unwrap();
    peer.apply_remote(&l.outbox(true)).unwrap();
    assert_eq!(peer.read().nodes[FRAME].props["w"], json!(778));
}

/// The `apply` fuzz target's input format (`[0xf0 | k, a, b, rest]`, cut into 3 updates): the second update starts
/// a client at clock 1 with nothing before it (pending in yrs), the third overlaps it, and yrs's pending merge then
/// used freed memory (ASan). Both are refused before yrs sees them.
#[test]
fn overlapping_pending_updates_are_refused() {
    let d = include_bytes!("../fuzz/regressions/split-pending-uaf");
    let (k, a, b, rest) = (d[0], d[1], d[2], &d[3..]);
    assert!(k >= 0xf0 && k & 1 == 1);
    let at = |f: u8| rest.len() * f as usize / 256;
    let (x, y) = (at(a).min(at(b)), at(a).max(at(b)));
    let mut l = Live::new();
    l.apply_remote(BASE).unwrap();
    assert!(l.apply_remote(&rest[..x]).is_err());
    assert!(matches!(
        l.apply_remote(&rest[x..y]),
        Err(Error::Malformed(_))
    ));
    assert!(matches!(
        l.apply_remote(&rest[y..]),
        Err(Error::Malformed(_))
    ));
    assert_eq!(l.read().nodes.len(), 3);
}

fn op(l: &mut Live, v: serde_json::Value) {
    l.apply_ops(&parse_ops(v.to_string().as_bytes()).unwrap())
        .unwrap();
}

#[test]
fn incremental_edits_relay_one_at_a_time() {
    let (mut a, mut b) = (Live::new(), Live::new());
    a.apply_remote(BASE).unwrap();
    b.apply_remote(BASE).unwrap();
    for (i, id) in [
        "n_ffffffffffff",
        "n_gggggggggggg",
        "n_hhhhhhhhhhhh",
        "n_iiiiiiiiiiii",
        "n_jjjjjjjjjjjj",
    ]
    .into_iter()
    .enumerate()
    {
        // a new node with a props map (refers to its parent and to blocks of this same update), an edit of an
        // existing node, and a node added and deleted in the same batch (a delete of this update's own blocks)
        op(
            &mut a,
            json!([
                {"op": "add", "id": id, "type": "frame", "parent": FRAME, "order": format!("b{}", i + 1),
                 "props": {"w": 10 + i, "h": 20}},
                {"op": "set", "id": FRAME, "key": "w", "value": 400 + i},
                {"op": "add", "id": "n_zzzzzzzzzzzz", "type": "rect", "parent": FRAME, "order": "z"},
                {"op": "delete", "id": "n_zzzzzzzzzzzz"},
            ]),
        );
        b.apply_remote(&a.outbox(true))
            .unwrap_or_else(|e| panic!("edit {i}: {e:?}"));
        assert_eq!(b.read(), a.read(), "edit {i}");
    }
}

#[test]
fn a_state_vector_resync_after_an_out_of_order_update() {
    let (mut a, mut b) = (Live::new(), Live::new());
    a.apply_remote(BASE).unwrap();
    b.apply_remote(BASE).unwrap();
    op(
        &mut a,
        json!([{"op": "set", "id": FRAME, "key": "w", "value": 1}]),
    );
    let first = a.outbox(true);
    op(
        &mut a,
        json!([{"op": "add", "id": "n_ffffffffffff", "type": "frame", "parent": FRAME, "order": "b",
                       "props": {"w": 5}}]),
    );
    let second = a.outbox(true);
    assert!(
        matches!(b.apply_remote(&second), Err(Error::Malformed(_))),
        "arrived before the first"
    );
    b.apply_remote(&a.diff(&b.state_vector()).unwrap()).unwrap();
    assert_eq!(b.read(), a.read());
    b.apply_remote(&first).unwrap(); // the late one is already held
    assert_eq!(b.read(), a.read());
}

#[test]
fn skip_blocks_are_refused() {
    let mut a = Live::new();
    a.apply_remote(BASE).unwrap();
    let mut parts = vec![];
    for w in [1, 2, 3] {
        op(
            &mut a,
            json!([{"op": "set", "id": FRAME, "key": "w", "value": w}]),
        );
        parts.push(a.outbox(true));
    }
    // merging the first and third leaves a skip where the second was
    let merged = yrs::merge_updates_v1([parts[0].as_slice(), parts[2].as_slice()]).unwrap();
    let mut b = Live::new();
    b.apply_remote(BASE).unwrap();
    match b.apply_remote(&merged) {
        Err(Error::Malformed(m)) => assert!(!m.contains("resync"), "refused at decode: {m}"),
        r => panic!("{r:?}"),
    }
    for p in &parts {
        b.apply_remote(p).unwrap();
    }
    assert_eq!(b.read(), a.read());
}

#[test]
fn an_update_with_a_gap_is_refused_until_the_resync() {
    let mut a = Live::new();
    a.apply_remote(BASE).unwrap();
    let op = json!([{"op": "name", "id": FRAME, "name": "Home"}]);
    a.apply_ops(&parse_ops(op.to_string().as_bytes()).unwrap())
        .unwrap();
    let later = a.outbox(true);
    let mut b = Live::new();
    assert!(
        matches!(b.apply_remote(&later), Err(Error::Malformed(_))),
        "it builds on BASE, which b lacks"
    );
    b.apply_remote(BASE).unwrap();
    b.apply_remote(&later).unwrap();
    assert_eq!(b.read().nodes[FRAME].name, "Home");
}

fn peers(first: u64, n: u64) -> Vec<u8> {
    let clients: HashMap<ClientID, AwarenessUpdateEntry> = (first..first + n)
        .map(|i| {
            let e = AwarenessUpdateEntry {
                clock: 1,
                json: format!(r#"{{"label":"p{i}"}}"#).into(),
            };
            (ClientID::new(i), e)
        })
        .collect();
    AwarenessUpdate { clients }.encode_v1()
}

#[test]
fn peers_expire_and_new_ones_get_in() {
    let now = Arc::new(AtomicU64::new(1_000_000));
    let n2 = now.clone();
    let mut l = Live::with_clock(Arc::new(move || n2.load(Ordering::Relaxed)));
    let batch = MAX_PEERS as u64;
    for b in 0..4 {
        l.presence().apply(&peers(1000 + b * batch, batch)).unwrap();
    }
    assert!(
        l.presence().apply(&peers(9000, batch)).is_err(),
        "256 live peers is the cap"
    );
    now.fetch_add(PEER_TTL_MS + 1, Ordering::Relaxed);
    assert!(
        l.presence().peers().as_object().unwrap().is_empty(),
        "all expired"
    );
    // many generations of peers come and go; the table never fills up
    for g in 0..40 {
        l.presence()
            .apply(&peers(100_000 + g * batch, batch))
            .unwrap();
        now.fetch_add(PEER_TTL_MS + 1, Ordering::Relaxed);
    }
    l.presence().apply(&peers(9000, batch)).unwrap();
    assert_eq!(l.presence().peers().as_object().unwrap().len(), MAX_PEERS);
}

/// Real updates for the `apply` fuzz target: a base state and the updates of each op kind on top of it.
#[test]
fn fuzz_seeds() {
    let mut l = Live::new();
    let ops = |v: serde_json::Value| parse_ops(v.to_string().as_bytes()).unwrap();
    let mut seeds = vec![];
    l.apply_ops(&ops(json!([
        {"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"},
        {"op": "add", "id": FRAME, "type": "frame", "parent": PAGE, "order": "a", "props": {"w": 360, "h": 640,
         "fill": [{"type": "solid", "color": "#336699"}]}},
        {"op": "add", "id": "n_cccccccccccc", "type": "text", "parent": FRAME, "order": "a", "text": "Hello"},
    ])))
    .unwrap();
    seeds.push(("base", l.outbox(true)));
    for (name, v) in [
        (
            "set",
            json!([{"op": "set", "id": FRAME, "key": "w", "value": 400}]),
        ),
        (
            "text",
            json!([{"op": "text", "id": "n_cccccccccccc", "text": "Hi there"}]),
        ),
        (
            "move",
            json!([{"op": "move", "id": "n_cccccccccccc", "parent": PAGE, "order": "b"}]),
        ),
        ("delete", json!([{"op": "delete", "id": FRAME}])),
    ] {
        l.apply_ops(&ops(v)).unwrap();
        seeds.push((name, l.outbox(true)));
    }
    seeds.push(("full", l.diff(&[]).unwrap()));
    let mut b = Live::new();
    for (name, s) in &seeds {
        assert!(!s.is_empty(), "{name}");
        b.apply_remote(s).unwrap();
    }
    assert_eq!(b.read(), l.read());
    if std::env::var_os("UPDATE_SEEDS").is_some() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/apply");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, s) in seeds {
            std::fs::write(dir.join(name), s).unwrap();
        }
    }
}

/// Cost of the trial layer on a spike-size document (5 000 nodes): `cargo test --release -p design-doc --test hostile
/// trial_cost -- --ignored --nocapture`.
#[test]
#[ignore]
fn trial_cost() {
    let mut a = Live::new();
    a.apply_remote(BASE).unwrap();
    for batch in 0..25 {
        let ops: Vec<_> = (0..200)
            .map(|i| {
                let n = batch * 200 + i;
                let id: String = format!("{n:0>12}").chars().map(|c| (b'k' + (c as u8 - b'0')) as char).collect();
                json!({"op": "add", "id": format!("n_{id}"), "type": "rect", "parent": FRAME,
                       "order": format!("c{n}z"), "props": {"w": 10, "h": 10, "x": n % 1000, "y": n / 1000}})
            })
            .collect();
        op(&mut a, serde_json::Value::Array(ops));
    }
    let full = a.diff(&[]).unwrap();
    let mut b = Live::new();
    let t = std::time::Instant::now();
    b.apply_remote(&full).unwrap();
    println!(
        "full state {} KB: first apply (builds the trial) {:?}",
        full.len() / 1024,
        t.elapsed()
    );
    a.outbox(true);
    let mut times = vec![];
    for i in 0..20 {
        op(
            &mut a,
            json!([{"op": "set", "id": FRAME, "key": "w", "value": 500 + i}]),
        );
        let u = a.outbox(true);
        let t = std::time::Instant::now();
        b.apply_remote(&u).unwrap();
        times.push(t.elapsed());
    }
    times.sort();
    println!(
        "one-prop edit, 20 runs: median {:?}, max {:?}",
        times[10], times[19]
    );
}
