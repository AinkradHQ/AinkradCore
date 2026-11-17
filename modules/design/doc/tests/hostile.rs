//! V2-02 review fixes: hostile peers. Deep nesting must be refused without aborting on a 512 KB stack (the App's
//! render thread); presence expires; `UPDATE_SEEDS=1` rewrites the `fuzz/seeds/apply` corpus from real updates.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use design_doc::{Error, Live, MAX_PEERS, PEER_TTL_MS, parse_ops};
use serde_json::json;
use yrs::sync::awareness::{AwarenessUpdate, AwarenessUpdateEntry};
use yrs::updates::encoder::Encode;
use yrs::{Any, ClientID, Doc, Map, MapPrelim, Out, Transact};

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
    let (pages, frame) = small_stack(move || {
        let mut l = Live::new();
        for u in &updates {
            l.apply_remote(u).unwrap();
        }
        let doc = l.read();
        let _ = l.diff(&[]).unwrap();
        (doc.nodes.contains_key(PAGE), doc.nodes.contains_key(FRAME))
    });
    assert!(pages, "the clean node still reads");
    assert!(!frame, "the node with nested maps in its props is left out");
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
    log.lock().unwrap().clear();
    let meta = d.get_or_insert_map("meta");
    meta.insert(&mut d.transact_mut(), "ok", nest(10));
    meta.insert(&mut d.transact_mut(), "deep", nest(100));
    let u = log.lock().unwrap().clone();
    let mut l = Live::new();
    l.apply_remote(&u[0]).unwrap();
    assert!(matches!(l.apply_remote(&u[1]), Err(Error::Malformed(_))));
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
