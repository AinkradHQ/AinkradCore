//! Round-5 review: the resend-and-relabel attack. A block the replica already holds is sent again, labelled as a
//! node map under `nodes`, together with a new `props` map whose parent is that block. yrs drops the resent block and
//! nests the new map under the real one, one level per update; 20 000 updates and a delete of the top node aborted
//! the process. Both layers must refuse it on their own: the layout gate (held blocks are skipped and looked up
//! only in the shadow) and the trial copy (its walk sees the map nested in props).

use yrs::{Doc, Map, MapPrelim, Transact};

use crate::{Error, Live, trial};

const ATTACKER: u64 = 4242;

fn var(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn string(out: &mut Vec<u8>, s: &str) {
    var(out, s.len() as u64);
    out.extend(s.as_bytes());
}

/// One map item: under root `nodes` with `key`, or under the type `parent` with key `props`.
fn map_item(out: &mut Vec<u8>, parent: Option<(u64, u32)>, key: &str) {
    out.push(0x20 | 7); // has a key, content = type
    match parent {
        None => {
            var(out, 1);
            string(out, "nodes");
        }
        Some((c, k)) => {
            var(out, 0);
            var(out, c);
            var(out, u64::from(k));
        }
    }
    string(out, key);
    out.push(1); // map
}

/// A base document (client 7: one node with a props map) and the id of that props map.
fn base() -> (Vec<u8>, (u64, u32)) {
    let d = Doc::with_client_id(7);
    let nodes = d.get_or_insert_map("nodes");
    let mut t = d.transact_mut();
    let node = nodes.insert(&mut t, "n_bbbbbbbbbbbb", MapPrelim::default());
    node.insert(&mut t, "type", "frame");
    node.insert(&mut t, "parent", yrs::Any::Null);
    node.insert(&mut t, "order", "a");
    let props = node.insert(&mut t, "props", MapPrelim::default());
    let yrs::BranchID::Nested(id) = props.as_ref().id() else {
        unreachable!()
    };
    let bytes = t.encode_update_v1();
    (bytes, (id.client.get(), id.clock))
}

/// Attack update `i`: resend the held block `held` as a node map under `nodes`, plus a new map (attacker, i) under it.
fn attack(i: u32, held: (u64, u32)) -> Vec<u8> {
    let mut u = vec![];
    let key = format!("n_{:0>12}", i);
    if held.0 == ATTACKER {
        // one run for the attacker: the resent block (i - 1), then the new one (i)
        var(&mut u, 1);
        var(&mut u, 2);
        var(&mut u, ATTACKER);
        var(&mut u, u64::from(held.1));
        map_item(&mut u, None, &key);
        map_item(&mut u, Some(held), "props");
    } else {
        var(&mut u, 2);
        var(&mut u, 1);
        var(&mut u, held.0);
        var(&mut u, u64::from(held.1));
        map_item(&mut u, None, &key);
        var(&mut u, 1);
        var(&mut u, ATTACKER);
        var(&mut u, u64::from(i));
        map_item(&mut u, Some(held), "props");
    }
    u.push(0); // no deletes
    u
}

fn small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn the_resend_relabel_chain_is_refused_and_nothing_aborts() {
    let (base, props) = base();
    let (refused, first, layout_ok) = small_stack(move || {
        let mut l = Live::new();
        l.apply_remote(&base).unwrap();
        let mut first = None;
        let mut refused = 0;
        for i in 0..20_000u32 {
            let held = if i == 0 { props } else { (ATTACKER, i - 1) };
            if let Err(e) = l.apply_remote(&attack(i, held)) {
                refused += 1;
                first.get_or_insert((i, e));
            }
        }
        // the final delete of the top node (the base client's node map, clock 0)
        let mut del = vec![0];
        var(&mut del, 1);
        var(&mut del, 7);
        var(&mut del, 1);
        var(&mut del, 0);
        var(&mut del, 1);
        let _ = l.apply_remote(&del);
        let _ = l.read();
        (refused, first, trial::walk(l.doc()))
    });
    assert!(
        matches!(first, Some((0, Error::Malformed(_)))),
        "refused at the first level: {first:?}"
    );
    // every other update finds its resent block unknown, so it is an honest new node with props: legal, depth 2
    assert!(refused >= 10_000, "{refused}");
    assert!(
        layout_ok,
        "the replica holds nothing deeper than node -> props"
    );
}

#[test]
fn the_trial_layer_alone_refuses_it() {
    // the gate is bypassed here: the trial copy gets the attack directly
    let (base, props) = base();
    let t = trial::run(None, base, &attack(0, props));
    assert!(t.is_err(), "a map nested in props fails the walk");
}

#[test]
fn the_gate_alone_refuses_it() {
    let (base, props) = base();
    let mut l = Live::new();
    l.apply_remote(&base).unwrap();
    let have = l.state_vector_struct();
    let r = l
        .gate
        .shadow
        .lock()
        .unwrap()
        .check(&attack(0, props), &have)
        .map(|_| ());
    assert!(r.is_err(), "{r:?}");
}

/// Ported from `design-crdt` (`a_held_block_is_never_a_parent_or_origin_taken_from_the_update`), against the layout
/// shadow that replaced its depth index: the update's own claim about a held block is ignored and what the replica
/// committed is the truth. The same relabelled resend that is refused under a props map is legal under a node map.
#[test]
fn a_held_block_is_judged_by_what_the_replica_holds() {
    let (base, props) = base();
    let mut l = Live::new();
    l.apply_remote(&base).unwrap();
    let have = l.state_vector_struct();
    let check = |u: &[u8]| l.gate.shadow.lock().unwrap().check(u, &have).map(|_| ());
    assert!(
        check(&attack(0, props)).is_err(),
        "a map under props: depth 3"
    );
    // the base's node map is client 7's first block: a props map under it is the layout
    assert!(
        check(&attack(0, (7, 0))).is_ok(),
        "a props map under a node map"
    );
}
