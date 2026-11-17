//! The reset path itself (no known remote bytes reach it since `no_gap`, so it is driven directly): unsent local edits
//! survive, and the breaker halts remote updates after `MAX_RESETS` resets within the window.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use crate::{Error, Live, RESET_WINDOW_MS, parse_ops};

const BASE: &[u8] = include_bytes!("../fuzz/seeds/apply/base");
const FRAME: &str = "n_bbbbbbbbbbbb";

fn live() -> (Arc<AtomicU64>, Live) {
    let now = Arc::new(AtomicU64::new(1_000_000));
    let n = now.clone();
    (
        now,
        Live::with_clock(Arc::new(move || n.load(Ordering::Relaxed))),
    )
}

fn set_w(l: &mut Live, w: u32) {
    let op = json!([{"op": "set", "id": FRAME, "key": "w", "value": w}]);
    l.apply_ops(&parse_ops(op.to_string().as_bytes()).unwrap())
        .unwrap();
}

fn w(l: &Live) -> serde_json::Value {
    l.read().nodes[FRAME].props["w"].clone()
}

#[test]
fn unsent_edits_survive_resets_and_still_go_out() {
    let (_, mut l) = live();
    l.apply_remote(BASE).unwrap();
    set_w(&mut l, 777);
    l.reset();
    assert!(
        l.read().nodes.is_empty(),
        "the edit waits for what it builds on"
    );
    l.apply_remote(BASE).unwrap(); // the resync
    assert_eq!(w(&l), json!(777));
    set_w(&mut l, 778);
    l.reset();
    l.apply_remote(BASE).unwrap();
    assert_eq!(w(&l), json!(778));
    let out = l.outbox(true);
    let mut peer = Live::new();
    peer.apply_remote(BASE).unwrap();
    peer.apply_remote(&out).unwrap();
    assert_eq!(w(&peer), json!(778));
}

#[test]
fn three_resets_in_the_window_halt_remote_updates() {
    let (now, mut l) = live();
    l.reset();
    l.reset();
    now.fetch_add(RESET_WINDOW_MS + 1, Ordering::Relaxed); // those two leave the window
    l.reset();
    l.reset();
    l.apply_remote(BASE).unwrap(); // two in this window: still syncing
    set_w(&mut l, 5);
    l.reset(); // the third
    assert_eq!(l.apply_remote(BASE), Err(Error::Halted), "no resync loop");
    // local edits still queue and go out
    let add = json!([{"op": "add", "id": "n_zzzzzzzzzzzz", "type": "page", "parent": null, "order": "z"}]);
    l.apply_ops(&parse_ops(add.to_string().as_bytes()).unwrap())
        .unwrap();
    assert!(!l.outbox(false).is_empty());
}
