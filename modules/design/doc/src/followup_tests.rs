//! Review follow-ups for the converged doc crate: the stack fallback, the outbox cap and the trusted load.

use crate::gate::Refused;
use crate::trial::big_stack_of;
use crate::{Live, Replica, parse_ops};
use serde_json::json;

#[test]
fn a_stack_that_cannot_be_reserved_falls_back_to_the_next_size() {
    // 1 << 60 bytes cannot be mapped; the second size can
    assert_eq!(big_stack_of(&[1usize << 60, 1 << 22], || 7), Ok(7));
}

#[test]
fn no_stack_at_all_is_busy_and_the_closure_did_not_run() {
    let ran = std::sync::atomic::AtomicBool::new(false);
    let r = big_stack_of(&[1usize << 60], || {
        ran.store(true, std::sync::atomic::Ordering::Relaxed)
    });
    assert_eq!(r, Err(Refused::Busy));
    assert!(!ran.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn one_update_over_the_cap_stays_queued_and_is_not_sent() {
    let mut l = Live::new();
    let ops = json!([{"op": "add", "id": "n_aaaaaaaaaaaa", "type": "page", "parent": null, "order": "a"}]);
    l.apply_ops(&parse_ops(ops.to_string().as_bytes()).unwrap())
        .unwrap();
    assert!(l.outbox_under(true, 4).is_empty(), "over the cap: nothing goes out");
    assert!(!l.outbox(false).is_empty(), "and it is still queued");
}

#[test]
fn from_stored_takes_good_bytes_and_refuses_garbage() {
    let mut l = Live::new();
    let ops = json!([{"op": "add", "id": "n_aaaaaaaaaaaa", "type": "page", "parent": null, "order": "a"}]);
    l.apply_ops(&parse_ops(ops.to_string().as_bytes()).unwrap())
        .unwrap();
    let good = l.outbox(true);
    let r = Replica::from_stored([good.as_slice()]).unwrap();
    assert_eq!(r.read().unwrap().nodes.len(), 1);
    assert!(Replica::from_stored([&[0xff, 0xff, 0xff][..]]).is_err());
}
