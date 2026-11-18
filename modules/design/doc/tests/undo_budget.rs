//! Undo and redo are held to the same 1 MiB update budget as an edit: deleting a large selection is a small update,
//! but undoing it writes every node back. That undo is refused (`TooLarge`) and reverted. Its update cannot be replaced by
//! a small one here (the restored nodes' content is in it), so it stays queued: the outbox reports stuck at once (#331),
//! refuses new edits, and the updates queued before it still go out.

use design_doc::{Error, Live, MAX_PEER_UPDATE_BYTES, parse_ops};
use serde_json::{Value, json};

const PAGE: &str = "n_aaaaaaaaaaaa";

fn id(mut i: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = vec![b'b'; 12];
    for c in s.iter_mut().rev() {
        *c = A[i % 32];
        i /= 32;
    }
    format!("n_{}", String::from_utf8(s).unwrap())
}

fn run(l: &mut Live, v: Value) {
    l.apply_ops(&parse_ops(v.to_string().as_bytes()).unwrap())
        .unwrap();
}

/// A page holding 500 texts of 3000 chars: ~1.5 MB in five batches, each well under the budget.
fn big(l: &mut Live) {
    run(
        l,
        json!([{"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"}]),
    );
    for b in 0..5 {
        let ops: Vec<Value> = (0..100)
            .map(|i| {
                json!({"op": "add", "id": id(b * 100 + i + 1), "type": "text", "parent": PAGE,
                       "order": "a", "text": "x".repeat(3000)})
            })
            .collect();
        run(l, Value::Array(ops));
    }
}

fn drain(l: &Live) -> Vec<Vec<u8>> {
    let mut chunks = vec![];
    for _ in 0..200 {
        let c = l.outbox(true);
        if c.is_empty() {
            assert!(
                !l.outbox_stuck(),
                "the outbox is stuck behind an oversized update"
            );
            return chunks;
        }
        assert!(c.len() <= MAX_PEER_UPDATE_BYTES, "{}", c.len());
        chunks.push(c);
    }
    panic!("the outbox never drained: the client would loop");
}

#[test]
fn undoing_a_big_delete_is_refused_reverted_and_does_not_loop() {
    let mut l = Live::new();
    big(&mut l);
    let mut peer = Live::new();
    for c in drain(&l) {
        peer.apply_remote(&c).unwrap();
    }
    run(&mut l, json!([{"op": "delete", "id": PAGE}]));
    assert!(l.read().nodes.is_empty());
    assert_eq!(l.undo_checked(), Err(Error::TooLarge));
    assert!(l.read().nodes.is_empty(), "the undo was reverted");
    assert!(
        l.outbox_stuck(),
        "stuck is reported as soon as the oversized update is queued"
    );
    assert!(!l.undo(), "the plain call just says false");
    assert_eq!(
        l.apply_ops(
            &parse_ops(
                br#"[{"op":"add","id":"n_bbbbbbbbbbbb","type":"page","parent":null,"order":"a"}]"#
            )
            .unwrap()
        ),
        Err(Error::TooLarge),
        "no new edits while stuck"
    );
    // what was queued before the oversized update still reaches a peer in chunks under the cap
    while !l.outbox(false).is_empty() {
        let c = l.outbox(true);
        assert!(c.len() <= MAX_PEER_UPDATE_BYTES);
        peer.apply_remote(&c).unwrap();
    }
    assert_eq!(peer.read(), l.read());
    assert!(l.outbox_stuck() && l.outbox(false).is_empty());
}

#[test]
fn a_small_undo_still_works() {
    let mut l = Live::new();
    run(
        &mut l,
        json!([{"op": "add", "id": PAGE, "type": "page", "parent": null, "order": "a"}]),
    );
    assert_eq!(l.undo_checked(), Ok(true));
    assert_eq!(l.redo_checked(), Ok(true));
    assert_eq!(l.read().nodes.len(), 1);
}
