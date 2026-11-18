//! PR 324 review: held runner frames stay bounded when the Core never replies.
use ainkrad_proto::v2::{Body, Credit};

use super::*;

fn credit(bytes: u64) -> Body {
    Body::Credit(Credit { bytes })
}

#[test]
fn a_long_upload_with_no_reply_holds_one_credit_frame() {
    let mut h = Held::default();
    for _ in 0..10_000 {
        h.frame(3, credit(16 * 1024));
    }
    assert_eq!(h.sent.len(), 1);
    let kept = h.sent[0].body().unwrap().unwrap();
    assert!(matches!(kept, Body::Credit(c) if c.bytes == 10_000 * 16 * 1024));
}

#[test]
fn seqs_stay_unique_and_resend_filters_by_seq() {
    let mut h = Held::default();
    let seqs: Vec<u64> = (0..3).map(|_| h.frame(3, credit(1)).seq).collect();
    assert_eq!(seqs, [0, 1, 2]);
    assert_eq!((h.base, h.sent.len(), h.sent[0].seq), (2, 1, 2));
}
