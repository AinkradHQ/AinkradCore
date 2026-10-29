//! Transcripts: ordered by seq, idempotent on resend, only from the lease holder.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::RunEvent;
use serde_json::json;

use super::lease::{assigned, working};
use super::wake::runner;
use super::*;

const NOW: &str = "2026-10-21T10:00:00.000Z";
/// Past the lease of a run claimed at `NOW`.
const LATER: &str = "2026-10-21T10:05:00.000Z";

#[tokio::test]
async fn chunks_are_ordered_idempotent_and_only_from_the_holder() {
    let db = db().await;
    let pool = &db.pool;
    assigned(pool, "A").await;
    let (mac, other) = (runner(pool, "mac").await, runner(pool, "other").await);
    let run = working(pool, mac, NOW).await;
    let chunk = |n: u64| json!({"type": "assistant_text", "text": format!("step {n}")});

    // Out of order, with a resend that differs: stored once, read back by seq.
    for seq in [2, 1, 3] {
        assert!(
            append_run_event(pool, run.id, mac, seq, &chunk(seq), NOW)
                .await
                .unwrap()
        );
    }
    let resent = json!({"type": "assistant_text", "text": "changed"});
    assert!(
        !append_run_event(pool, run.id, mac, 2, &resent, NOW)
            .await
            .unwrap()
    );
    let untyped = json!(["no", "type"]);
    assert!(
        append_run_event(pool, run.id, mac, 4, &untyped, NOW)
            .await
            .unwrap()
    );
    let stored = list_run_events(pool, run.id).await.unwrap();
    let seqs: Vec<i64> = stored.iter().map(|c| c.seq).collect();
    assert_eq!(seqs, [1, 2, 3, 4]);
    assert_eq!(stored[1].payload, chunk(2));
    assert_eq!(stored[1].kind, "assistant_text");
    assert_eq!(stored[3].kind, "chunk");
    assert_eq!(stored[0].at, NOW);

    // Another runner, a bad seq, an expired lease and an ended run are all refused.
    let not_holder = append_run_event(pool, run.id, other, 5, &chunk(5), NOW).await;
    assert!(
        matches!(not_holder, Err(ChunkError::NotHolder)),
        "{not_holder:?}"
    );
    let zero = append_run_event(pool, run.id, mac, 0, &chunk(0), NOW).await;
    assert!(matches!(zero, Err(ChunkError::BadSeq)));
    let huge = append_run_event(pool, run.id, mac, u64::MAX, &chunk(9), NOW).await;
    assert!(matches!(huge, Err(ChunkError::BadSeq)));
    let late = append_run_event(pool, run.id, mac, 5, &chunk(5), LATER).await;
    assert!(matches!(late, Err(ChunkError::NotHolder)), "{late:?}");
    let by = AuditActor::Runner(mac);
    transition_run(pool, run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    let ended = append_run_event(pool, run.id, mac, 5, &chunk(5), NOW).await;
    assert!(matches!(ended, Err(ChunkError::NotHolder)), "{ended:?}");
    assert_eq!(list_run_events(pool, run.id).await.unwrap().len(), 4);
}
