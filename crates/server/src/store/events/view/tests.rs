use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::*;
use crate::store::events::{append, last_event_seq, list_events, trim};
use crate::store::{begin_write, connect, kinds};

struct Db {
    pool: SqlitePool,
    dir: std::path::PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `ops.line` is `read`, `term.out` is `terminal`, `ops.secret` is `admin`.
async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-view-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let mut tx = begin_write(&pool).await.unwrap();
    let ops = [("ops.line", "read"), ("ops.secret", "admin")];
    kinds::register(&mut tx, "ops", &ops, &[]).await.unwrap();
    kinds::register(&mut tx, "term", &[("term.out", "terminal")], &[])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    Db { pool, dir }
}

async fn emit(pool: &SqlitePool, kinds: &[&str]) {
    let mut tx = begin_write(pool).await.unwrap();
    for k in kinds {
        append(&mut tx, k, &json!({})).await.unwrap();
    }
    tx.commit().await.unwrap();
}

fn reader() -> View {
    View::of(&["read".to_owned(), "approve".to_owned()])
}

async fn all_of(pool: &SqlitePool, v: View) -> Vec<StoredEvent> {
    replay(pool, v, 0, MAX_EVENTS).await.unwrap().unwrap()
}

#[tokio::test]
async fn a_view_sees_only_its_kinds_numbered_without_gaps() {
    let db = db().await;
    let pool = &db.pool;
    let pattern = [
        "term.out",
        "ops.line",
        "term.out",
        "term.out",
        "ops.secret",
        "ops.line",
    ];
    for _ in 0..7 {
        emit(pool, &pattern).await;
    }
    let mine = all_of(pool, reader()).await;
    assert_eq!(mine.len(), 14);
    assert!(mine.iter().all(|e| e.kind == "ops.line"));
    let seqs: Vec<i64> = mine.iter().map(|e| e.seq).collect();
    assert_eq!(
        seqs,
        (1..=14).collect::<Vec<_>>(),
        "gap-free: no hidden count leaks"
    );
    assert_eq!(head(pool, reader()).await.unwrap(), (14, 0));

    // The full view is the global log, seq for seq.
    let full = all_of(pool, View::all()).await;
    assert_eq!(full, list_events(pool, 0, MAX_EVENTS).await.unwrap());
    assert_eq!(
        head(pool, View::all()).await.unwrap().0,
        last_event_seq(pool).await.unwrap()
    );
    let terminal = View::of(&["read".to_owned(), "terminal".to_owned()]);
    assert_eq!(all_of(pool, terminal).await.len(), 35);

    // Resuming from every cursor returns exactly the rest, for each view.
    for v in [reader(), terminal, View::all()] {
        let every = all_of(pool, v).await;
        for after in 0..=every.len() as i64 + 2 {
            let got = replay(pool, v, after, MAX_EVENTS).await.unwrap().unwrap();
            let want: Vec<_> = every.iter().filter(|e| e.seq > after).cloned().collect();
            assert_eq!(got, want, "{v:?} after {after}");
        }
    }
}

#[tokio::test]
async fn trimming_raises_each_views_floor_in_its_own_numbers() {
    let db = db().await;
    let pool = &db.pool;
    emit(
        pool,
        &[
            "ops.line", "term.out", "term.out", "ops.line", "term.out", "ops.line",
        ],
    )
    .await;
    // Everything is old by a far clock; the batch of 4 trims seq 1 to 4.
    let t = trim(pool, "2999-01-01T00:00:00.000Z", 0, 4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t.floor, 4);
    assert_eq!(head(pool, reader()).await.unwrap(), (3, 2));
    assert_eq!(head(pool, View::all()).await.unwrap(), (6, 4));
    let past = replay(pool, reader(), 1, 10).await.unwrap().unwrap_err();
    assert_eq!(past.floor, 2, "the floor in the reader's numbers");
    let got = replay(pool, reader(), 2, 10).await.unwrap().unwrap();
    assert_eq!(got.iter().map(|e| e.seq).collect::<Vec<_>>(), [3]);
    // Appends after the trim keep counting.
    emit(pool, &["term.out", "ops.line"]).await;
    let got = replay(pool, reader(), 2, 10).await.unwrap().unwrap();
    assert_eq!(got.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4]);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM event_views WHERE seq < 4")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 0,
        "only the floor's own totals are kept below the log"
    );
}

#[tokio::test]
async fn a_kind_may_not_be_visible_to_runner_and_audit_is_admin_only() {
    let db = db().await;
    let mut tx = begin_write(&db.pool).await.unwrap();
    let refused = kinds::register(&mut tx, "run", &[("run.x", "runner")], &[]).await;
    assert!(matches!(refused, Err(sqlx::Error::InvalidArgument(_))));
    drop(tx);
    let scope: String = sqlx::query_scalar("SELECT scope FROM event_kinds WHERE kind = 'audit'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(scope, "admin");
}
