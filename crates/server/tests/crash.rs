//! Crash consistency (E1-03.4): a child process writes transactions in a loop and is killed
//! with SIGKILL at a random moment, again and again, on one database. After every kill the
//! database must pass `integrity_check`, and every transaction must be there whole or not at
//! all: its two audit rows, their trigger-written `audit` events and its own event.
//!
//! The child is this test binary run again for `crash_child` (which does nothing unless
//! `CORE_CRASH_CHILD_DB` is set). Iterations: `CORE_CRASH_ITERATIONS`, default 200.
//!
//! SIGKILL tests a process crash. It cannot tell `synchronous = FULL` from NORMAL: those differ
//! only when the OS or the power fails.

use std::time::Duration;

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core_server::store::{audit, begin_write, connect, events, kinds};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const CHILD_DB: &str = "CORE_CRASH_CHILD_DB";
const READY: &str = "crash-child-ready";

/// One transaction: two audits (each with its trigger-written event) and one event of its own,
/// all carrying the transaction's number `i`.
async fn write_one(pool: &SqlitePool, i: i64) -> Result<(), sqlx::Error> {
    let mut tx = begin_write(pool).await?;
    for action in ["crash.first", "crash.second"] {
        let event = NewAuditEvent {
            actor: AuditActor::System,
            action: action.to_owned(),
            entity: None,
            details: format!(r#"{{"i":{i}}}"#),
        };
        audit::append(&mut tx, &event).await?;
    }
    events::append(&mut tx, "crash.test", &serde_json::json!({"i": i})).await?;
    tx.commit().await
}

/// Registers the kind and actions the child writes, as a module `crash` would declare them.
async fn register(pool: &SqlitePool) {
    let mut tx = begin_write(pool).await.unwrap();
    let actions = ["crash.first", "crash.second"];
    kinds::register(&mut tx, "crash", &[("crash.test", "read")], &actions)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// The child: writes until it is killed. Not a test on its own.
#[tokio::test]
async fn crash_child() {
    let Ok(db) = std::env::var(CHILD_DB) else {
        return;
    };
    let pool = connect(db.as_ref()).await.unwrap();
    register(&pool).await;
    let mut i: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE kind = 'crash.test'")
        .fetch_one(&pool)
        .await
        .unwrap();
    println!("{READY}");
    loop {
        write_one(&pool, i).await.unwrap();
        i += 1;
    }
}

fn random_below(n: u64) -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    u64::from_le_bytes(bytes) % n
}

async fn scalar(pool: &SqlitePool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// Every invariant a kill must not break; returns the number of whole transactions.
async fn check(pool: &SqlitePool, iteration: u32) -> i64 {
    let integrity: Vec<String> = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(integrity, ["ok"], "iteration {iteration}");

    let txs = scalar(
        pool,
        "SELECT count(*) FROM events WHERE kind = 'crash.test'",
    )
    .await;
    let audits = scalar(pool, "SELECT count(*) FROM audit_events").await;
    let audit_events = scalar(pool, "SELECT count(*) FROM events WHERE kind = 'audit'").await;
    assert_eq!(audits, 2 * txs, "iteration {iteration}: a half transaction");
    assert_eq!(
        audit_events, audits,
        "iteration {iteration}: an audit without its event"
    );
    // No gap in either sequence, and transaction numbers 0..txs each exactly once.
    let gaps = [
        "SELECT coalesce(max(seq), 0) - count(*) FROM audit_events",
        "SELECT coalesce(max(seq), 0) - count(*) FROM events",
        "SELECT coalesce(max(payload ->> 'i') + 1, 0) - count(DISTINCT payload ->> 'i') \
         FROM events WHERE kind = 'crash.test'",
    ];
    for sql in gaps {
        assert_eq!(scalar(pool, sql).await, 0, "iteration {iteration}: {sql}");
    }
    // Every audit seq named by exactly one `audit` event (both are gapless, so a count and
    // the bounds pin the set), and every transaction number on exactly two audits. Linear
    // aggregates: a correlated subquery would make each check quadratic in the growing log.
    let linked = [
        (
            "SELECT count(DISTINCT payload ->> 'audit_seq') FROM events WHERE kind = 'audit'",
            audits,
        ),
        (
            "SELECT coalesce(max(payload ->> 'audit_seq'), 0) FROM events WHERE kind = 'audit'",
            audits,
        ),
        (
            "SELECT count(*) FROM (SELECT details ->> 'i' AS i FROM audit_events GROUP BY i \
             HAVING count(*) = 2)",
            txs,
        ),
        (
            "SELECT coalesce(max(details ->> 'i') + 1, 0) FROM audit_events",
            txs,
        ),
    ];
    for (sql, want) in linked {
        assert_eq!(
            scalar(pool, sql).await,
            want,
            "iteration {iteration}: {sql}"
        );
    }
    // The audit hash chain is whole (E1-10.1).
    if let Err(b) = audit::chain::verify_db(pool).await.unwrap() {
        panic!("iteration {iteration}: {b}");
    }
    // The append-only triggers survived.
    for sql in ["DELETE FROM audit_events", "UPDATE events SET kind = 'x'"] {
        let err = sqlx::query(sql).execute(pool).await.unwrap_err();
        assert!(err.to_string().contains("append-only"), "{err}");
    }
    txs
}

/// Starts the child on `db` and waits until it is writing.
async fn spawn_child(db: &std::path::Path, iteration: u32) -> tokio::process::Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crash_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(CHILD_DB, db)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = async {
        while let Some(line) = lines.next_line().await.unwrap() {
            // libtest may print `test crash_child ... ` ahead of it on the same line.
            if line.ends_with(READY) {
                return;
            }
        }
        panic!("iteration {iteration}: the child exited before it was ready");
    };
    tokio::time::timeout(Duration::from_secs(30), ready)
        .await
        .unwrap_or_else(|_| panic!("iteration {iteration}: the child never got ready"));
    child
}

#[tokio::test]
async fn a_killed_writer_leaves_a_consistent_database() {
    let iterations: u32 = std::env::var("CORE_CRASH_ITERATIONS")
        .ok()
        .map_or(200, |n| {
            n.parse().expect("CORE_CRASH_ITERATIONS is a number")
        });
    let dir = std::env::temp_dir().join(format!("core-crash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");

    let mut last = 0;
    for iteration in 0..iterations {
        let mut child = spawn_child(&db, iteration).await;
        // ponytail: kill points are uniform in the first 25 ms of writing; checkpoints and
        // the commit path are hit by volume, not aimed at.
        tokio::time::sleep(Duration::from_micros(random_below(25_000))).await;
        child.kill().await.unwrap();

        let pool = connect(&db).await.unwrap();
        let txs = check(&pool, iteration).await;
        assert!(
            txs >= last,
            "iteration {iteration}: committed transactions vanished"
        );
        last = txs;
        pool.close().await;
    }
    assert!(last > 0, "the child never committed");
    eprintln!("{iterations} kills, {last} whole transactions");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// E1-04 AC: a client reading the stream while the Core is killed (SIGKILL) resumes after the
/// restart from the last seq it read and gets exactly the events after it: across every kill,
/// what it read is 1..=head, each seq once, in order. It reads through `events::replay`, what
/// `GET /api/v1/events` and the socket serve. Iterations: `CORE_REPLAY_ITERATIONS`, default 30.
#[tokio::test]
async fn replay_after_a_kill_resumes_with_no_gap_and_no_duplicate() {
    let iterations: u32 = std::env::var("CORE_REPLAY_ITERATIONS")
        .ok()
        .map_or(30, |n| {
            n.parse().expect("CORE_REPLAY_ITERATIONS is a number")
        });
    let dir = std::env::temp_dir().join(format!("core-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("core.db");
    // The client: the seqs it read, and its resume point.
    let mut read: Vec<i64> = Vec::new();
    let mut cursor = 0;
    let catch_up = async |pool: &SqlitePool, read: &mut Vec<i64>, cursor: &mut i64| loop {
        let page = events::replay(pool, *cursor, 100).await.unwrap().unwrap();
        let Some(last) = page.last() else { return };
        *cursor = last.seq;
        read.extend(page.iter().map(|e| e.seq));
    };
    for iteration in 0..iterations {
        let mut child = spawn_child(&db, iteration).await;
        // A reader only: `connect` would migrate and register, writes that can starve behind a
        // writer this busy (SQLite's busy wait is not a queue).
        let reader = SqliteConnectOptions::new().filename(&db).read_only(true);
        let pool = SqlitePool::connect_with(reader).await.unwrap();
        // Read while the child writes, then kill it mid-way.
        let reading = async {
            for _ in 0..(1 + random_below(5)) {
                catch_up(&pool, &mut read, &mut cursor).await;
                tokio::time::sleep(Duration::from_micros(random_below(5_000))).await;
            }
        };
        reading.await;
        child.kill().await.unwrap();
        pool.close().await;

        // "Restart": a fresh pool on the same file; resume from the last seq read.
        let pool = connect(&db).await.unwrap();
        catch_up(&pool, &mut read, &mut cursor).await;
        let head = events::last_event_seq(&pool).await.unwrap();
        assert_eq!(cursor, head, "iteration {iteration}: caught up to the head");
        pool.close().await;
    }
    let want: Vec<i64> = (1..=cursor).collect();
    assert!(cursor > 0, "nothing was written");
    assert!(
        read == want,
        "{} events read, head {cursor}: a gap or a duplicate",
        read.len()
    );
    eprintln!("{iterations} kills, {cursor} events replayed with no gap or duplicate");
    std::fs::remove_dir_all(&dir).unwrap();
}
