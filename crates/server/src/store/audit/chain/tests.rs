//! The hash chain (E1-10.1) and its export (E1-10.3): a whole chain verifies from the database
//! and from its export alone; a row changed or removed behind the triggers' back is named.

use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use sqlx::AssertSqlSafe;

use super::*;
use crate::store::audit::append_one;
use crate::store::connect;
use crate::store::kinds::allow;

struct Db {
    pool: SqlitePool,
    dir: std::path::PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A database with `n` chained rows.
async fn db(n: i64) -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let k = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-chain-{}-{k}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    allow(&pool, &[], &["thing.done"]).await;
    for i in 1..=n {
        append_one(&pool, &row(i)).await.unwrap();
    }
    Db { pool, dir }
}

fn row(i: i64) -> NewAuditEvent {
    NewAuditEvent {
        actor: AuditActor::System,
        action: "thing.done".to_owned(),
        entity: None,
        details: format!(r#"{{"i":{i},"z":"last","a":"first"}}"#),
    }
}

async fn sql(pool: &SqlitePool, sql: &str) {
    sqlx::raw_sql(AssertSqlSafe(sql.to_owned()))
        .execute(pool)
        .await
        .unwrap();
}

async fn broken(pool: &SqlitePool) -> Broken {
    verify_db(pool).await.unwrap().unwrap_err()
}

#[tokio::test]
async fn a_whole_chain_verifies_from_the_database_and_from_its_export() {
    let db = db(5).await;
    let done = verify_db(&db.pool).await.unwrap().unwrap();
    assert_eq!((done.rows, done.unchained), (5, 0));
    let (seq, head) = done.head.clone().unwrap();
    assert_eq!((seq, head.len()), (5, 64));

    let mut out = Vec::new();
    assert_eq!(export(&db.pool, &mut out).await.unwrap(), 5);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(text.lines().count(), 5);
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(first["prev_hash"], GENESIS);
    assert_eq!(
        first["details"], r#"{"i":1,"z":"last","a":"first"}"#,
        "as stored"
    );
    assert_eq!(
        verify_export(&out[..]).unwrap(),
        done,
        "the export alone re-verifies"
    );

    // An edited line of the export fails on its own too.
    let edited = text.replacen(r#"\"i\":3"#, r#"\"i\":33"#, 1);
    let err = verify_export(edited.as_bytes()).unwrap_err().to_string();
    assert!(err.contains("seq 3"), "{err}");
}

#[tokio::test]
async fn a_row_edited_with_the_triggers_dropped_is_named() {
    let db = db(5).await;
    sql(&db.pool, "DROP TRIGGER audit_events_no_update").await;
    sql(
        &db.pool,
        r#"UPDATE audit_events SET details = '{"i":3,"z":"x"}' WHERE seq = 3"#,
    )
    .await;
    let b = broken(&db.pool).await;
    assert_eq!(b.seq, 3, "{b}");
    assert!(b.why.contains("changed"), "{b}");
}

#[tokio::test]
async fn a_removed_row_is_named_by_the_one_after_it_and_a_removed_tail_by_the_counter() {
    let db = db(5).await;
    sql(&db.pool, "DROP TRIGGER audit_events_no_delete").await;
    sql(&db.pool, "DELETE FROM audit_events WHERE seq = 3").await;
    let b = broken(&db.pool).await;
    assert_eq!(b.seq, 4, "{b}");

    let db = db_tail().await;
    let b = broken(&db.pool).await;
    assert_eq!(b.seq, 5, "{b}");
}

async fn db_tail() -> Db {
    let db = db(5).await;
    sql(&db.pool, "DROP TRIGGER audit_events_no_delete").await;
    sql(&db.pool, "DELETE FROM audit_events WHERE seq = 5").await;
    db
}

#[tokio::test]
async fn a_raw_insert_cannot_join_the_chain() {
    let db = db(2).await;
    let err = sqlx::query(
        "INSERT INTO audit_events (actor_kind, action) VALUES ('system', 'thing.done')",
    )
    .execute(&db.pool)
    .await
    .unwrap_err();
    assert!(err.to_string().contains("hash-chained"), "{err}");
    // A made-up link to the wrong head is refused too.
    let err = sqlx::query(
        "INSERT INTO audit_events (seq, actor_kind, action, prev_hash, hash) \
         VALUES (3, 'system', 'thing.done', zeroblob(32), zeroblob(32))",
    )
    .execute(&db.pool)
    .await
    .unwrap_err();
    assert!(err.to_string().contains("hash-chained"), "{err}");
}

/// Rows from before migration 0002 have no hash: counted, and the chain starts after them.
#[tokio::test]
async fn rows_from_before_the_chain_are_counted_and_the_chain_starts_after_them() {
    let db = db(0).await;
    let trigger: String =
        sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE name = 'audit_events_chained'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    sql(&db.pool, "DROP TRIGGER audit_events_chained").await;
    for _ in 0..2 {
        sql(
            &db.pool,
            "INSERT INTO audit_events (actor_kind, action) VALUES ('system', 'thing.done')",
        )
        .await;
    }
    sql(&db.pool, &trigger).await;
    append_one(&db.pool, &row(3)).await.unwrap();
    append_one(&db.pool, &row(4)).await.unwrap();
    let done = verify_db(&db.pool).await.unwrap().unwrap();
    assert_eq!((done.rows, done.unchained), (4, 2));

    // An unchained row after the chain began is refused by the trigger, and by verify.
    sql(&db.pool, "DROP TRIGGER audit_events_chained").await;
    sql(
        &db.pool,
        "INSERT INTO audit_events (actor_kind, action) VALUES ('system', 'thing.done')",
    )
    .await;
    assert_eq!(broken(&db.pool).await.seq, 5);
}
