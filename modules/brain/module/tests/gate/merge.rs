//! B4-01: merge-on-save. The Rust `body_norm` equals the SQL backfill; a fact seen in three sessions
//! is one record with support 3 and three citations; Undo puts it back. Every record here is made up.

use brain_model::merge::body_norm;
use brain_module::changes::{ChangeSet, undo};
use brain_module::files::{self, CANON};
use brain_module::merge::reinforce;
use sqlx::SqlitePool;

const KEY: [u8; 32] = [7; 32];

async fn pool() -> (tempfile::TempDir, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let p = files::open_migrated(&dir.path().join("room.db"), &KEY, true, CANON)
        .await
        .unwrap();
    (dir, p)
}

#[tokio::test]
async fn the_rust_normaliser_equals_the_sql_backfill() {
    let sql = include_str!("../../migrations/canon_0006.sql");
    let from = sql.find("UPDATE records SET body_norm").unwrap();
    let update = &sql[from..from + sql[from..].find(';').unwrap()];
    let bodies = [
        "  Deploy\ton   FRIDAYS \r\n",
        "plain",
        "",
        "   ",
        "A\t\tB\n\nC\r\nD",
        "ÄÖ Straße MIXED Case",
        "trailing\n",
        "x      y",
        "tag\u{a0}nbsp stays",
    ];
    let (_dir, pool) = pool().await;
    for (i, b) in bodies.iter().enumerate() {
        sqlx::query(
            "INSERT INTO records (id, type, status, body, tags, source_ids, created_at) \
             VALUES (?, 'fact', 'accepted', ?, '[]', '[]', '2026-11-10T10:00:00Z')",
        )
        .bind(format!("r{i}"))
        .bind(b)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("UPDATE records SET body_norm = NULL")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(update.to_owned()))
        .execute(&pool)
        .await
        .unwrap();
    for (i, b) in bodies.iter().enumerate() {
        let sql_norm: String = sqlx::query_scalar("SELECT body_norm FROM records WHERE id = ?")
            .bind(format!("r{i}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(body_norm(b), sql_norm, "body {b:?}");
    }
}

#[tokio::test]
async fn one_fact_from_three_sessions_is_one_record_and_undo_restores_it() {
    let (_dir, pool) = pool().await;
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, body_norm, last_seen_at) \
         VALUES ('rec-1', 'fact', 'accepted', 'We deploy on Fridays', '[]', '[\"s1\"]', '2026-11-10T10:00:00Z', 'we deploy on fridays', '2026-11-10T10:00:00Z')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_sources (record, source, position) VALUES ('rec-1', 's1', 0)")
        .execute(&pool)
        .await
        .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", "2026-11-11T10:00:00Z");
    reinforce(
        &mut tx,
        &mut cs,
        "rec-1",
        &["s2".to_owned()],
        &Default::default(),
        "2026-11-11T10:00:00Z",
    )
    .await
    .unwrap();
    reinforce(
        &mut tx,
        &mut cs,
        "rec-1",
        &["s3".to_owned(), "s1".to_owned()],
        &Default::default(),
        "2026-11-12T10:00:00Z",
    )
    .await
    .unwrap();
    let id = cs
        .commit(&mut tx, "Saved 0 · reinforced 2", serde_json::json!({}))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();

    let state = |p: SqlitePool| async move {
        let (support, seen): (i64, String) =
            sqlx::query_as("SELECT support, last_seen_at FROM records WHERE id = 'rec-1'")
                .fetch_one(&p)
                .await
                .unwrap();
        let cites: i64 =
            sqlx::query_scalar("SELECT count(*) FROM record_sources WHERE record = 'rec-1'")
                .fetch_one(&p)
                .await
                .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
            .fetch_one(&p)
            .await
            .unwrap();
        (support, seen, cites, rows)
    };
    assert_eq!(
        state(pool.clone()).await,
        (3, "2026-11-12T10:00:00Z".to_owned(), 3, 1)
    );

    let mut tx = pool.begin().await.unwrap();
    let done = undo(&mut tx, &id, "2026-11-13T10:00:00Z")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(done.restored, vec!["rec-1".to_owned()]);
    assert_eq!(
        state(pool.clone()).await,
        (1, "2026-11-10T10:00:00Z".to_owned(), 1, 1)
    );
}

/// A transcript part of AI session `session` in the room, as the collector writes one.
async fn part(p: &SqlitePool, id: &str, session: &str) {
    sqlx::query(
        "INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, \
         title, text, started_at, run, assigned_by) \
         VALUES (?, ?, 'ai_session', 'd', ?, 'agent', 'a', 't', 'x', '2026-11-10T10:00:00Z', 'r', 'rule')",
    )
    .bind(id)
    .bind(format!("h-{id}"))
    .bind(format!("core://ai-session/{session}"))
    .execute(p)
    .await
    .unwrap();
}

/// B5-02 review: support is the number of distinct origins, recounted, never incremented. One
/// session repeating a fact (twice, or in two parts) is 1; a second session is 2; a session the
/// Brain gave the record to adds a citation but no support; Undo puts support back.
#[tokio::test]
async fn support_counts_distinct_origins_and_never_a_session_that_loaded_the_record() {
    let (_dir, pool) = pool().await;
    for (id, session) in [("a1", "A"), ("a2", "A"), ("b1", "B"), ("c1", "C")] {
        part(&pool, id, session).await;
    }
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, body_norm) \
         VALUES ('rec-1', 'fact', 'accepted', 'We deploy on Fridays', '[]', '[\"a1\"]', '2026-11-10T10:00:00Z', 'we deploy on fridays')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_sources (record, source, position) VALUES ('rec-1', 'a1', 0)")
        .execute(&pool)
        .await
        .unwrap();
    let state = |p: SqlitePool| async move {
        let support: i64 = sqlx::query_scalar("SELECT support FROM records WHERE id = 'rec-1'")
            .fetch_one(&p)
            .await
            .unwrap();
        let cites: i64 =
            sqlx::query_scalar("SELECT count(*) FROM record_sources WHERE record = 'rec-1'")
                .fetch_one(&p)
                .await
                .unwrap();
        (support, cites)
    };
    let at = "2026-11-11T10:00:00Z";
    let none = std::collections::HashSet::new();

    // One session says it again, then again in a later part: still one origin.
    let mut tx = pool.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", at);
    reinforce(&mut tx, &mut cs, "rec-1", &["a1".to_owned()], &none, at)
        .await
        .unwrap();
    reinforce(&mut tx, &mut cs, "rec-1", &["a2".to_owned()], &none, at)
        .await
        .unwrap();
    cs.commit(&mut tx, "Saved 0 · reinforced 2", serde_json::json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(state(pool.clone()).await, (1, 2));

    // A second session: two origins. A third that was given the record and says it back: cited,
    // marked echo, and support does not move.
    let later = "2026-11-12T10:00:00Z";
    let loaded_c = std::collections::HashSet::from(["C".to_owned()]);
    let mut tx = pool.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", later);
    reinforce(&mut tx, &mut cs, "rec-1", &["b1".to_owned()], &none, later)
        .await
        .unwrap();
    reinforce(&mut tx, &mut cs, "rec-1", &["c1".to_owned()], &loaded_c, later)
        .await
        .unwrap();
    let id = cs
        .commit(&mut tx, "Saved 0 · reinforced 2", serde_json::json!({}))
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(state(pool.clone()).await, (2, 4));
    let echo: i64 = sqlx::query_scalar("SELECT echo FROM record_sources WHERE source = 'c1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(echo, 1);

    // Undo puts the support (and the citations) back.
    let mut tx = pool.begin().await.unwrap();
    undo(&mut tx, &id, "2026-11-13T10:00:00Z")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(state(pool.clone()).await, (1, 2));
}
