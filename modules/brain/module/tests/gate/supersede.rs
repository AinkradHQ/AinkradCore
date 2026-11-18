//! B4-02: a replaced record leaves memory (`valid_to`), keeps its row as history linked to its
//! successor, and Undo restores both; a `replaces` aimed at a rule needs a user-grounded candidate;
//! the SQL staleness test equals the pure one. Every record here is made up.

use brain_model::merge::{STALE_SQL, is_stale};
use brain_module::changes::{ChangeSet, image, undo};
use brain_module::files::{self, CANON};
use brain_module::merge::supersede;
use sqlx::SqlitePool;

const KEY: [u8; 32] = [7; 32];
const T0: &str = "2026-11-10T10:00:00Z";
const NOW: &str = "2026-11-12T10:00:00Z";

async fn pool() -> (tempfile::TempDir, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let p = files::open_migrated(&dir.path().join("room.db"), &KEY, true, CANON)
        .await
        .unwrap();
    (dir, p)
}

async fn record(p: &SqlitePool, id: &str, kind: &str, at: &str) {
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, body_norm, last_seen_at) \
         VALUES (?, ?, 'accepted', ?, '[]', '[]', ?, ?, ?)",
    )
    .bind(id)
    .bind(kind)
    .bind(format!("body of {id}"))
    .bind(at)
    .bind(format!("body of {id}"))
    .bind(at)
    .execute(p)
    .await
    .unwrap();
}

async fn source(p: &SqlitePool, id: &str, record: &str, at: &str) {
    sqlx::query(
        "INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, \
         title, text, started_at, run, assigned_by) VALUES (?, ?, 'note', 'd', '/p', 'user', 'a', 't', 'x', ?, 'r', 'rule')",
    )
    .bind(id)
    .bind(format!("h-{id}"))
    .bind(at)
    .execute(p)
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_sources (record, source, position) VALUES (?, ?, 0)")
        .bind(record)
        .bind(id)
        .execute(p)
        .await
        .unwrap();
}

/// Runs `supersede(old, new)` in its own change set; returns (superseded, change id when written).
async fn run(p: &SqlitePool, old: &str, new: &str, grounded: bool) -> (bool, Option<String>) {
    let mut tx = p.begin().await.unwrap();
    let mut cs = ChangeSet::new("distil", NOW);
    let done = supersede(&mut tx, &mut cs, old, new, grounded, NOW)
        .await
        .unwrap();
    let id = cs
        .commit(&mut tx, "Saved 1 · replaced 1", serde_json::json!({}))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (done, id)
}

async fn in_memory(p: &SqlitePool, id: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM memory WHERE id = ?")
        .bind(id)
        .fetch_one(p)
        .await
        .unwrap()
        > 0
}

async fn row(p: &SqlitePool, id: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    sqlx::query_as("SELECT valid_from, valid_to, supersedes, superseded_by FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(p)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_replaced_record_leaves_memory_stays_as_history_and_undo_restores_both() {
    let (_d, p) = pool().await;
    record(&p, "old", "project-state", T0).await;
    record(&p, "new", "project-state", NOW).await;
    source(&p, "s-new", "new", "2026-11-11T09:00:00Z").await;
    let mut conn = p.acquire().await.unwrap();
    let (old_img, new_img) = (
        image(&mut conn, "old").await.unwrap(),
        image(&mut conn, "new").await.unwrap(),
    );
    drop(conn);

    let (done, change) = run(&p, "old", "new", false).await;
    assert!(done);
    // The moment the new fact began: its earliest cited source.
    let at = Some("2026-11-11T09:00:00Z".to_owned());
    // `old` never had a `valid_from` here (a row from before B2-01's backfill would); the link and
    // `valid_to` are what B4-02 sets.
    assert_eq!(row(&p, "old").await, (None, at.clone(), None, Some("new".into())));
    assert_eq!(row(&p, "new").await, (at.clone(), None, Some("old".into()), None));
    assert!(!in_memory(&p, "old").await);
    assert!(in_memory(&p, "new").await);
    // History: still readable by id, with its successor named.
    let status: String = sqlx::query_scalar("SELECT status FROM records WHERE id = 'old'")
        .fetch_one(&p)
        .await
        .unwrap();
    assert_eq!(status, "accepted");

    let mut tx = p.begin().await.unwrap();
    undo(&mut tx, &change.unwrap(), "2026-11-13T10:00:00Z")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    let mut conn = p.acquire().await.unwrap();
    assert_eq!(image(&mut conn, "old").await.unwrap(), old_img);
    assert_eq!(image(&mut conn, "new").await.unwrap(), new_img);
    drop(conn);
    assert!(in_memory(&p, "old").await);
}

#[tokio::test]
async fn the_moment_never_precedes_the_old_record_began() {
    let (_d, p) = pool().await;
    record(&p, "old", "task", "2026-11-10T10:00:00Z").await;
    record(&p, "new", "task", NOW).await;
    source(&p, "s-early", "new", "2026-01-01T00:00:00Z").await;
    assert!(run(&p, "old", "new", false).await.0);
    let (_, to, _, _) = row(&p, "old").await;
    assert_eq!(to.as_deref(), Some("2026-11-10T10:00:00Z"));
}

#[tokio::test]
async fn without_a_cited_source_the_moment_is_now() {
    let (_d, p) = pool().await;
    record(&p, "old", "fact", T0).await;
    record(&p, "new", "fact", NOW).await;
    assert!(run(&p, "old", "new", false).await.0);
    assert_eq!(row(&p, "new").await.0.as_deref(), Some(NOW));
}

#[tokio::test]
async fn replacing_a_rule_or_preference_needs_a_user_grounded_candidate() {
    for kind in ["rule", "preference"] {
        let (_d, p) = pool().await;
        record(&p, "old", kind, T0).await;
        record(&p, "new", kind, NOW).await;
        let (done, change) = run(&p, "old", "new", false).await;
        assert!(!done, "{kind} must survive an ungrounded replaces");
        assert!(change.is_none(), "nothing written");
        assert!(in_memory(&p, "old").await);
        assert_eq!(row(&p, "old").await.1, None);
        assert!(run(&p, "old", "new", true).await.0);
        assert!(!in_memory(&p, "old").await);
    }
}

#[tokio::test]
async fn a_target_outside_memory_or_the_record_itself_is_ignored() {
    let (_d, p) = pool().await;
    record(&p, "a", "fact", T0).await;
    record(&p, "b", "fact", NOW).await;
    record(&p, "c", "fact", NOW).await;
    assert!(!run(&p, "a", "a", true).await.0);
    assert!(!run(&p, "nope", "b", true).await.0);
    // Already superseded: a second replace of the same target does nothing.
    assert!(run(&p, "a", "b", false).await.0);
    assert!(!run(&p, "a", "c", false).await.0);
    assert_eq!(row(&p, "a").await.3.as_deref(), Some("b"));
    // Archived targets are not in memory either.
    sqlx::query("UPDATE records SET archived_at = ? WHERE id = 'c'")
        .bind(NOW)
        .execute(&p)
        .await
        .unwrap();
    record(&p, "d", "fact", NOW).await;
    assert!(!run(&p, "c", "d", false).await.0);
}

#[tokio::test]
async fn the_sql_staleness_test_equals_the_pure_one() {
    let (_d, p) = pool().await;
    let cut = "2026-08-01T00:00:00Z";
    let mut n = 0;
    for kind in ["project-state", "task", "decision", "rule", "fact"] {
        for at in ["2026-07-01T00:00:00Z", "2026-09-01T00:00:00Z"] {
            n += 1;
            record(&p, &format!("r{n}"), kind, at).await;
            let sql: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT {STALE_SQL} FROM records WHERE id = ?"
            )))
            .bind(cut)
            .bind(format!("r{n}"))
            .fetch_one(&p)
            .await
            .unwrap();
            assert_eq!(sql != 0, is_stale(kind, at, cut), "{kind} {at}");
        }
    }
}
