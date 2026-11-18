//! B2-01: Brain schema v2 — room-file migrations (`canon_0006`, `index_0002`) and control `0009`.

use std::sync::Arc;

use axum::http::Method;
use brain_module::files::{self, CANON, INDEX};
use serde_json::json;
use sqlx::SqlitePool;

use super::common::*;

const KEY: [u8; 32] = [7; 32];

fn path(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(name);
    (dir, p)
}

/// Sources `s1` (older) and `s2` (newer), and records covering every backfill branch, written
/// the way canon level 5 wrote them.
async fn seed_level_5(pool: &SqlitePool) {
    for (id, at) in [("s1", "2026-01-01T00:00:00Z"), ("s2", "2026-03-01T00:00:00Z")] {
        sqlx::query(
            "INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, \
             title, text, started_at, run, assigned_by) VALUES (?, ?, 'note', 'd', '/p', 'user', 'a', 't', 'x', ?, 'r', 'rule')",
        )
        .bind(id)
        .bind(format!("h-{id}"))
        .bind(at)
        .execute(pool)
        .await
        .unwrap();
    }
    // (id, status, body, source_ids, decided_by, distil)
    let rows: [(&str, &str, &str, &str, Option<&str>, Option<&str>); 6] = [
        ("r-auto", "accepted", "  Deploy\ton   FRIDAYS \n", r#"["s1","s2"]"#, Some("auto"), Some("dst-1")),
        ("r-person", "accepted", "We use Rust", r#"["s2"]"#, Some("dev-9"), Some("dst-1")),
        ("r-ai", "candidate", "AI proposed", "[]", None, Some("ai:as_1")),
        ("r-bad", "accepted", "bad json", "not json", Some("auto"), None),
        ("r-dangling", "rejected", "cites nothing real", r#"["gone"]"#, None, None),
        ("r-dup", "accepted", "dup cite", r#"["s1","s1"]"#, Some("auto"), None),
    ];
    for (id, status, body, ids, by, distil) in rows {
        sqlx::query(
            "INSERT INTO records (id, type, status, body, source_ids, created_at, decided_by, distil) \
             VALUES (?, 'fact', ?, ?, ?, '2026-04-01T00:00:00Z', ?, ?)",
        )
        .bind(id)
        .bind(status)
        .bind(body)
        .bind(ids)
        .bind(by)
        .bind(distil)
        .execute(pool)
        .await
        .unwrap();
    }
}

async fn snapshot(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT id || '|' || coalesce(body_norm,'~') || '|' || coalesce(valid_from,'~') || '|' || coalesce(last_seen_at,'~') \
         || '|' || origin || '|' || edited_by_person || '|' || support || '|' || \
         coalesce((SELECT group_concat(source || ':' || position) FROM record_sources WHERE record = records.id), '') \
         FROM records ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_room_file_from_every_canon_level_opens_at_the_newest() {
    for level in 1..=CANON.len() {
        let (_d, p) = path("canon.db");
        let old = files::open_migrated(&p, &KEY, true, &CANON[..level]).await.unwrap();
        old.close().await;
        let pool = files::open_migrated(&p, &KEY, false, CANON).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM _file_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n as usize, CANON.len(), "from level {level}");
        let m: i64 = sqlx::query_scalar("SELECT count(*) FROM memory")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(m, 0);
        pool.close().await;
    }
}

#[tokio::test]
async fn the_backfill_fills_the_new_columns_from_what_level_5_recorded() {
    let (_d, p) = path("canon.db");
    let old = files::open_migrated(&p, &KEY, true, &CANON[..5]).await.unwrap();
    seed_level_5(&old).await;
    old.close().await;
    let pool = files::open_migrated(&p, &KEY, false, CANON).await.unwrap();
    let snap = snapshot(&pool).await;
    assert_eq!(
        snap,
        vec![
            "r-ai|ai proposed|2026-04-01T00:00:00Z|~|ai|0|1|",
            "r-auto|deploy on fridays|2026-01-01T00:00:00Z|2026-03-01T00:00:00Z|distil|0|1|s1:0,s2:1",
            "r-bad|bad json|2026-04-01T00:00:00Z|~|distil|0|1|",
            "r-dangling|cites nothing real|2026-04-01T00:00:00Z|~|distil|0|1|gone:0",
            "r-dup|dup cite|2026-01-01T00:00:00Z|2026-01-01T00:00:00Z|distil|0|1|s1:0",
            "r-person|we use rust|2026-03-01T00:00:00Z|2026-03-01T00:00:00Z|person|1|1|s2:0",
        ]
    );
    // `source_ids` is untouched for old readers.
    let ids: String = sqlx::query_scalar("SELECT source_ids FROM records WHERE id = 'r-auto'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(ids, r#"["s1","s2"]"#);
    // The `memory` view: accepted, current, not archived.
    sqlx::query("UPDATE records SET valid_to = '2026-05-01' WHERE id = 'r-bad'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET archived_at = '2026-05-01' WHERE id = 'r-dup'")
        .execute(&pool)
        .await
        .unwrap();
    let mem: Vec<String> = sqlx::query_scalar("SELECT id FROM memory ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(mem, ["r-auto", "r-person"]);
    pool.close().await;
}

#[tokio::test]
async fn the_backfill_is_idempotent_and_reopening_changes_nothing() {
    let (_d, p) = path("canon.db");
    let old = files::open_migrated(&p, &KEY, true, &CANON[..5]).await.unwrap();
    seed_level_5(&old).await;
    old.close().await;
    let pool = files::open_migrated(&p, &KEY, false, CANON).await.unwrap();
    let first = snapshot(&pool).await;
    // Run the backfill statements again (everything after the marker; the DDL above it is not repeatable).
    let backfill = CANON[5].up.split("-- Backfill.").nth(1).unwrap();
    sqlx::raw_sql(&format!("--{backfill}")).execute(&pool).await.unwrap();
    assert_eq!(snapshot(&pool).await, first);
    pool.close().await;
    let pool = files::open_migrated(&p, &KEY, false, CANON).await.unwrap();
    assert_eq!(snapshot(&pool).await, first);
    pool.close().await;
}

#[tokio::test]
async fn new_records_get_the_v2_defaults_and_the_change_tables_work() {
    let (_d, p) = path("canon.db");
    let pool = files::open_migrated(&p, &KEY, true, CANON).await.unwrap();
    sqlx::query("INSERT INTO records (id, type, body, created_at) VALUES ('r', 'fact', 'b', 'now')")
        .execute(&pool)
        .await
        .unwrap();
    let (support, origin, edited, status): (i64, String, i64, String) =
        sqlx::query_as("SELECT support, origin, edited_by_person, status FROM records")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((support, origin.as_str(), edited, status.as_str()), (1, "distil", 0, "candidate"));
    sqlx::query("INSERT INTO changes (id, kind, summary, at) VALUES ('c1', 'distil', 'Saved 1', 'now')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO change_rows (change, seq, record, after) VALUES ('c1', 0, 'r', '{}')")
        .execute(&pool)
        .await
        .unwrap();
    // A second row of the same change and seq is refused; a duplicate citation is refused.
    assert!(
        sqlx::query("INSERT INTO change_rows (change, seq, record) VALUES ('c1', 0, 'x')")
            .execute(&pool)
            .await
            .is_err()
    );
    sqlx::query("INSERT INTO record_sources VALUES ('r', 's', 0)").execute(&pool).await.unwrap();
    assert!(sqlx::query("INSERT INTO record_sources VALUES ('r', 's', 1)").execute(&pool).await.is_err());
    sqlx::query("UPDATE sources SET compacted_at = NULL, redistil = NULL").execute(&pool).await.unwrap();
    pool.close().await;
}

#[tokio::test]
async fn a_room_index_from_level_1_opens_and_holds_the_memory_search() {
    let (_d, p) = path("index.db");
    let old = files::open_migrated(&p, &KEY, true, &INDEX[..1]).await.unwrap();
    old.close().await;
    let pool = files::open_migrated(&p, &KEY, false, INDEX).await.unwrap();
    sqlx::query("INSERT INTO rec_fts (record, type, body, tags) VALUES ('r', 'fact', 'Deploy on Fridays', 'ops')")
        .execute(&pool)
        .await
        .unwrap();
    let hit: Vec<String> =
        sqlx::query_scalar("SELECT record FROM rec_fts WHERE rec_fts MATCH '\"deploy\"'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(hit, ["r"]);
    pool.close().await;
}

fn has(cols: &[String], c: &str) -> bool {
    cols.iter().any(|x| x == c)
}

async fn columns(fx: &Fx, table: &str) -> Vec<String> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT name FROM pragma_table_info('{table}')"
    )))
    .fetch_all(&fx.app.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn control_0009_goes_down_and_up_and_switches_old_rooms_to_auto_save() {
    use ainkrad_core_server::module::Module;
    use ainkrad_core_server::store::migrate;
    let fx = fx().await;
    let (d, pol) = (columns(&fx, "brain_distils").await, columns(&fx, "brain_room_policy").await);
    assert!(has(&d, "trigger") && has(&d, "of_session"));
    assert!(has(&pol, "retention_days") && has(&pol, "daily_distils"));

    migrate::undo(&fx.app.pool, "brain", brain_module::MIGRATIONS, 8).await.unwrap();
    let (d, pol) = (columns(&fx, "brain_distils").await, columns(&fx, "brain_room_policy").await);
    assert!(!has(&d, "trigger") && !has(&d, "of_session"));
    assert!(!has(&pol, "retention_days") && !has(&pol, "daily_distils"));

    // Two rooms as level 8 wrote them: one with the old `[]`, one that chose `["task"]`.
    for (room, kinds) in [("old-empty", "[]"), ("old-task", r#"["task"]"#)] {
        sqlx::query("INSERT INTO brain_rooms (id, name, kind) VALUES (?, ?, 'general')")
            .bind(room)
            .bind(room)
            .execute(&fx.app.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO brain_room_policy (room, auto_accept) VALUES (?, ?)")
            .bind(room)
            .bind(kinds)
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO brain_distils (id, room, state, requested_by) VALUES ('d1', 'old-task', 'done', 'me')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(fx.brain.clone())];
    migrate::migrate_modules(&fx.app.pool, &modules).await.unwrap();

    let rows: Vec<(String, String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT room, auto_accept, retention_days, daily_distils FROM brain_room_policy \
         WHERE room LIKE 'old-%' ORDER BY room",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    let all = r#"["decision","fact","preference","project-state","rule","summary","task"]"#;
    assert_eq!(
        rows,
        vec![
            ("old-empty".to_owned(), all.to_owned(), None, 12),
            ("old-task".to_owned(), r#"["task"]"#.to_owned(), None, 12),
        ]
    );
    let trig: String = sqlx::query_scalar(r#"SELECT "trigger" FROM brain_distils WHERE id = 'd1'"#)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(trig, "manual");
    // The new control tables take ids only and enforce their keys.
    sqlx::query("INSERT INTO brain_session_loaded VALUES ('s', 'old-task', 'rec-1')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("INSERT INTO brain_session_loaded VALUES ('s', 'old-task', 'rec-1')")
            .execute(&fx.app.pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("INSERT INTO brain_session_cursor VALUES (2, 0)").execute(&fx.app.pool).await.is_err()
    );
}

#[tokio::test]
async fn a_room_made_by_a_commit_auto_saves_every_kind_until_set_back_to_review() {
    let fx = fx().await;
    let run = start(&fx).await;
    send(&fx, &run, vec![item(1, "/h/Projects/Alpha/a", "a", "alpha text")]).await;
    finish(&fx, &run).await;
    let id = proposals(&fx, &run).await[0]["id"].as_str().unwrap().to_owned();
    ok(&fx, Method::PATCH, &format!("/imports/{run}/proposals/{id}"), Some(json!({"state": "accepted"}))).await;
    let room = ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
        .as_str()
        .unwrap()
        .to_owned();
    let pol = ok(&fx, Method::GET, &format!("/rooms/{room}/policy"), None).await;
    assert_eq!(
        pol["auto_accept"],
        json!(["decision", "fact", "preference", "project-state", "rule", "summary", "task"])
    );
    let back = ok(&fx, Method::PATCH, &format!("/rooms/{room}/policy"), Some(json!({"auto_accept": []}))).await;
    assert_eq!(back["auto_accept"], json!([]));
}
