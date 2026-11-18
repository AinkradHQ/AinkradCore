//! B6-02: retention. Every source and record here is made up.

use axum::http::{Method, StatusCode};
use serde_json::json;
use sqlx::SqlitePool;

use super::common::*;

const OLD: &str = "2020-01-01T00:00:00.000Z";

/// A room with sources A..G (see `setup`), opened, and its file.
async fn setup(fx: &Fx) -> (String, SqlitePool) {
    let room = committed_room(
        fx,
        &[("A", "alpha text"), ("B", "bravo text"), ("C", "charlie text"), ("D", "delta text"),
          ("E", "echo text"), ("F", "foxtrot text"), ("G", "golf text")],
    )
    .await;
    ok(fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let pool = canon_pool(fx, &room).await;
    sqlx::query("UPDATE sources SET started_at = ?, distilled = 'run_done'").bind(OLD).execute(&pool).await.unwrap();
    // Imported long ago too (the age counts from the later of the two).
    sqlx::query("UPDATE op_log SET at = ?").bind(OLD).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO brain_distils (id, room, state, requested_by) VALUES ('run_done', ?, 'done', 'test')")
        .bind(&room).execute(&fx.app.pool).await.unwrap();
    // B waits for a re-distil, E was never distilled, F is recent, G belongs to a run still open.
    sqlx::query("UPDATE sources SET redistil = 'purge1' WHERE title = 'B'").execute(&pool).await.unwrap();
    sqlx::query("UPDATE sources SET distilled = NULL WHERE title = 'E'").execute(&pool).await.unwrap();
    sqlx::query("UPDATE sources SET started_at = ? WHERE title = 'F'").bind(fx.app.clock.now()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE sources SET distilled = 'run_open' WHERE title = 'G'").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO brain_distils (id, room, state, requested_by) VALUES ('run_open', ?, 'running', 'test')")
        .bind(&room).execute(&fx.app.pool).await.unwrap();
    // C is cited by a candidate; D only by a record archived yesterday.
    for (rec, status, title, archived) in [("rc", "candidate", "C", None), ("rd", "accepted", "D", Some(fx.app.clock.now()))] {
        let src: String = sqlx::query_scalar("SELECT item_id FROM sources WHERE title = ?").bind(title).fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO records (id, type, status, body, tags, source_ids, created_at, archived_at) VALUES (?, 'fact', ?, 'x', '[]', '[]', ?, ?)")
            .bind(rec).bind(status).bind(OLD).bind(archived).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO record_sources (record, source, position) VALUES (?, ?, 0)").bind(rec).bind(src).execute(&pool).await.unwrap();
    }
    (room, pool)
}

async fn compacted(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT title FROM sources WHERE compacted_at IS NOT NULL ORDER BY title").fetch_all(pool).await.unwrap()
}

async fn set_days(fx: &Fx, room: &str, days: u32) {
    ok(fx, Method::PATCH, &format!("/rooms/{room}/policy"), Some(json!({"retention_days": days}))).await;
}

#[tokio::test]
async fn the_default_keeps_everything() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    let v = ok(&fx, Method::GET, &format!("/rooms/{room}/policy"), None).await;
    assert!(v["retention_days"].is_null());
    assert_eq!(fx.brain.retention_step().await.unwrap(), 0);
    assert!(compacted(&pool).await.is_empty());
    pool.close().await;
}

#[tokio::test]
async fn turning_it_on_needs_a_step_up_and_bad_values_are_refused() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    let path = format!("/rooms/{room}/policy");
    let (s, v) = call(&fx, &fx.laptop, Method::PATCH, &path, Some(json!({"retention_days": 30}))).await;
    assert_eq!((s, &v["code"]), (StatusCode::FORBIDDEN, &json!("step_up_required")));
    let (s, _) = call(&fx, &fx.admin, Method::PATCH, &path, Some(json!({"retention_days": 99999}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let kept: Option<i64> = sqlx::query_scalar("SELECT retention_days FROM brain_room_policy WHERE room = ?").bind(&room).fetch_one(&fx.app.pool).await.unwrap();
    assert_eq!(kept, None);
    set_days(&fx, &room, 30).await;
    let v = ok(&fx, Method::GET, &path, None).await;
    assert_eq!(v["retention_days"], json!(30));
    set_days(&fx, &room, 0).await;
    assert!(ok(&fx, Method::GET, &path, None).await["retention_days"].is_null());
    pool.close().await;
}

#[tokio::test]
async fn the_dry_run_reports_counts_and_writes_nothing() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    let v = ok(&fx, Method::GET, &format!("/rooms/{room}/retention?days=30"), None).await;
    assert_eq!(v["would_compact"], json!(1)); // only A
    assert_eq!(v["chars"], json!("alpha text".len()));
    assert_eq!(ok(&fx, Method::GET, &format!("/rooms/{room}/retention?days=36500"), None).await["would_compact"], json!(0));
    let (s, _) = call(&fx, &fx.admin, Method::GET, &format!("/rooms/{room}/retention"), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST); // off and no days
    assert!(compacted(&pool).await.is_empty());
    pool.close().await;
}

#[tokio::test]
async fn the_job_compacts_only_what_is_safe_and_is_idempotent_and_audited() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    set_days(&fx, &room, 30).await;
    assert_eq!(fx.brain.retention_step().await.unwrap(), 1);
    // Not B (re-distil), C (candidate), D (undo window), E (undistilled), F (recent), G (open run).
    assert_eq!(compacted(&pool).await, ["A"]);
    let (text, hash): (String, String) = sqlx::query_as("SELECT text, content_hash FROM sources WHERE title = 'A'").fetch_one(&pool).await.unwrap();
    assert_eq!(text, "");
    let kept: String = sqlx::query_scalar("SELECT text FROM sources WHERE title = 'B'").fetch_one(&pool).await.unwrap();
    assert_eq!(kept, "bravo text");
    // The hash stays known, so a re-import is skipped.
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_seen WHERE content_hash = ?").bind(&hash).fetch_one(&fx.app.pool).await.unwrap();
    assert_eq!(seen, 1);
    // Audited in the room and on the Core.
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM room_audit WHERE action = 'retention.compacted'").fetch_one(&pool).await.unwrap();
    assert_eq!(audit, 1);
    // Searching no longer finds the dropped text.
    let hits = ok(&fx, Method::GET, &format!("/rooms/{room}/search?q=alpha"), None).await;
    assert!(!hits.to_string().contains("alpha"), "{hits}");
    // A second run changes nothing; once D leaves the undo window and B is re-read, they go.
    assert_eq!(fx.brain.retention_step().await.unwrap(), 0);
    assert_eq!(compacted(&pool).await, ["A"]);
    sqlx::query("UPDATE records SET archived_at = ? WHERE id = 'rd'").bind(OLD).execute(&pool).await.unwrap();
    sqlx::query("UPDATE sources SET redistil = NULL").execute(&pool).await.unwrap();
    assert_eq!(fx.brain.retention_step().await.unwrap(), 2);
    assert_eq!(compacted(&pool).await, ["A", "B", "D"]);
    pool.close().await;
}

async fn id_of(pool: &SqlitePool, title: &str) -> String {
    sqlx::query_scalar("SELECT item_id FROM sources WHERE title = ?").bind(title).fetch_one(pool).await.unwrap()
}

#[tokio::test]
async fn a_failed_run_does_not_count_as_distilled() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    sqlx::query("UPDATE brain_distils SET state = 'failed' WHERE id = 'run_done'").execute(&fx.app.pool).await.unwrap();
    set_days(&fx, &room, 30).await;
    assert_eq!(fx.brain.retention_step().await.unwrap(), 0);
    assert!(compacted(&pool).await.is_empty());
    pool.close().await;
}

#[tokio::test]
async fn a_source_that_changed_or_was_cited_since_the_read_is_not_wiped() {
    let fx = fx().await;
    let (_room, pool) = setup(&fx).await;
    let w = brain_module::retention::Window::new(fx.app.clock.unix(), 30, "[\"run_done\"]");
    let found = brain_module::retention::eligible(&pool, &w, -1).await.unwrap();
    assert_eq!(found.len(), 1);
    // Between the read and the write: a re-import changed A, and a candidate now cites it.
    let a = id_of(&pool, "A").await;
    sqlx::query("UPDATE sources SET content_hash = 'new-hash', text = 'alpha v2' WHERE item_id = ?").bind(&a).execute(&pool).await.unwrap();
    let done = brain_module::retention::compact(&pool, &w, &fx.app.clock.now(), &found).await.unwrap();
    assert!(done.ids.is_empty());
    sqlx::query("UPDATE sources SET content_hash = ? WHERE item_id = ?").bind(&found[0].content_hash).bind(&a).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO records (id, type, status, body, tags, source_ids, created_at) VALUES ('rn', 'fact', 'candidate', 'x', '[]', ?, ?)")
        .bind(json!([a]).to_string()).bind(OLD).execute(&pool).await.unwrap();
    let done = brain_module::retention::compact(&pool, &w, &fx.app.clock.now(), &found).await.unwrap();
    assert!(done.ids.is_empty());
    assert!(compacted(&pool).await.is_empty());
    pool.close().await;
}

#[tokio::test]
async fn age_counts_from_the_import_and_one_run_compacts_at_most_500_per_room() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    set_days(&fx, &room, 30).await;
    // A was imported just now (an old chat export): it stays.
    let a = id_of(&pool, "A").await;
    sqlx::query("UPDATE op_log SET at = ? WHERE ref = ?").bind(fx.app.clock.now()).bind(&a).execute(&pool).await.unwrap();
    assert_eq!(fx.brain.retention_step().await.unwrap(), 0);
    assert!(compacted(&pool).await.is_empty());
    // 600 old, distilled sources: 500 go in the first run, the rest in the next.
    sqlx::query(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 600) \
         INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, title, text, started_at, run, assigned_by, distilled) \
         SELECT 'bulk' || i, 'bulkhash' || i, 'note', 'd', '/p', 'user', 'u', 'bulk', 'text', ?, 'r', 'rule', 'run_done' FROM n",
    )
    .bind(OLD).execute(&pool).await.unwrap();
    assert_eq!(fx.brain.retention_step().await.unwrap(), 500);
    assert_eq!(fx.brain.retention_step().await.unwrap(), 100);
    pool.close().await;
}

#[tokio::test]
async fn a_source_of_a_recent_unundone_change_stays_until_undone() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    set_days(&fx, &room, 30).await;
    let a = id_of(&pool, "A").await;
    sqlx::query("INSERT INTO changes (id, kind, summary, at) VALUES ('ch1', 'merge', 's', ?)").bind(fx.app.clock.now()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO change_rows (change, seq, record, before) VALUES ('ch1', 0, 'gone', ?)")
        .bind(json!({"id": "gone", "_sources": [[a, 0]]}).to_string()).execute(&pool).await.unwrap();
    assert_eq!(fx.brain.retention_step().await.unwrap(), 0);
    sqlx::query("UPDATE changes SET undone_at = ?").bind(fx.app.clock.now()).execute(&pool).await.unwrap();
    assert_eq!(fx.brain.retention_step().await.unwrap(), 1);
    pool.close().await;
}

#[tokio::test]
async fn vectors_of_every_compacted_source_are_swept_and_a_bad_room_does_not_stop_the_job() {
    let fx = fx().await;
    let (room, pool) = setup(&fx).await;
    // A second room whose file is unreadable must not stop the first.
    let bad = committed_room_named(&fx, "Beta", &[("Z", "zulu text")]).await;
    ok(&fx, Method::POST, &format!("/rooms/{bad}/open"), None).await;
    let bad_pool = canon_pool(&fx, &bad).await;
    sqlx::query("DROP TABLE sources").execute(&bad_pool).await.unwrap();
    bad_pool.close().await;
    set_days(&fx, &bad, 30).await;
    set_days(&fx, &room, 30).await;
    assert_eq!(fx.brain.retention_step().await.unwrap(), 1);
    // A earlier run left a compacted source's vector behind: the next run drops it.
    let (hash,): (String,) = sqlx::query_as("SELECT content_hash FROM sources WHERE title = 'A'").fetch_one(&pool).await.unwrap();
    let key = key_of(&fx).await;
    let v = brain_module::files::open_migrated(&brain_module::files::vectors_path(&brain_module::files::root(&fx.app)), &key, true, brain_module::files::VECTORS).await.unwrap();
    sqlx::query("INSERT INTO vectors (model, content_hash, vec) VALUES ('m', ?, x'00')").bind(&hash).execute(&v).await.unwrap();
    assert_eq!(fx.brain.retention_step().await.unwrap(), 0);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM vectors WHERE content_hash = ?").bind(&hash).fetch_one(&v).await.unwrap();
    assert_eq!(left, 0);
    v.close().await;
    pool.close().await;
}
