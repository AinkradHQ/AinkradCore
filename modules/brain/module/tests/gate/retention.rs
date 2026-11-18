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
