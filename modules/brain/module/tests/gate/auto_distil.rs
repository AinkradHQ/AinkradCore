//! B5-01: automatic distillation. Time is the `now` the step is given (the fake clock); the Core's
//! event log is real. Every item here is synthetic.

use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::events;
use axum::http::{Method, StatusCode};
use serde_json::json;

use super::common::*;
use super::sync::{room_alpha, session};

const ALPHA: &str = "/h/Projects/Alpha/a";

/// A room whose sources are all read, with the event cursor started.
async fn quiet_room(fx: &Fx) -> (String, i64) {
    let room = room_alpha(fx).await;
    mark_read(fx, &room).await;
    let now = fx.app.clock.unix();
    // The first step only starts the cursor at the newest event.
    assert_eq!(fx.brain.auto_distil_step_at(now).await.unwrap(), 0);
    (room, now)
}

async fn mark_read(fx: &Fx, room: &str) {
    let p = canon_pool(fx, room).await;
    sqlx::query("UPDATE sources SET distilled = 'old' WHERE distilled IS NULL")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
}

async fn unread(fx: &Fx, room: &str, n: usize, started: &str) {
    let p = canon_pool(fx, room).await;
    for i in 0..n {
        sqlx::query(
            "INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, \
             title, text, started_at, run, assigned_by) VALUES (?, ?, 'note', 'd', '/p', 'user', 'a', 't', 'x', ?, 'r', 'rule')",
        )
        .bind(format!("u{i}-{started}"))
        .bind(format!("h{i}-{started}"))
        .bind(started)
        .execute(&p)
        .await
        .unwrap();
    }
    p.close().await;
}

async fn ended(fx: &Fx, id: &str) {
    let mut c = fx.app.pool.acquire().await.unwrap();
    events::append(&mut c, "agent.ended", &json!({"session": id, "state": "ended", "outcome": "completed"}))
        .await
        .unwrap();
}

async fn rows(fx: &Fx, filter: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM brain_distils WHERE {filter}"
    )))
    .fetch_one(&fx.app.pool)
    .await
    .unwrap()
}

async fn close_all(fx: &Fx, room: &str) {
    sqlx::query("UPDATE brain_distils SET state = 'done'").execute(&fx.app.pool).await.unwrap();
    let p = canon_pool(fx, room).await;
    sqlx::query("UPDATE sources SET distilled = NULL").execute(&p).await.unwrap();
    p.close().await;
}

#[tokio::test]
async fn a_session_end_queues_one_distil_after_the_idle_wait_and_never_twice() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    session(&fx, "as_one", Some(ALPHA), "ended", None, &[("user", "we ship Friday"), ("assistant", "ok")]).await;
    ended(&fx, "as_one").await;
    // Too young: nothing yet, and nothing is lost.
    assert_eq!(fx.brain.auto_distil_step_at(now + 5).await.unwrap(), 0);
    assert_eq!(rows(&fx, "1 = 1").await, 0);
    assert_eq!(fx.brain.auto_distil_step_at(now + 90).await.unwrap(), 1);
    let (r, t, s, st): (String, String, String, String) =
        sqlx::query_as("SELECT room, \"trigger\", of_session, state FROM brain_distils")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!((r, t, s, st), (room, "session_end".into(), "as_one".into(), "queued".into()));
    let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'brain.distil.queued'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(audited, 1);
    // The same end read again (a crash before the cursor moved) makes no second distil.
    sqlx::query("UPDATE brain_distils SET state = 'done'").execute(&fx.app.pool).await.unwrap();
    ended(&fx, "as_one").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 200).await.unwrap(), 0);
    assert_eq!(rows(&fx, "1 = 1").await, 1);
}

#[tokio::test]
async fn a_brain_owned_session_is_never_a_trigger() {
    let fx = fx().await;
    let (_, now) = quiet_room(&fx).await;
    session(&fx, "as_brain", Some(ALPHA), "ended", Some("brain"), &[("user", "x")]).await;
    ended(&fx, "as_brain").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 90).await.unwrap(), 0);
    assert_eq!(rows(&fx, "1 = 1").await, 0);
}

#[tokio::test]
async fn the_import_threshold_counts_sources_or_age() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let young = iso_of_unix(now - 60);
    unread(&fx, &room, 39, &young).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 0);
    unread(&fx, &room, 1, "2999-01-01T00:00:00Z").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 800).await.unwrap(), 1);
    assert_eq!(rows(&fx, "\"trigger\" = 'threshold' AND sources = 30").await, 1);
    // Few sources, but the oldest is a day old.
    close_all(&fx, &room).await;
    mark_read(&fx, &room).await;
    unread(&fx, &room, 1, &iso_of_unix(now - 86_400)).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 1200).await.unwrap(), 1);
}

#[tokio::test]
async fn the_daily_room_cap_stops_the_next_distil_and_the_next_day_resets_it() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let day = now - now.rem_euclid(86_400);
    sqlx::query("UPDATE brain_room_policy SET daily_distils = 2 WHERE room = ?")
        .bind(&room)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let old = iso_of_unix(day - 86_400);
    mark_read(&fx, &room).await;
    for k in 1..=3 {
        unread(&fx, &room, 1, &format!("{old}{k}")).await;
        let n = fx.brain.auto_distil_step_at(day + 86_400 + 10_000 + k * 400).await.unwrap();
        assert_eq!(n, u32::from(k <= 2), "round {k}");
        close_all(&fx, &room).await;
        mark_read(&fx, &room).await;
    }
    assert_eq!(rows(&fx, "state = 'failed'").await, 0);
    unread(&fx, &room, 1, &old).await;
    assert_eq!(fx.brain.auto_distil_step_at(day + 2 * 86_400 + 10_000).await.unwrap(), 1);
}

#[tokio::test]
async fn the_global_cap_bounds_all_rooms_together() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    sqlx::query("UPDATE brain_room_policy SET daily_distils = 1000 WHERE room = ?")
        .bind(&room)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let at = iso_of_unix(now);
    for i in 0..100 {
        sqlx::query("INSERT INTO brain_distils (id, room, state, requested_by, \"trigger\", created_at, updated_at) VALUES (?, ?, 'done', 'x', 'threshold', ?, ?)")
            .bind(format!("dst-f{i}"))
            .bind(&room)
            .bind(&at)
            .bind(&at)
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    unread(&fx, &room, 1, "2020-01-01T00:00:00Z").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 0);
    assert_eq!(rows(&fx, "state != 'done'").await, 0);
}

#[tokio::test]
async fn a_local_only_room_waits_for_a_local_model() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    sqlx::query("UPDATE brain_room_policy SET allowed_providers = '[\"local\"]' WHERE room = ?")
        .bind(&room)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    unread(&fx, &room, 1, "2020-01-01T00:00:00Z").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 1);
    assert_eq!(rows(&fx, "state = 'needs_local_model'").await, 1);
    // Open already: more triggers coalesce into it.
    assert_eq!(fx.brain.auto_distil_step_at(now + 800).await.unwrap(), 0);
}

#[tokio::test]
async fn no_ai_op_can_force_a_distil() {
    let fx = fx().await;
    let (st, _) = call(&fx, &fx.admin, Method::POST, "/ai/rooms/any/distil", None).await;
    assert!(matches!(st, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED), "{st}");
}
