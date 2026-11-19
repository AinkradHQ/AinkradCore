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
    events::append(
        &mut c,
        "agent.ended",
        &json!({"session": id, "state": "ended", "outcome": "completed"}),
    )
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
    sqlx::query("UPDATE brain_distils SET state = 'done'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let p = canon_pool(fx, room).await;
    sqlx::query("UPDATE sources SET distilled = NULL")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
}

#[tokio::test]
async fn a_session_end_queues_one_distil_after_the_idle_wait_and_never_twice() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    session(
        &fx,
        "as_one",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "we ship Friday"), ("assistant", "ok")],
    )
    .await;
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
    assert_eq!(
        (r, t, s, st),
        (room, "session_end".into(), "as_one".into(), "queued".into())
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'brain.distil.queued'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
    // The same end read again (a crash before the cursor moved) makes no second distil.
    sqlx::query("UPDATE brain_distils SET state = 'done'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    ended(&fx, "as_one").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 200).await.unwrap(), 0);
    assert_eq!(rows(&fx, "1 = 1").await, 1);
}

#[tokio::test]
async fn a_brain_owned_session_is_never_a_trigger() {
    let fx = fx().await;
    let (_, now) = quiet_room(&fx).await;
    session(
        &fx,
        "as_brain",
        Some(ALPHA),
        "ended",
        Some("brain"),
        &[("user", "x")],
    )
    .await;
    ended(&fx, "as_brain").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 90).await.unwrap(), 0);
    assert_eq!(rows(&fx, "1 = 1").await, 0);
}

#[tokio::test]
async fn the_dreaming_sweep_distils_any_unread_source_batch_after_batch() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    // Nothing unread, nothing queued.
    assert_eq!(fx.brain.auto_distil_step_at(now + 100).await.unwrap(), 0);
    // One young source is enough (E9-1: no count or age threshold any more).
    unread(&fx, &room, 1, &iso_of_unix(now - 60)).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 200).await.unwrap(), 1);
    // An import of 70 sources goes 30 at a time: the next batch is queued a minute after the last.
    close_all(&fx, &room).await;
    mark_read(&fx, &room).await;
    unread(&fx, &room, 70, &iso_of_unix(now - 60)).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 300).await.unwrap(), 1);
    assert_eq!(
        rows(&fx, "\"trigger\" = 'threshold' AND sources = 30").await,
        1
    );
    close_all(&fx, &room).await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 1);
}

#[tokio::test]
async fn the_dreaming_sweep_is_never_stopped_by_the_room_or_global_cap() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    sqlx::query("UPDATE brain_room_policy SET daily_distils = 1 WHERE room = ?")
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
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 1);
    assert_eq!(rows(&fx, "state = 'queued'").await, 1);
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
    assert!(
        matches!(st, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED),
        "{st}"
    );
}

async fn put(
    fx: &Fx,
    id: &str,
    room: &str,
    state: &str,
    by: &str,
    at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO brain_distils (id, room, state, requested_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(room)
        .bind(state)
        .bind(by)
        .bind(at)
        .bind(at)
        .execute(&fx.app.pool)
        .await
        .map(drop)
}

async fn cursor(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT seq FROM brain_session_cursor")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn newest_event(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT max(seq) FROM events")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_database_allows_one_open_distil_per_room_and_a_manual_start_gets_the_open_answer() {
    let fx = fx().await;
    let (room, _) = quiet_room(&fx).await;
    let at = "2020-01-01T00:00:00Z";
    put(&fx, "dst-a", &room, "done", "x", at).await.unwrap();
    put(&fx, "dst-b", &room, "failed", "x", at).await.unwrap();
    put(&fx, "dst-c", &room, "queued", "x", at).await.unwrap();
    let dup = put(&fx, "dst-d", &room, "running", "x", at)
        .await
        .unwrap_err();
    assert!(
        dup.as_database_error()
            .is_some_and(|d| d.is_unique_violation()),
        "{dup}"
    );
    // The manual start finds the open one (by the check, or by the index when it lost a race).
    unread(&fx, &room, 1, at).await;
    let (st, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/distil"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "distil_open", "{v}");
}

#[tokio::test]
async fn a_failing_sync_stops_the_tick_sets_nothing_aside_and_never_holds_a_stale_end() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let before = cursor(&fx).await;
    for i in 0..5 {
        let id = format!("as_bad{i}");
        session(
            &fx,
            &id,
            Some(ALPHA),
            "ended",
            None,
            &[("user", "x"), ("assistant", "y")],
        )
        .await;
        ended(&fx, &id).await;
    }
    unread(&fx, &room, 40, &iso_of_unix(now - 60)).await;
    sqlx::query("ALTER TABLE brain_sources RENAME TO brain_sources_away")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    // The first end fails the sync and the tick stops there: none of the five is set aside.
    let n = fx.brain.auto_distil_step_at(now + 400).await;
    assert_eq!(cursor(&fx).await, before);
    // The threshold scan still ran.
    assert_eq!(n.unwrap(), 1, "the threshold queued its distil");
    assert_eq!(rows(&fx, "\"trigger\" = 'threshold'").await, 1);
    // Days later the ends are stale: they skip the sync and the cursor moves past them.
    fx.brain
        .auto_distil_step_at(now + 3 * 86_400)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE brain_sources_away RENAME TO brain_sources")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(cursor(&fx).await, newest_event(&fx).await);
}

#[tokio::test]
async fn the_cursor_waits_for_a_session_the_sync_has_not_taken_yet() {
    let fx = fx().await;
    let (_, now) = quiet_room(&fx).await;
    let before = cursor(&fx).await;
    // 201 sessions: one sync takes the newest 200, so the oldest end must wait.
    for i in 0..201 {
        session(
            &fx,
            &format!("as_{i:03}"),
            None,
            "ended",
            None,
            &[("user", "we ship Friday"), ("assistant", "ok")],
        )
        .await;
    }
    ended(&fx, "as_000").await;
    let last = newest_event(&fx).await;
    fx.brain.auto_distil_step_at(now + 90).await.unwrap();
    assert_eq!(
        cursor(&fx).await,
        before,
        "not moved past an event that never reached the queue"
    );
    // The cursor goes to the newest event there is when the step looks, no further (the events the
    // step writes itself come after it).
    let seen = newest_event(&fx).await;
    assert!(seen >= last);
    fx.brain.auto_distil_step_at(now + 200).await.unwrap();
    assert_eq!(
        cursor(&fx).await,
        seen,
        "moved once its session was collected"
    );
}

#[tokio::test]
async fn a_session_end_in_another_room_does_not_hide_this_rooms_end() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    sqlx::query("INSERT INTO brain_rooms (id, name, kind) VALUES ('rm-other', 'Other', 'general')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    put(
        &fx,
        "dst-o",
        "rm-other",
        "done",
        "x",
        "2020-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    sqlx::query("UPDATE brain_distils SET \"trigger\" = 'session_end', of_session = 'as_one' WHERE id = 'dst-o'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    session(
        &fx,
        "as_one",
        Some(ALPHA),
        "ended",
        None,
        &[("user", "we ship Friday"), ("assistant", "ok")],
    )
    .await;
    ended(&fx, "as_one").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 90).await.unwrap(), 1);
    assert_eq!(
        rows(
            &fx,
            &format!("room = '{room}' AND \"trigger\" = 'session_end'")
        )
        .await,
        1
    );
}

#[tokio::test]
async fn the_distil_runs_as_the_most_recent_manual_requester_with_a_write_scope() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    let readonly = enroll(&fx.app, "reader", &["read"]).await;
    // The read-only device asked last, but cannot be the requester; the admin asked after the laptop.
    put(
        &fx,
        "dst-1",
        &room,
        "done",
        &fx.laptop.id,
        "2020-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    put(
        &fx,
        "dst-2",
        &room,
        "done",
        &fx.admin.id,
        "2020-02-01T00:00:00Z",
    )
    .await
    .unwrap();
    put(
        &fx,
        "dst-3",
        &room,
        "done",
        &readonly.id,
        "2020-03-01T00:00:00Z",
    )
    .await
    .unwrap();
    unread(&fx, &room, 1, "2020-01-01T00:00:00Z").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 1);
    let by: String = sqlx::query_scalar(
        "SELECT requested_by FROM brain_distils WHERE \"trigger\" = 'threshold'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(by, fx.admin.id);
}

#[tokio::test]
async fn a_room_whose_distil_failed_is_skipped_for_six_hours() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    put(&fx, "dst-f", &room, "failed", "x", &iso_of_unix(now - 3600))
        .await
        .unwrap();
    unread(&fx, &room, 1, "2020-01-01T00:00:00Z").await;
    assert_eq!(fx.brain.auto_distil_step_at(now + 400).await.unwrap(), 0);
    assert_eq!(
        fx.brain
            .auto_distil_step_at(now + 6 * 3600 + 400)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn a_capped_room_is_audited_once_a_day() {
    let fx = fx().await;
    let (room, now) = quiet_room(&fx).await;
    sqlx::query("UPDATE brain_room_policy SET daily_distils = 0 WHERE room = ?")
        .bind(&room)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    for id in ["as_one", "as_two"] {
        session(
            &fx,
            id,
            Some(ALPHA),
            "ended",
            None,
            &[("user", "we ship Friday"), ("assistant", "ok")],
        )
        .await;
        ended(&fx, id).await;
    }
    assert_eq!(fx.brain.auto_distil_step_at(now + 90).await.unwrap(), 0);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'brain.distil.capped'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}
