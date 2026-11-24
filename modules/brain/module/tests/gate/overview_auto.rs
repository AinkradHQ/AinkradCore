//! Automatic room Overviews: the sweep queues a first one and a refresh through the manual path.
//! Time is the `now` the sweep is given. Every record here is made up.

use axum::http::Method;
use serde_json::{Value, json};

use super::common::*;

const DOCS: &[(&str, &str)] = &[(
    "Billing",
    "we export invoices as CSV\nAlways run the linter.",
)];

async fn records(fx: &Fx, room: &str, n: usize, at: &str) {
    let p = canon_pool(fx, room).await;
    for _ in 0..n {
        let k: i64 = sqlx::query_scalar("SELECT count(*) FROM records")
            .fetch_one(&p)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO records (id, type, status, body, tags, source_ids, created_at) \
             VALUES (?, 'fact', 'accepted', 'x', '[]', '[]', ?)",
        )
        .bind(format!("auto-{k}-{at}"))
        .bind(at)
        .execute(&p)
        .await
        .unwrap();
    }
    p.close().await;
}

async fn queued(fx: &Fx, room: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM brain_overview_queue WHERE room = ?")
        .bind(room)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn card(fx: &Fx, room: &str) -> Value {
    ok(fx, Method::GET, &format!("/rooms/{room}/overview"), None).await
}

/// The room's overview as written `at`, queue cleared.
async fn written(fx: &Fx, room: &str, at: &str, state: &str) {
    let p = canon_pool(fx, room).await;
    sqlx::query("INSERT OR IGNORE INTO room_overview (id, updated_at) VALUES (1, ?)")
        .bind(at)
        .execute(&p)
        .await
        .unwrap();
    sqlx::query("UPDATE room_overview SET state = ?, overview = '{}', written_at = ?, updated_at = ? WHERE id = 1")
        .bind(state)
        .bind(at)
        .bind(at)
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    sqlx::query("DELETE FROM brain_overview_queue")
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_room_with_records_gets_its_first_overview_once() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    let now = fx.app.clock.unix() + 1000;
    assert_eq!(
        fx.brain.overview_sweep_at(now).await.unwrap(),
        0,
        "no records"
    );
    records(&fx, &room, 3, "2026-11-01T00:00:00Z").await;
    assert_eq!(fx.brain.overview_sweep_at(now + 100).await.unwrap(), 1);
    assert_eq!(queued(&fx, &room).await, 1);
    let v = card(&fx, &room).await;
    assert_eq!(v["card_pending"], true, "{v}");
    assert!(v["card_at"].is_null());
    // Open: not queued again, whatever the time.
    assert_eq!(fx.brain.overview_sweep_at(now + 9000).await.unwrap(), 0);
    assert_eq!(queued(&fx, &room).await, 1);
}

#[tokio::test]
async fn a_local_only_room_is_never_queued() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    ok(
        &fx,
        Method::PATCH,
        &format!("/rooms/{room}/policy"),
        Some(json!({"model": "local_only"})),
    )
    .await;
    records(&fx, &room, 3, "2026-11-01T00:00:00Z").await;
    assert_eq!(
        fx.brain
            .overview_sweep_at(fx.app.clock.unix() + 100)
            .await
            .unwrap(),
        0
    );
    assert_eq!(queued(&fx, &room).await, 0);
    assert_eq!(card(&fx, &room).await["card_pending"], false);
}

#[tokio::test]
async fn a_refresh_needs_25_new_records_or_a_day_and_is_debounced() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    let t0 = fx.app.clock.unix();
    let w = ainkrad_core_server::scheduler::iso_of_unix(t0);
    let later = ainkrad_core_server::scheduler::iso_of_unix(t0 + 10);
    written(&fx, &room, &w, "written").await;
    records(&fx, &room, 3, "2026-11-01T00:00:00Z").await; // older than the overview: not new
    records(&fx, &room, 24, &later).await;
    // Young overview: debounced, even with plenty new.
    assert_eq!(fx.brain.overview_sweep_at(t0 + 120).await.unwrap(), 0);
    // 24 new after the debounce: below the threshold, and under a day old.
    assert_eq!(fx.brain.overview_sweep_at(t0 + 7200).await.unwrap(), 0);
    records(&fx, &room, 1, &later).await;
    assert_eq!(
        fx.brain.overview_sweep_at(t0 + 7300).await.unwrap(),
        1,
        "25 new"
    );
    // Any new record plus a day also refreshes.
    written(&fx, &room, &w, "written").await;
    let p = canon_pool(&fx, &room).await;
    sqlx::query("DELETE FROM records WHERE created_at = ?")
        .bind(&later)
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    records(&fx, &room, 1, &later).await;
    assert_eq!(fx.brain.overview_sweep_at(t0 + 7400).await.unwrap(), 0);
    assert_eq!(
        fx.brain.overview_sweep_at(t0 + 90_000).await.unwrap(),
        1,
        "a day old"
    );
}

#[tokio::test]
async fn a_failed_write_does_not_loop() {
    let fx = fx().await;
    let room = committed_room(&fx, DOCS).await;
    bind_distil_chain(&fx, make_chain(&fx, &["anthropic"]).await).await;
    let t0 = fx.app.clock.unix();
    records(&fx, &room, 3, "2026-11-01T00:00:00Z").await;
    let p = canon_pool(&fx, &room).await;
    let at = ainkrad_core_server::scheduler::iso_of_unix(t0);
    sqlx::query("INSERT OR IGNORE INTO room_overview (id, updated_at) VALUES (1, ?)")
        .bind(&at)
        .execute(&p)
        .await
        .unwrap();
    sqlx::query("UPDATE room_overview SET state = 'failed', updated_at = ? WHERE id = 1")
        .bind(&at)
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    assert_eq!(fx.brain.overview_sweep_at(t0 + 100).await.unwrap(), 0);
    assert_eq!(
        fx.brain.overview_sweep_at(t0 + 7 * 3600).await.unwrap(),
        1,
        "tried again after 6 h"
    );
}
