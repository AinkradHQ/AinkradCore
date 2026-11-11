use axum::http::{Method, StatusCode};
use brain_module::Brain;
use brain_module::rooms::AccessError;
use serde_json::json;

use super::common::*;

/// One committed personal room; returns its id.
async fn one_room(fx: &Fx) -> String {
    let run = start(fx).await;
    send(
        fx,
        &run,
        vec![item(1, "/h/Projects/Alpha/a", "a", "alpha text")],
    )
    .await;
    finish(fx, &run).await;
    let id = proposals(fx, &run).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{id}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    ok(fx, Method::POST, &format!("/imports/{run}/commit"), None).await["rooms"][0]["room"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn opening_a_room_needs_a_step_up_and_a_closed_room_gives_no_handle() {
    let fx = fx().await;
    let room = one_room(&fx).await;
    let key = key_of(&fx).await;
    assert_eq!(
        fx.brain.rooms().access(&fx.app, &key, &room).await.err(),
        Some(AccessError::Closed)
    );
    let (s, v) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &format!("/rooms/{room}/open"),
        None,
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert_eq!(
        fx.brain.rooms().access(&fx.app, &key, &room).await.err(),
        Some(AccessError::Closed)
    );
    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    assert!(fx.brain.rooms().access(&fx.app, &key, &room).await.is_ok());
    assert_eq!(
        fx.brain
            .rooms()
            .access(&fx.app, &key, "no-such-room")
            .await
            .err(),
        Some(AccessError::Unknown)
    );
    assert_eq!(
        fx.brain
            .rooms()
            .access(&fx.app, &key, "../escape")
            .await
            .err(),
        Some(AccessError::Unknown)
    );
    let (s, _) = call(&fx, &fx.admin, Method::POST, "/rooms/nope/open", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_lease_that_ends_closes_the_room() {
    let fx = fx_with(Brain::with_lease_secs(1), 1).await;
    let room = one_room(&fx).await;
    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let key = key_of(&fx).await;
    assert!(fx.brain.rooms().access(&fx.app, &key, &room).await.is_ok());
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert_eq!(
        fx.brain.rooms().access(&fx.app, &key, &room).await.err(),
        Some(AccessError::Closed)
    );
    assert_eq!(ok(&fx, Method::GET, "/rooms", None).await[0]["open"], false);
}

#[tokio::test]
async fn a_room_file_from_a_newer_version_is_refused_and_stays_closed() {
    let fx = fx().await;
    let room = one_room(&fx).await;
    let key = key_of(&fx).await;
    let path = brain_module::files::room_path(&brain_module::files::root(&fx.app), &room);
    let pool = brain_module::cipher::open(&path, &key, false)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO _file_migrations (version, name, checksum) VALUES (99, 'canon_0099', x'00')",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/open"),
        None,
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("room_file_newer"))
    );
    assert!(fx.brain.rooms().access(&fx.app, &key, &room).await.is_err());
    let alarms = ainkrad_core_server::store::events::list_events(&fx.app.pool, 0, 1000)
        .await
        .unwrap();
    assert!(format!("{alarms:?}").contains("brain.alarm"));
    let refused: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'brain.room.refused'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(refused, 1);
}
