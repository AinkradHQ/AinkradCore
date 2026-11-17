//! P1-03: a project and a Brain room are strictly 1:1, in both directions.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::projects::{self, Who};
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::common::*;

async fn project(fx: &Fx, slug: &str, name: &str) -> i64 {
    let now = fx.app.clock.now();
    let who = Who {
        by_device: &fx.admin.id,
        actor: AuditActor::System,
        now: &now,
    };
    projects::create(&fx.app.pool, slug, name, "", "manual", who)
        .await
        .unwrap()
        .id
}

/// `GET /api/v1/projects/{id}` as the admin.
async fn get_project(fx: &Fx, id: i64) -> Value {
    let uri = format!("/api/v1/projects/{id}");
    let mut b = Request::builder().uri(&uri).header(header::HOST, HOST);
    for (n, v) in fx.admin.headers("GET", &uri, b"") {
        b = b.header(n, v);
    }
    let res = ainkrad_core_server::api::router(fx.app.clone())
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(res.into_body(), 1 << 20).await.unwrap()).unwrap()
}

async fn link(fx: &Fx, project: i64, room: &str) -> (StatusCode, Value) {
    call(
        fx,
        &fx.admin,
        Method::PUT,
        &format!("/projects/{project}/room"),
        Some(json!({"room": room})),
    )
    .await
}

#[tokio::test]
async fn a_new_project_gets_a_product_room_named_after_it_and_archiving_leaves_it() {
    let fx = fx().await;
    let id = project(&fx, "shop", "Shop").await;
    assert!(get_project(&fx, id).await["room"].is_null());
    fx.brain.project_rooms_step().await.unwrap();
    let p = get_project(&fx, id).await;
    assert_eq!(p["room"]["name"], "Shop");
    let room = p["room"]["room_id"].as_str().unwrap().to_owned();
    let kind: String = sqlx::query_scalar("SELECT kind FROM brain_rooms WHERE id = ?")
        .bind(&room)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(kind, "product");
    // Read twice: still one room.
    fx.brain.project_rooms_step().await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    let now = fx.app.clock.now();
    let who = Who {
        by_device: &fx.admin.id,
        actor: AuditActor::System,
        now: &now,
    };
    projects::archive(&fx.app.pool, id, who).await.unwrap();
    assert_eq!(get_project(&fx, id).await["room"]["room_id"], room);
    let state: String = sqlx::query_scalar("SELECT state FROM brain_rooms WHERE id = ?")
        .bind(&room)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(state, "active");
}

#[tokio::test]
async fn a_room_is_linked_to_one_project_and_a_project_to_one_room() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let other = committed_room_named(&fx, "Beta", &[("B", "beta text")]).await;
    let (a, b) = (project(&fx, "aa", "A").await, project(&fx, "bb", "B").await);
    assert_eq!(link(&fx, a, &room).await.0, StatusCode::OK);
    // The room again, from another project.
    let (s, v) = link(&fx, b, &room).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("room_linked"))
    );
    // The project again, with another room.
    let (s, v) = link(&fx, a, &other).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("project_linked"))
    );
    // The table refuses both on its own, whatever the handler does.
    let a_text = a.to_string();
    for (p, r) in [("9", room.as_str()), (a_text.as_str(), other.as_str())] {
        let e = sqlx::query("INSERT INTO brain_project_rooms (project, room) VALUES (?, ?)")
            .bind(p)
            .bind(r)
            .execute(&fx.app.pool)
            .await
            .unwrap_err();
        assert!(e.as_database_error().unwrap().is_unique_violation(), "{e}");
    }
    // Unlinking frees both sides; the room stays.
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        &format!("/projects/{a}/room"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(link(&fx, b, &room).await.0, StatusCode::OK);
    assert!(get_project(&fx, a).await["room"].is_null());
    // A project whose room was linked by hand before the handler ran keeps it; the handler adds none.
    let c = project(&fx, "cc", "C").await;
    assert_eq!(link(&fx, c, &other).await.0, StatusCode::OK);
    fx.brain.project_rooms_step().await.unwrap();
    assert_eq!(get_project(&fx, c).await["room"]["room_id"], other);
}

#[tokio::test]
async fn a_project_room_made_before_the_brain_key_gets_its_file_on_first_open() {
    let fx = fx().await;
    let id = project(&fx, "early", "Early").await;
    fx.brain.project_rooms_step().await.unwrap();
    let room = get_project(&fx, id).await["room"]["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let file = brain_module::files::room_path(&brain_module::files::root(&fx.app), &room);
    assert!(!file.exists(), "no key yet, so no file");
    // The key appears (an import makes it); the first open makes the room's file.
    start(&fx).await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/rooms/{room}/open"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(file.exists());
}
