//! Room settings (app PR #166): `daily_distils` on the policy, and `GET /rooms/{room}/card`.
//! Every room and source here is made up.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::ai::as_session;
use super::common::*;

#[tokio::test]
async fn daily_distils_is_shown_bounded_and_a_person_only_setting() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let path = format!("/rooms/{room}/policy");
    assert_eq!(
        ok(&fx, Method::GET, &path, None).await["daily_distils"],
        json!(12)
    );

    for n in [0, 50] {
        let v = ok(&fx, Method::PATCH, &path, Some(json!({"daily_distils": n}))).await;
        assert_eq!(v["daily_distils"], json!(n));
        assert_eq!(
            ok(&fx, Method::GET, &path, None).await["daily_distils"],
            json!(n)
        );
    }
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &path,
        Some(json!({"daily_distils": 51})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let kept: i64 =
        sqlx::query_scalar("SELECT daily_distils FROM brain_room_policy WHERE room = ?")
            .bind(&room)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(kept, 50);

    // A patch that leaves it out keeps it.
    ok(&fx, Method::PATCH, &path, Some(json!({"min_sources": 2}))).await;
    assert_eq!(
        ok(&fx, Method::GET, &path, None).await["daily_distils"],
        json!(50)
    );

    // An AI session may not change it, even down.
    let s = chain_session(&fx, &["anthropic"]).await;
    let (st, v) = as_session(
        &fx,
        &s,
        Method::PATCH,
        &path,
        Some(json!({"daily_distils": 5})),
    )
    .await;
    assert_eq!(
        (st, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("person_only"))
    );
    assert_eq!(
        ok(&fx, Method::GET, &path, None).await["daily_distils"],
        json!(50)
    );
}

#[tokio::test]
async fn the_card_is_served_to_a_person_for_an_open_room_only() {
    let fx = fx().await;
    let room = committed_room(&fx, &[("A", "alpha text")]).await;
    let path = format!("/rooms/{room}/card");

    let (s, v) = call(&fx, &fx.admin, Method::GET, &path, None).await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("room_closed"))
    );
    let (s, _) = call(&fx, &fx.admin, Method::GET, "/rooms/nope/card", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let v = ok(&fx, Method::GET, &path, None).await;
    assert!(
        v["text"].is_string() && v["ids"].is_array() && v["complete"].is_boolean(),
        "{v}"
    );

    // An AI session gets the card through `brainAiContext`, not this route.
    let s = chain_session(&fx, &["anthropic"]).await;
    let (st, v) = as_session(&fx, &s, Method::GET, &path, None).await;
    assert_eq!(
        (st, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("person_only"))
    );
}
