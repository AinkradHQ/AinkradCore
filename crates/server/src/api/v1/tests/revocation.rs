//! Revocation fan-out (handshake spec §10, §17.14): a revoked device's open event socket
//! closes with 4001 within 5 s, through the broadcast (API revoke) or, without it, through
//! the 2 s database backstop (a revoke from the CLI, another process); its next request is
//! `auth_failed`, and the revocation is audited once.

use std::time::Duration;

use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use super::events::{connect, drain, quick, serve};
use super::*;

async fn close_within(ws: &mut super::events::Ws, limit: Duration) -> (CloseCode, String) {
    let started = std::time::Instant::now();
    let (_, _, close) = tokio::time::timeout(limit, drain(ws))
        .await
        .expect("closed within the limit");
    assert!(started.elapsed() <= limit);
    close.expect("a close frame")
}

#[tokio::test]
async fn revoking_through_the_api_closes_the_socket_at_once() {
    let fx = fx().await;
    let phone = fx.enroll("iPhone", &["read"]).await;
    let app = serve(&fx, quick()).await;
    let mut ws = connect(&app, &phone, None).await.unwrap();
    let mut bystander = connect(&app, &fx.dev, None).await.unwrap();

    let uri = format!("/api/v1/devices/{}", phone.id);
    let (status, body) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (code, reason) = close_within(&mut ws, Duration::from_secs(1)).await;
    assert_eq!(code, CloseCode::Library(4001), "{reason}");
    assert!(reason.starts_with("revoked"), "{reason}");

    let (status, body) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("auth_failed"))
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'device.revoked' \
         AND json_extract(details, '$.device') = ?",
    )
    .bind(&phone.id)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(rows, 1);

    // Another device's socket stays open: it still gets events.
    sqlx::query("INSERT INTO events (kind, payload) VALUES ('ops.line', '{}')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    use futures_util::StreamExt;
    let msg = tokio::time::timeout(Duration::from_secs(5), bystander.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(msg.is_text(), "{msg:?}");
}

#[tokio::test]
async fn without_the_broadcast_the_backstop_closes_the_socket_within_five_seconds() {
    let fx = fx().await;
    let phone = fx.enroll("iPhone", &["read"]).await;
    let app = serve(&fx, quick()).await;
    let mut ws = connect(&app, &phone, None).await.unwrap();
    // As the CLI does: the store only, no broadcast reaches this process.
    let revoked =
        crate::store::gov::revoke_device(&fx.app.pool, &phone.id, super::super::BY, None, NOW);
    assert!(revoked.await.unwrap());
    let (code, _) = close_within(&mut ws, Duration::from_secs(5)).await;
    assert_eq!(code, CloseCode::Library(4001));
    // Its session is useless: the device row says revoked.
    let (status, _) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
