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

/// KAN-417, agent streams: a device holding `agent` is fed agent events over its socket; once
/// revoked the socket closes with 4001 and not one agent event reaches it afterwards, through the
/// broadcast and, as the CLI does it, through the store only. It cannot reconnect either.
#[tokio::test]
async fn an_agent_event_stream_ends_when_its_device_is_revoked() {
    use futures_util::StreamExt;
    for broadcast in [true, false] {
        let fx = fx().await;
        let agent = fx.enroll("agent-ui", &["read", "agent"]).await;
        let app = serve(&fx, quick()).await;
        let mut ws = connect(&app, &agent, None).await.unwrap();
        let insert = || async {
            sqlx::query("INSERT INTO events (kind, payload) VALUES ('agent.message', '{}')")
                .execute(&fx.app.pool)
                .await
                .unwrap();
        };
        insert().await;
        let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            first.is_text() && first.to_text().unwrap().contains("agent.message"),
            "{first:?}"
        );

        if broadcast {
            let uri = format!("/api/v1/devices/{}", agent.id);
            let (status, _) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
            assert_eq!(status, StatusCode::OK);
        } else {
            let done = crate::store::gov::revoke_device(
                &fx.app.pool,
                &agent.id,
                super::super::BY,
                None,
                NOW,
            );
            assert!(done.await.unwrap());
        }
        // Appended after the revocation: it must not be delivered on this socket.
        insert().await;
        let limit = Duration::from_secs(if broadcast { 1 } else { 5 });
        let (events, _, close) = tokio::time::timeout(limit, drain(&mut ws))
            .await
            .expect("closed within the limit");
        assert_eq!(events, 0, "an event after the revocation was delivered");
        assert_eq!(close.map(|c| c.0), Some(CloseCode::Library(4001)));
        assert!(connect(&app, &agent, None).await.is_err(), "reconnected");
    }
}

/// KAN-417: a replay in progress ends when the device is revoked: the catch-up loop checks the
/// fanned-out revocation between frames and the database between pages, so a revoked device
/// is not sent the rest of a long history.
#[tokio::test]
async fn a_replay_in_progress_ends_when_its_device_is_revoked() {
    use futures_util::StreamExt;
    const EVENTS: usize = 5000;
    for broadcast in [true, false] {
        let fx = fx().await;
        let reader = fx.enroll("reader", &["read"]).await;
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?) \
             INSERT INTO events (kind, payload) \
             SELECT 'ops.line', json_object('p', hex(zeroblob(2048))) FROM n",
        )
        .bind(EVENTS as i64)
        .execute(&fx.app.pool)
        .await
        .unwrap();
        let app = serve(&fx, quick()).await;
        let mut ws = connect(&app, &reader, Some("0")).await.unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(first.is_text());
        if broadcast {
            let uri = format!("/api/v1/devices/{}", reader.id);
            let (status, _) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.dev), None)).await;
            assert_eq!(status, StatusCode::OK);
        } else {
            let done = crate::store::gov::revoke_device(
                &fx.app.pool,
                &reader.id,
                super::super::BY,
                None,
                NOW,
            );
            assert!(done.await.unwrap());
        }
        let (events, _, close) = tokio::time::timeout(Duration::from_secs(10), drain(&mut ws))
            .await
            .expect("closed");
        // Only what the kernel had already buffered can still arrive: far from the history.
        assert!(
            events < EVENTS * 3 / 4,
            "the replay ran on: {events} frames"
        );
        assert_eq!(close.map(|c| c.0), Some(CloseCode::Library(4001)));
    }
}
