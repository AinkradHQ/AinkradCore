//! Unauthenticated pressure (security review M1, M2, L1 and the §17.8 gaps): a flood of
//! challenges for made-up ids cannot starve a real device; concurrent failures from one address
//! cannot slip under its budget, and past it nothing is written; every refusal from the device
//! lookup on takes the 50 ms floor; pending and locked devices look like unknown ones.

use std::time::Instant;

use super::signed::{PATH, raw};
use super::*;
use crate::api::v1::gate::FAIL_FLOOR;

async fn ask(fx: &Fx, peer: &str, id: &str) -> (StatusCode, Value) {
    let body = json!({"device_id": id});
    send(
        &fx.app,
        from(
            peer,
            req(Method::POST, "/handshake/challenge", None, Some(body)),
        ),
    )
    .await
}

/// M1: 10,000 challenges for made-up ids from 340 addresses store nothing; the real device's
/// next challenge works and gives a session.
#[tokio::test]
async fn a_challenge_flood_cannot_starve_a_real_device() {
    let fx = fx().await;
    let fx = &fx;
    let sends = (0..10_000).map(|i| {
        let peer = format!("10.{}.{}.1", 20 + i / 30 / 250, (i / 30) % 250);
        let id = crate::auth::crypto::random_id("d_");
        async move { ask(fx, &peer, &id).await.0 }
    });
    let statuses = futures_util::future::join_all(sends).await;
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "every made-up id gets an answer"
    );
    let (status, got) = ask(fx, "10.99.0.1", &fx.dev.id).await;
    assert_eq!(status, StatusCode::OK);
    let body = json!({"challenge": got["challenge"]}).to_string();
    let h = fx
        .dev
        .headers_session("POST", "/handshake/session", body.as_bytes(), None);
    let (status, grant) = send(
        &fx.app,
        raw(Method::POST, "/handshake/session", &h, body.as_bytes()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
}

/// M2: 200 concurrent failures from one address: at most its budget (20) are evaluated and
/// written; the rest are a cheap 429.
#[tokio::test]
async fn concurrent_failures_from_one_address_stay_within_its_budget() {
    let fx = fx().await;
    let fx = &fx;
    let sends = (0..200).map(|_| {
        let stranger = fx.stranger();
        async move {
            let r = from("10.8.8.8", req(Method::GET, PATH, Some(&stranger), None));
            send(&fx.app, r).await.0
        }
    });
    let statuses = futures_util::future::join_all(sends).await;
    let failed = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    let limited = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert!(failed <= 20, "{failed} evaluated past the budget");
    assert_eq!(failed + limited, 200);
    let fails: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(fails), 0) + count(*) FILTER (WHERE locked_until > 0) * 20 \
         FROM core_auth_limits WHERE key = 'ip:10.8.8.8'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert!(fails <= 20, "{fails} failures written for the address");
}

/// The 50 ms floor: an unknown device's refusal never comes back faster.
#[tokio::test]
async fn a_refusal_takes_at_least_the_floor() {
    let fx = fx().await;
    for i in 0..5 {
        let r = from(
            &format!("10.7.7.{i}"),
            req(Method::GET, PATH, Some(&fx.stranger()), None),
        );
        let started = Instant::now();
        let (status, _) = send(&fx.app, r).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(started.elapsed() >= FAIL_FLOOR, "{:?}", started.elapsed());
    }
}

/// §17.8 for every unusable state: unknown, pending, locked, rejected and expired devices get
/// the same answer; and a body over 16 KiB from an unusable device is not a tell-tale 413.
#[tokio::test]
async fn unusable_devices_of_every_status_look_alike() {
    let fx = fx().await;
    let mut bodies = Vec::new();
    for (n, status) in ["pending", "locked", "rejected", "expired"]
        .iter()
        .enumerate()
    {
        let dev = fx.enroll(status, &["read"]).await;
        sqlx::query("UPDATE core_devices SET status = ? WHERE id = ?")
            .bind(status)
            .bind(&dev.id)
            .execute(&fx.app.pool)
            .await
            .unwrap();
        let r = from(
            &format!("10.6.6.{n}"),
            req(Method::GET, PATH, Some(&dev), None),
        );
        bodies.push(send(&fx.app, r).await);
    }
    let r = from(
        "10.6.6.9",
        req(Method::GET, PATH, Some(&fx.stranger()), None),
    );
    bodies.push(send(&fx.app, r).await);
    for (status, body) in &mut bodies {
        assert_eq!(*status, StatusCode::UNAUTHORIZED);
        body.as_object_mut().unwrap().remove("error_id");
    }
    assert!(bodies.iter().all(|b| b.1 == bodies[0].1), "{bodies:?}");
    let big = json!({"token": "x".repeat(20 * 1024)});
    let r = from(
        "10.6.6.10",
        req(
            Method::PUT,
            "/api/v1/push-token",
            Some(&fx.stranger()),
            Some(big),
        ),
    );
    assert_eq!(
        send(&fx.app, r).await.0,
        StatusCode::UNAUTHORIZED,
        "not 413"
    );
}
