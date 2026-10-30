//! The audit log is permanent, so what an abuser can repeat must not grow it per request (review
//! M4): refused step-ups (403 and 429), device-management and lockout refusals, and the gate's
//! `step_up_required` add no row each; only the transitions do (a lock, a grant, a last-admin
//! refusal once per window). Plus the identity layer's other lessons for step-up: the 50 ms
//! floor, and the host's socket never refused because outside addresses filled the table.

use std::time::Instant;

use super::stepup::{challenge, plain, post, step_up};
use super::*;
use crate::api::v1::gate::FAIL_FLOOR;

async fn rows(fx: &Fx, action: Option<&str>) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE ?1 IS NULL OR action = ?1")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

/// A bad step-up proof from `peer`.
async fn bad_proof(fx: &Fx, dev: &TestDevice, peer: &str) -> StatusCode {
    let c = challenge(fx, dev).await;
    let body = json!({"challenge": c, "stepup_sig": "A".repeat(86)});
    let r = from(
        peer,
        req(Method::POST, "/api/v1/auth/step-up", Some(dev), Some(body)),
    );
    send(&fx.app, r).await.0
}

#[tokio::test]
async fn refused_step_ups_from_many_devices_and_addresses_grow_the_audit_log_by_their_locks_only() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    let before = rows(&fx, None).await;
    let devices = [
        plain(&fx, "a", &ALL, true).await,
        plain(&fx, "b", &ALL, true).await,
        plain(&fx, "c", &ALL, true).await,
    ];
    let enrolled = rows(&fx, None).await - before;
    let start = rows(&fx, None).await;
    let (mut refused, mut throttled) = (0, 0);
    for (d, dev) in devices.iter().enumerate() {
        for n in 0..40 {
            match bad_proof(&fx, dev, &format!("10.9.{d}.{}", n % 4)).await {
                StatusCode::FORBIDDEN => refused += 1,
                StatusCode::TOO_MANY_REQUESTS => throttled += 1,
                other => panic!("{other}"),
            }
        }
    }
    assert_eq!(
        (refused, throttled),
        (15, 105),
        "5 evaluated per device, the rest cheap 429s"
    );
    let grown = rows(&fx, None).await - start;
    assert_eq!(
        rows(&fx, Some("api.refused")).await,
        0,
        "no row per refusal"
    );
    assert_eq!(
        grown, 3,
        "one auth.lockout per device, whatever N: {grown} (enrolment {enrolled})"
    );
    assert_eq!(rows(&fx, Some("auth.lockout")).await, 3);
    assert!(
        fx.app
            .auth
            .refusals
            .count("step_up_failed POST /api/v1/auth/step-up")
            >= 15
    );

    // A grant is still audited, once.
    let ok = plain(&fx, "ok", &ALL, true).await;
    assert_eq!(step_up(&fx, &ok).await.0, StatusCode::OK);
    assert_eq!(rows(&fx, Some("auth.step_up")).await, 1);
}

#[tokio::test]
async fn device_admin_and_gate_refusals_are_counted_and_the_last_admin_audited_once() {
    let fx = fx().await;
    let start = rows(&fx, None).await;
    let me = format!("/api/v1/devices/{}", fx.dev.id);
    for _ in 0..10 {
        let body = Some(json!({"name": ""}));
        assert_eq!(
            send(&fx.app, req(Method::PATCH, &me, Some(&fx.dev), body))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let r = post(
            &fx,
            &fx.dev,
            "/api/v1/auth/lockouts/clear",
            json!({"key": "ip:nope"}),
        )
        .await;
        assert_eq!(r.0, StatusCode::NOT_FOUND);
        let scopes = format!("{me}/scopes");
        let body = Some(json!({"scopes": ["read"]}));
        assert_eq!(
            send(&fx.app, req(Method::PUT, &scopes, Some(&fx.dev), body))
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            send(&fx.app, req(Method::DELETE, &me, Some(&fx.dev), None))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
    // The gate's step_up_required (an un-elevated pairing create) writes nothing either.
    let plain_admin = plain(&fx, "plain", &ALL, true).await;
    let enrolled = rows(&fx, None).await;
    for _ in 0..10 {
        let body = json!({"name": "x", "kind": "device", "scopes": ["read"]});
        let r = post(&fx, &plain_admin, "/api/v1/pairings", body).await;
        assert_eq!(r.1["code"], json!("step_up_required"));
    }
    assert_eq!(rows(&fx, None).await, enrolled);
    assert_eq!(rows(&fx, Some("api.refused")).await, 0);
    assert_eq!(
        rows(&fx, Some("device.last_admin_refused")).await,
        1,
        "once per window"
    );
    assert_eq!(
        enrolled - start,
        1 + 1,
        "the last-admin row and the extra device's enrolment"
    );
}

#[tokio::test]
async fn a_failed_step_up_takes_the_floor_and_the_hosts_socket_survives_a_full_address_table() {
    let fx = fx().await;
    let mac = plain(&fx, "mac", &ALL, true).await;
    for peer in ["10.8.0.1", "10.8.0.2"] {
        let started = Instant::now();
        assert_eq!(bad_proof(&fx, &mac, peer).await, StatusCode::FORBIDDEN);
        assert!(started.elapsed() >= FAIL_FLOOR, "{:?}", started.elapsed());
    }
    // Outside addresses fill (and overflow) the address table, each past its budget.
    let now = fx.clock.unix();
    for i in 0..(crate::auth::budget::ADDRESSES_MAX + 100) {
        let addr = format!("ip:198.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255);
        fx.app.auth.failures.count(&addr, now);
    }
    // The host's own socket (no peer address: `ip:local`) still steps up.
    assert_eq!(step_up(&fx, &mac).await.0, StatusCode::OK);
}

/// Review M1: a runner (the lowest-trust device, and since E2-07 able to reach one handler)
/// cannot grow the audit log by repeating refused redemptions: the broker off, a junk lease, a
/// malformed body. They are counted, not written.
#[tokio::test]
async fn refused_secret_redemptions_add_no_audit_row_each() {
    let mut fx = fx().await;
    fx.app.limits = Arc::new(Limits {
        requests: Limiter::new(100_000, 1.0),
    });
    fx.app.secrets = Some(Arc::new(crate::ops::secretbox::SecretBox::new(&[7; 32])));
    let vm = super::secrets::runner(&fx, "vm").await;
    let start = rows(&fx, None).await;
    let uri = "/api/v1/secret-leases/redeem";
    for n in 0..30 {
        let body = match n % 3 {
            0 => json!({"lease": "l_00000000000000000000000000"}),
            1 => json!({"lease": format!("junk-{n}")}),
            _ => json!({"nope": n}),
        };
        let (s, _) = send(&fx.app, req(Method::POST, uri, Some(&vm), Some(body))).await;
        assert!(s.is_client_error(), "{s}");
    }
    assert_eq!(rows(&fx, None).await, start, "no row per refusal");
}
