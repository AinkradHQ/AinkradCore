//! Device management (E1-09.5, handshake spec §8, §10, §12, §17.15): get, rename, change scopes
//! and revoke, each audited; the subset rule, the runner rule and the last admin hold; a
//! runner or a read-only device is refused all of it; a scope change closes the device's
//! sockets with 4003.

use std::time::Duration;

use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use super::events::{connect, drain, quick, serve};
use super::stepup::plain;
use super::*;

fn path(dev: &TestDevice) -> String {
    format!("/api/v1/devices/{}", dev.id)
}

async fn scopes(fx: &Fx, by: &TestDevice, of: &TestDevice, s: &[&str]) -> (StatusCode, Value) {
    let uri = format!("{}/scopes", path(of));
    send(
        &fx.app,
        req(Method::PUT, &uri, Some(by), Some(json!({"scopes": s}))),
    )
    .await
}

async fn audited(fx: &Fx, action: &str, device: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = ? \
         AND json_extract(details, '$.device') = ?",
    )
    .bind(action)
    .bind(device)
    .fetch_one(&fx.app.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn get_rename_and_change_scopes_are_audited() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let got = fx.ok(&path(&phone)).await;
    assert_eq!(
        (got["name"].clone(), got["stepup"].clone()),
        (json!("phone"), json!(true))
    );
    let (s, _) = fx.get("/api/v1/devices/d_00000000000000000000000000").await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let body = |n: &str| Some(json!({"name": n}));
    let (s, b) = send(
        &fx.app,
        req(
            Method::PATCH,
            &path(&phone),
            Some(&fx.dev),
            body(" iPhone "),
        ),
    )
    .await;
    assert_eq!((s, &b["name"]), (StatusCode::OK, &json!("iPhone")));
    for bad in ["", "   ", "a\nb", &"x".repeat(65)] {
        let (s, _) = send(
            &fx.app,
            req(Method::PATCH, &path(&phone), Some(&fx.dev), body(bad)),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    assert_eq!(audited(&fx, "device.renamed", &phone.id).await, 1);

    let (s, b) = scopes(&fx, &fx.dev, &phone, &["approve", "read", "read"]).await;
    assert_eq!(
        (s, &b["scopes"]),
        (StatusCode::OK, &json!(["read", "approve"])),
        "{b}"
    );
    assert_eq!(audited(&fx, "device.scopes_changed", &phone.id).await, 1);
    // Enforced on its very next request: it holds `approve` but not `admin`.
    let (s, _) = send(
        &fx.app,
        req(Method::GET, "/api/v1/devices", Some(&phone), None),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn nobody_grants_more_than_it_holds_and_runners_stay_runners() {
    let fx = fx().await;
    let narrow = fx.enroll("narrow", &["read", "admin"]).await;
    let phone = fx.enroll("phone", &["read"]).await;
    // Not to another device, and not to itself.
    for (of, s) in [
        (&phone, &["read", "terminal"][..]),
        (&narrow, &["read", "admin", "terminal"]),
    ] {
        let (st, b) = scopes(&fx, &narrow, of, s).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
    }
    assert_eq!(
        scopes(&fx, &narrow, &phone, &["admin"]).await.0,
        StatusCode::OK
    );
    for bad in [&["nope"][..], &[], &["runner"]] {
        assert_eq!(
            scopes(&fx, &fx.dev, &phone, bad).await.0,
            StatusCode::BAD_REQUEST,
            "{bad:?}"
        );
    }
    let runner = TestDevice::enroll(
        &fx.app.pool,
        "runner",
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    for bad in [&["read"][..], &["runner", "read"]] {
        assert_eq!(
            scopes(&fx, &fx.dev, &runner, bad).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        scopes(&fx, &fx.dev, &runner, &["runner"]).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_last_admin_can_be_neither_demoted_nor_revoked() {
    let fx = fx().await;
    let mac = fx.dev.id.clone();
    let (s, b) = scopes(&fx, &fx.dev, &fx.dev, &["read"]).await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::CONFLICT, &json!("conflict")),
        "{b}"
    );
    let (s, _) = send(
        &fx.app,
        req(Method::DELETE, &path(&fx.dev), Some(&fx.dev), None),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // With a second admin, two demotions race in the store (each holds every scope): exactly one
    // wins, whichever commits first. Over the API the loser could also be refused its scope.
    let phone = fx.enroll("phone", &ALL).await;
    let all: Vec<String> = ALL.iter().map(|s| (*s).to_owned()).collect();
    let read = ["read".to_owned()];
    let pool = &fx.app.pool;
    let by = super::super::BY;
    let (a, b) = tokio::join!(
        crate::store::gov::set_device_scopes(pool, &phone.id, &read, &all, by, &mac),
        crate::store::gov::set_device_scopes(pool, &mac, &read, &all, by, &phone.id)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert!(a.is_ok() != b.is_ok(), "{a:?} {b:?}");
    assert!(
        [&a, &b]
            .iter()
            .any(|r| **r == Err(crate::store::gov::Refused::LastAdmin))
    );
    let admins: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_devices WHERE revoked_at IS NULL \
         AND EXISTS (SELECT 1 FROM json_each(scopes) WHERE value = 'admin')",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(admins, 1, "{mac}");
}

/// The review's H1 matrix for the new routes: a runner and a read-only phone get 403 on every
/// one, elevated or not.
#[tokio::test]
async fn runner_and_read_only_devices_are_refused_device_admin() {
    let fx = fx().await;
    let reader = fx.enroll("phone", &["read", "approve"]).await;
    let runner = TestDevice::enroll(
        &fx.app.pool,
        "runner",
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    let s = fx.app.auth.issue_session(&runner.id, fx.clock.unix());
    fx.app
        .auth
        .elevate(&s.id, &runner.id, fx.clock.unix() + 600);
    runner.set_session(Some(s.id));
    let target = path(&fx.dev);
    let calls = [
        (Method::GET, target.clone(), None),
        (Method::PATCH, target.clone(), Some(json!({"name": "x"}))),
        (
            Method::PUT,
            format!("{target}/scopes"),
            Some(json!({"scopes": ["read"]})),
        ),
        (Method::DELETE, target.clone(), None),
        (Method::GET, "/api/v1/auth/lockouts".to_owned(), None),
        (
            Method::POST,
            "/api/v1/auth/lockouts/clear".to_owned(),
            Some(json!({"key": "ip:x"})),
        ),
    ];
    for dev in [&reader, &runner] {
        for (m, uri, body) in &calls {
            let (s, b) = send(&fx.app, req(m.clone(), uri, Some(dev), body.clone())).await;
            assert_eq!(
                (s, &b["code"]),
                (StatusCode::FORBIDDEN, &json!("forbidden_scope")),
                "{m} {uri}"
            );
        }
    }
    assert_eq!(fx.ok(&target).await["revoked_at"], Value::Null);
}

#[tokio::test]
async fn revoke_needs_a_step_up_and_still_fans_out() {
    let fx = fx().await;
    let admin = plain(&fx, "admin", &ALL, true).await;
    let phone = fx.enroll("phone", &["read"]).await;
    let (s, b) = send(
        &fx.app,
        req(Method::DELETE, &path(&phone), Some(&admin), None),
    )
    .await;
    assert_eq!(
        (s, &b["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    assert_eq!(super::stepup::step_up(&fx, &admin).await.0, StatusCode::OK);
    let (s, b) = send(
        &fx.app,
        req(Method::DELETE, &path(&phone), Some(&admin), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, _) = send(&fx.app, req(Method::GET, "/api/v1/me", Some(&phone), None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(audited(&fx, "device.revoked", &phone.id).await, 1);
}

/// §17.15: a scope change closes the device's open socket with 4003, through the broadcast or,
/// from another process, the database backstop.
#[tokio::test]
async fn a_scope_change_closes_the_devices_socket_with_4003() {
    let fx = fx().await;
    let phone = fx.enroll("phone", &["read", "approve"]).await;
    let app = serve(&fx, quick()).await;
    let mut ws = connect(&app, &phone, None).await.unwrap();
    let mut bystander = connect(&app, &fx.dev, None).await.unwrap();
    assert_eq!(
        scopes(&fx, &fx.dev, &phone, &["read"]).await.0,
        StatusCode::OK
    );
    let (_, _, close) = tokio::time::timeout(Duration::from_secs(1), drain(&mut ws))
        .await
        .expect("closed at once");
    let (code, reason) = close.expect("a close frame");
    assert_eq!(code, CloseCode::Library(4003), "{reason}");

    // The backstop: the row changes with no broadcast in this process.
    let mut ws = connect(&app, &phone, None).await.unwrap();
    sqlx::query("UPDATE core_devices SET scopes = '[\"read\",\"approve\"]' WHERE id = ?")
        .bind(&phone.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let (_, _, close) = tokio::time::timeout(Duration::from_secs(5), drain(&mut ws))
        .await
        .expect("closed within 5 s");
    assert_eq!(close.unwrap().0, CloseCode::Library(4003));
    // Another device's socket stays open.
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
