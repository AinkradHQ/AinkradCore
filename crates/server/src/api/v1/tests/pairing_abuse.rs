//! Pairing under pressure and the checks the review's mutation run found untested: concurrent
//! wrong claims stay within the address's and the global budget (M2); wrong claims leave no
//! audit row each and a bounded lockout table (M4); approval re-checks the approver's scopes
//! (§17.20); the claim re-checks the bootstrap guard inside its transaction (§17.24).

use super::*;
use crate::store::gov::{self, NewPairing, create_pairing};

async fn count(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

fn wrong_claim(fx: &Fx, peer: &str) -> Request<Body> {
    let dev = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    from(
        peer,
        req(
            Method::POST,
            "/pair/claim",
            None,
            Some(dev.claim_body(Some("ZZZZZ-ZZZZZ"), None)),
        ),
    )
}

/// M2, §17.21 under concurrency: 200 wrong claims at once from one address: at most 20 are
/// evaluated, the rest are a 429 that writes nothing.
#[tokio::test]
async fn concurrent_wrong_claims_stay_within_both_budgets() {
    let fx = fx().await;
    let fx = &fx;
    let audit_before = count(fx, "SELECT count(*) FROM audit_events").await;
    let sends = (0..200).map(|_| async move { send(&fx.app, wrong_claim(fx, "10.9.9.9")).await.0 });
    let statuses = futures_util::future::join_all(sends).await;
    let guessed = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    let limited = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert!(guessed <= 20, "{guessed} claims evaluated");
    assert_eq!(guessed + limited, 200);
    let added = count(fx, "SELECT count(*) FROM audit_events").await - audit_before;
    assert!(
        added <= 1,
        "{added} audit rows: the address lock at most (nothing live to burn)"
    );
}

/// M4: 300 wrong claims from 100 addresses, nothing live: no audit row at all, one lockout row
/// per address, and the sweep empties the table once they stop counting.
#[tokio::test]
async fn wrong_claims_do_not_grow_the_audit_log_and_the_lockouts_are_swept() {
    let fx = fx().await;
    let audit_before = count(&fx, "SELECT count(*) FROM audit_events").await;
    for i in 0..300 {
        let (s, _) = send(
            &fx.app,
            wrong_claim(&fx, &format!("10.10.{}.{}", i % 100 / 250, i % 100)),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        count(&fx, "SELECT count(*) FROM audit_events").await,
        audit_before
    );
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_auth_limits").await,
        100
    );
    let later = fx.clock.unix() + 24 * 3600 + 601;
    gov::prune_limits(&fx.app.pool, later).await.unwrap();
    assert_eq!(count(&fx, "SELECT count(*) FROM core_auth_limits").await, 0);
}

/// §17.20 at approval: an approver narrower than the pairing cannot approve it as bound.
#[tokio::test]
async fn approval_rechecks_the_approvers_scopes() {
    let fx = fx().await;
    let body = json!({"name": "Wide", "kind": "device", "scopes": ["read", "terminal"]});
    let (_, created) = send(
        &fx.app,
        req(Method::POST, "/api/v1/pairings", Some(&fx.dev), Some(body)),
    )
    .await;
    let claimant = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    let claim = from(
        "10.11.0.1",
        req(
            Method::POST,
            "/pair/claim",
            None,
            Some(claimant.claim_body(created["code"].as_str(), None)),
        ),
    );
    let (_, got) = send(&fx.app, claim).await;
    let narrow = fx.enroll("narrow", &["read", "admin"]).await;
    let uri = format!(
        "/api/v1/pairings/{}/approve",
        created["pairing_id"].as_str().unwrap()
    );
    let (s, body) = send(
        &fx.app,
        req(
            Method::POST,
            &uri,
            Some(&narrow),
            Some(json!({"sas": got["sas"]})),
        ),
    )
    .await;
    assert_eq!(
        (s, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("forbidden_scope")),
        "terminal is not the approver's"
    );
    let (s, _) = send(
        &fx.app,
        req(
            Method::POST,
            &uri,
            Some(&narrow),
            Some(json!({"sas": got["sas"], "scopes": ["read"]})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "narrowed to the approver's own");
}

/// §17.24: a device enrolled between the bootstrap pairing's creation and its claim makes the
/// claim fail inside the claim's transaction.
#[tokio::test]
async fn a_bootstrap_claim_rechecks_that_no_device_exists() {
    let fx = fx().await;
    sqlx::query("DELETE FROM core_devices")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let scopes = vec!["read".to_owned()];
    let p = NewPairing {
        kind: "device",
        name: "first",
        scopes: &scopes,
        created_by: None,
        bootstrap: true,
        recovery: false,
    };
    let created = create_pairing(
        &fx.app.pool,
        &p,
        ainkrad_core::audit::AuditActor::System,
        fx.clock.unix(),
    )
    .await
    .unwrap();
    let _meanwhile = fx.enroll("meanwhile", &["read"]).await;
    let dev = TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone());
    let mut r = req(
        Method::POST,
        "/pair/claim",
        None,
        Some(dev.claim_body(Some(&created.code), None)),
    );
    r.extensions_mut()
        .insert(crate::gateway::Local { same_user: true });
    assert_eq!(send(&fx.app, r).await.0, StatusCode::UNAUTHORIZED);
    let devices = count(&fx, "SELECT count(*) FROM core_devices").await;
    assert_eq!(devices, 1, "only the one enrolled meanwhile");
}
