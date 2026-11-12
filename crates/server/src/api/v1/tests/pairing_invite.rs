//! Invite pairings (handshake spec §7.3): claimed over the network by the QR secret alone, never
//! by the typed code; no expiry; single use; the device is active at the claim with the invite's
//! scopes. The host's invite is bootstrap-class (refused beside a device, a new one burns the old
//! one); an admin's needs a step-up and never widens its creator's scopes. The secret reaches no
//! audit row, table or log.

use std::io::Write;
use std::sync::{Arc, Mutex};

use super::signed::raw;
use super::stepup::plain;
use super::*;
use crate::store::gov::{self, NewPairing, create_pairing, expire_pairings};

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn invite(fx: &Fx, by: &TestDevice, scopes: &[&str]) -> (StatusCode, Value) {
    let body = json!({"name": "Phone", "scopes": scopes});
    let r = req(
        Method::POST,
        "/api/v1/pairings/invites",
        Some(by),
        Some(body),
    );
    send(&fx.app, r).await
}

async fn claim(fx: &Fx, dev: &TestDevice, secret: &str, peer: &str) -> (StatusCode, Value) {
    let body = dev.claim_body(None, Some(secret));
    send(
        &fx.app,
        from(peer, req(Method::POST, "/pair/claim", None, Some(body))),
    )
    .await
}

fn newcomer(fx: &Fx) -> TestDevice {
    TestDevice::new(&fx.app.auth.identity.fp, fx.clock.clone())
}

async fn count(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

async fn pairing_status(fx: &Fx, id: &str) -> String {
    gov::get_pairing(&fx.app.pool, id)
        .await
        .unwrap()
        .unwrap()
        .status
}

/// The host's invite (bootstrap-class), as `ainkrad-core-server pairing-invite` makes it.
async fn host_invite(fx: &Fx) -> Result<gov::Created, sqlx::Error> {
    let scopes: Vec<String> = ALL.iter().map(|s| (*s).to_owned()).collect();
    let p = NewPairing {
        kind: "device",
        name: "first owner",
        scopes: &scopes,
        created_by: None,
        bootstrap: true,
        recovery: false,
        invite: true,
    };
    create_pairing(
        &fx.app.pool,
        &p,
        ainkrad_core::audit::AuditActor::System,
        fx.clock.unix(),
    )
    .await
}

/// An admin device creates an invite; a stranger claims it over the network and is active at
/// once with exactly its scopes: no SAS, no approval, one audit row.
#[tokio::test]
async fn an_admin_invite_is_claimed_over_the_network_and_enrols_at_once() {
    let fx = fx().await;
    let (s, made) = invite(&fx, &fx.dev, &["read", "approve"]).await;
    assert_eq!(s, StatusCode::OK, "{made}");
    let secret = made["secret"].as_str().unwrap();
    let want = format!(
        "ainkrad://connect?host={HOST}&fp={}&secret={secret}",
        fx.app.auth.identity.fp
    );
    assert_eq!(made["link"], want);
    let id = made["pairing_id"].as_str().unwrap();

    let mut dev = newcomer(&fx);
    let (s, got) = claim(&fx, &dev, secret, "203.0.113.9").await;
    assert_eq!(s, StatusCode::ACCEPTED, "{got}");
    let row = gov::get_device(&fx.app.pool, got["device_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.status.as_str(), row.scopes.clone()),
        ("active", vec!["approve".to_owned(), "read".to_owned()])
    );
    assert_eq!(pairing_status(&fx, id).await, "approved");
    dev.id = row.id.clone();
    let h = dev.headers_session("POST", "/pair/status", b"", None);
    let (s, st) = send(&fx.app, raw(Method::POST, "/pair/status", &h, b"")).await;
    assert_eq!((s, st["status"].as_str()), (StatusCode::OK, Some("active")));
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'pairing.approved'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'pairing.claimed'"
        )
        .await,
        0
    );
}

/// The typed code of an invite is refused (and counted); the secret still works after it.
#[tokio::test]
async fn an_invite_is_never_claimed_by_its_typed_code() {
    let fx = fx().await;
    // The code is never shown for an invite, so make one the store's way, which returns it.
    let scopes = vec!["read".to_owned()];
    let twin = create_pairing(
        &fx.app.pool,
        &NewPairing {
            kind: "device",
            name: "twin",
            scopes: &scopes,
            created_by: Some(&fx.dev.id),
            bootstrap: false,
            recovery: false,
            invite: true,
        },
        ainkrad_core::audit::AuditActor::System,
        fx.clock.unix(),
    )
    .await
    .unwrap();
    let (s, b) = claim_code(&fx, &twin.code, "198.51.100.1").await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("pairing_failed"))
    );
    assert_eq!(
        pairing_status(&fx, &twin.id).await,
        "live",
        "refused, not spent"
    );
    let (s, _) = claim(&fx, &newcomer(&fx), &twin.secret, "198.51.100.2").await;
    assert_eq!(s, StatusCode::ACCEPTED);
}

async fn claim_code(fx: &Fx, code: &str, peer: &str) -> (StatusCode, Value) {
    let body = newcomer(fx).claim_body(Some(code), None);
    send(
        &fx.app,
        from(peer, req(Method::POST, "/pair/claim", None, Some(body))),
    )
    .await
}

/// A used, wrong or second claim is the one `pairing_failed`. Twenty wrong claims from 20
/// addresses burn the normal pairings but leave a live invite (its 128-bit secret is not
/// guessable, and the burn would let anyone kill the owner's link): its secret still claims it.
#[tokio::test]
async fn wrong_claims_burn_normal_pairings_but_never_an_invite() {
    let fx = fx().await;
    let (_, used) = invite(&fx, &fx.dev, &["read"]).await;
    let (_, live) = invite(&fx, &fx.dev, &["read"]).await;
    let body = json!({"name": "New", "kind": "device", "scopes": ["read"]});
    let (_, normal) = send(
        &fx.app,
        req(Method::POST, "/api/v1/pairings", Some(&fx.dev), Some(body)),
    )
    .await;
    let secret = used["secret"].as_str().unwrap();
    assert_eq!(
        claim(&fx, &newcomer(&fx), secret, "10.9.0.1").await.0,
        StatusCode::ACCEPTED
    );
    let wrong = crate::auth::crypto::b64(&[9u8; 16]);
    let (s, _) = claim(&fx, &newcomer(&fx), secret, "10.9.1.0").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "second claim of a used invite");
    for i in 1..20 {
        let (s, b) = claim(&fx, &newcomer(&fx), &wrong, &format!("10.9.1.{i}")).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("pairing_failed"))
        );
    }
    assert_eq!(
        pairing_status(&fx, normal["pairing_id"].as_str().unwrap()).await,
        "burned",
        "the budget burns a normal pairing"
    );
    let live_id = live["pairing_id"].as_str().unwrap();
    assert_eq!(
        pairing_status(&fx, live_id).await,
        "live",
        "but not an invite"
    );
    let (s, _) = claim(
        &fx,
        &newcomer(&fx),
        live["secret"].as_str().unwrap(),
        "10.9.3.1",
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "its secret still claims it");
}

/// The 0031 down migration ends live invites first: without the flag they would be plain
/// pairings that never expire. Applying it again leaves them burned.
#[tokio::test]
async fn the_down_migration_burns_live_invites() {
    use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};
    let fx = fx().await;
    let (_, made) = invite(&fx, &fx.dev, &["read"]).await;
    let id = made["pairing_id"].as_str().unwrap();
    undo(&fx.app.pool, CORE, CORE_MIGRATIONS, 30).await.unwrap();
    let status = || async {
        sqlx::query_scalar::<_, String>("SELECT status FROM core_pairings WHERE id = ?")
            .bind(id)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap()
    };
    assert_eq!(status().await, "burned");
    migrate_core(&fx.app.pool).await.unwrap();
    assert_eq!(status().await, "burned");
}

/// A rejected (withdrawn) invite is dead.
#[tokio::test]
async fn a_withdrawn_invite_is_refused() {
    let fx = fx().await;
    let (_, made) = invite(&fx, &fx.dev, &["read"]).await;
    let id = made["pairing_id"].as_str().unwrap();
    let uri = format!("/api/v1/pairings/{id}/reject");
    let (s, _) = send(
        &fx.app,
        req(Method::POST, &uri, Some(&fx.dev), Some(json!({}))),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = claim(
        &fx,
        &newcomer(&fx),
        made["secret"].as_str().unwrap(),
        "10.9.4.1",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// No expiry: ten years on, the sweep leaves the invite live and it still claims.
#[tokio::test]
async fn an_invite_is_never_swept() {
    let fx = fx().await;
    let (_, made) = invite(&fx, &fx.dev, &["read"]).await;
    let id = made["pairing_id"].as_str().unwrap();
    fx.clock.advance(10 * 365 * 86_400);
    let now = crate::scheduler::Clock::now(&*fx.clock);
    assert_eq!(expire_pairings(&fx.app.pool, &now).await.unwrap(), 0);
    assert_eq!(pairing_status(&fx, id).await, "live");
    let (s, _) = claim(
        &fx,
        &newcomer(&fx),
        made["secret"].as_str().unwrap(),
        "10.9.5.1",
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
}

/// The host's invite: refused beside a device; with none, claimed from the network with every
/// scope; a new one burns the unclaimed old one; a device enrolled meanwhile stops the claim.
#[tokio::test]
async fn the_host_invite_is_for_the_first_owner_only() {
    let fx = fx().await;
    assert!(host_invite(&fx).await.is_err(), "a device exists");
    sqlx::query("DELETE FROM core_devices")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let first = host_invite(&fx).await.unwrap();
    let second = host_invite(&fx).await.unwrap();
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'pairing.burned'"
        )
        .await,
        1
    );
    let (s, _) = claim(&fx, &newcomer(&fx), &first.secret, "10.9.6.1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "burned by the newer one");
    let owner = newcomer(&fx);
    let (s, got) = claim(&fx, &owner, &second.secret, "10.9.6.2").await;
    assert_eq!(s, StatusCode::ACCEPTED, "{got}");
    let row = gov::get_device(&fx.app.pool, got["device_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.status.as_str(), row.scopes.len()),
        ("active", ALL.len())
    );
    assert!(row.scopes.iter().any(|s| s == "admin"));

    // A device that appears between creation and claim stops the claim, in its transaction.
    sqlx::query("DELETE FROM core_pairings WHERE device_id IS NOT NULL")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM core_devices")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let third = host_invite(&fx).await.unwrap();
    let _meanwhile = fx.enroll("meanwhile", &["read"]).await;
    let (s, _) = claim(&fx, &newcomer(&fx), &third.secret, "10.9.6.3").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(count(&fx, "SELECT count(*) FROM core_devices").await, 1);
}

/// An admin's invite needs a step-up and never more than its creator's scopes.
#[tokio::test]
async fn an_admin_invite_needs_a_step_up_and_stays_within_the_creators_scopes() {
    let fx = fx().await;
    let cold = plain(&fx, "cold", &["admin", "read"], true).await;
    let (s, b) = invite(&fx, &cold, &["read"]).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("step_up_required"))
    );
    let reader = fx.enroll("reader", &["read"]).await;
    assert_eq!(
        invite(&fx, &reader, &["read"]).await.0,
        StatusCode::FORBIDDEN,
        "no admin"
    );
    let limited = fx.enroll("limited", &["admin", "read"]).await;
    let (s, b) = invite(&fx, &limited, &["read", "terminal"]).await;
    assert_eq!(
        (s, b["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden_scope"))
    );
    assert_eq!(
        invite(&fx, &limited, &["nonsense"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(invite(&fx, &limited, &[]).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(invite(&fx, &limited, &["read"]).await.0, StatusCode::OK);
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_pairings WHERE invite = 1").await,
        1
    );
}

/// The secret is in no audit row, no table and no log line, not even after the claim.
#[tokio::test]
async fn the_secret_is_in_no_audit_row_table_or_log() {
    let logs = Logs::default();
    let writer = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let fx = fx().await;
    let (_, made) = invite(&fx, &fx.dev, &["read"]).await;
    let secret = made["secret"].as_str().unwrap().to_owned();
    claim(&fx, &newcomer(&fx), &secret, "10.9.7.1").await;
    claim(&fx, &newcomer(&fx), &secret, "10.9.7.2").await;
    let rows: String =
        sqlx::query_scalar("SELECT group_concat(action || details, ' ') FROM audit_events")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    let table: String = sqlx::query_scalar(
        "SELECT group_concat(id || kind || name || scopes || ifnull(sas, ''), ' ') FROM core_pairings",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for (what, text) in [("audit", rows), ("table", table), ("log", logged)] {
        assert!(!text.contains(&secret), "the secret is in the {what}");
    }
}

fn revoke_by_hand() -> &'static str {
    "UPDATE core_devices SET revoked_at = '2026-10-22T10:00:00.000Z' WHERE id = ?"
}

/// Revoking the creator burns its live invites at once (not only at the next claim), audited.
#[tokio::test]
async fn revoking_the_creator_burns_its_live_invites() {
    let fx = fx().await;
    let admin = fx.enroll("admin", &["admin", "read"]).await;
    let (_, mine) = invite(&fx, &admin, &["read"]).await;
    let (_, other) = invite(&fx, &fx.dev, &["read"]).await;
    let by = ainkrad_core::audit::AuditActor::System;
    gov::revoke_device(&fx.app.pool, &admin.id, by, None, NOW)
        .await
        .unwrap();
    assert_eq!(
        pairing_status(&fx, mine["pairing_id"].as_str().unwrap()).await,
        "burned"
    );
    assert_eq!(
        pairing_status(&fx, other["pairing_id"].as_str().unwrap()).await,
        "live"
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'pairing.burned'"
        )
        .await,
        1
    );
    let (s, _) = claim(
        &fx,
        &newcomer(&fx),
        mine["secret"].as_str().unwrap(),
        "10.9.8.1",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// The claim re-checks the creator: revoked or narrowed behind the invite's back (no burn ran)
/// refuses the claim, enrols nothing and burns the invite.
#[tokio::test]
async fn a_claim_refuses_an_invite_whose_creator_no_longer_stands_behind_it() {
    let fx = fx().await;
    let before = count(&fx, "SELECT count(*) FROM core_devices").await;
    for case in ["revoked", "narrowed", "locked"] {
        let admin = fx.enroll(case, &["admin", "read", "terminal"]).await;
        let (_, made) = invite(&fx, &admin, &["read", "terminal"]).await;
        match case {
            "revoked" => sqlx::query(revoke_by_hand()).bind(&admin.id),
            "narrowed" => {
                sqlx::query("UPDATE core_devices SET scopes = '[\"admin\",\"read\"]' WHERE id = ?")
                    .bind(&admin.id)
            }
            _ => sqlx::query("UPDATE core_devices SET status = 'locked' WHERE id = ?")
                .bind(&admin.id),
        }
        .execute(&fx.app.pool)
        .await
        .unwrap();
        let (s, _) = claim(
            &fx,
            &newcomer(&fx),
            made["secret"].as_str().unwrap(),
            "10.9.9.1",
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{case}");
        assert_eq!(
            pairing_status(&fx, made["pairing_id"].as_str().unwrap()).await,
            "burned",
            "{case}"
        );
    }
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_devices").await,
        before + 3,
        "no claimant enrolled"
    );
}

/// N11: a claim may name the device; without a name the invite's own is kept; a bad name is
/// refused and spends nothing.
#[tokio::test]
async fn a_claim_may_name_its_device() {
    let fx = fx().await;
    let (_, made) = invite(&fx, &fx.dev, &["read"]).await;
    let secret = made["secret"].as_str().unwrap();
    let named = |dev: &TestDevice, name: Value| {
        let mut body = dev.claim_body(None, Some(secret));
        body["device_name"] = name;
        send(
            &fx.app,
            from(
                "203.0.113.9",
                req(Method::POST, "/pair/claim", None, Some(body)),
            ),
        )
    };
    for bad in [
        json!(""),
        json!("   "),
        json!("x".repeat(65)),
        json!("a\nb"),
    ] {
        let (s, got) = named(&newcomer(&fx), bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {got}");
    }
    let (s, got) = named(&newcomer(&fx), json!("  Ahmed's MacBook ")).await;
    assert_eq!(
        s,
        StatusCode::ACCEPTED,
        "the bad names spent nothing: {got}"
    );
    let row = gov::get_device(&fx.app.pool, got["device_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "Ahmed's MacBook");
    // No name: the invite's own.
    let (_, made) = invite(&fx, &fx.dev, &["read"]).await;
    let (s, got) = claim(
        &fx,
        &newcomer(&fx),
        made["secret"].as_str().unwrap(),
        "203.0.113.9",
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{got}");
    let row = gov::get_device(&fx.app.pool, got["device_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "Phone");
}
