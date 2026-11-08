//! Renewing the access token: rotation, single flight, no loop, the verdicts, a person's
//! credential that wins a race, a lost caller that must not lose the rotated token, and an app
//! whose registration is wrong.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ainkrad_proto::v2::UpstreamStatus;
use serde_json::json;

use super::*;
use crate::connections::teams::{CallError, unpack};
use crate::store::connections::health::{self, Signal};
use crate::store::connections::{get, secret};

const NEW_ACCESS: &str = "acc9-graphtok-0009-aaaaaaaa";
const NEW_REFRESH: &str = "ref9-refreshtok-0009-bbbbbbbb";

async fn due(f: &Fx) -> Connection {
    f.connect("acme", &material(ACCESS, REFRESH, 10)).await
}

async fn stored(f: &Fx, id: i64) -> (String, String, Option<String>) {
    let m = secret::open(&f.pool, &f.sealer, 1, id).await.unwrap().0;
    let c = unpack(&m).unwrap();
    let access = c.secrets().remove(0);
    (access, c.refresh().to_owned(), m.expires_at)
}

#[tokio::test]
async fn concurrent_renewals_spend_the_refresh_token_once() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = due(&f).await;
    let cx = f.cx(NOW);
    let (a, b, d) = tokio::join!(
        f.teams.fresh(&cx, c.id),
        f.teams.fresh(&cx, c.id),
        f.teams.fresh(&cx, c.id)
    );
    for m in [a.unwrap(), b.unwrap(), d.unwrap()] {
        let cred = unpack(&m).unwrap();
        assert_eq!((cred.secrets()[0].as_str(), cred.refresh()), (ACC2, REF2));
    }
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "single-flight: one refresh, not three"
    );
    let (access, refresh, expires) = stored(&f, c.id).await;
    assert_eq!(
        (access.as_str(), refresh.as_str()),
        (ACC2, REF2),
        "the rotated token is sealed"
    );
    assert_eq!(expires.as_deref(), Some(at(3599).as_str()));
    // Not due any more: nothing is spent. Due again later: the NEW refresh token is used.
    f.teams.fresh(&cx, c.id).await.unwrap();
    assert_eq!(f.fake.count("token"), 1);
    let later = at(10_000);
    let m = f.teams.fresh(&f.cx(&later), c.id).await.unwrap();
    assert_eq!(
        unpack(&m).unwrap().refresh(),
        "ref3-refreshtok-0003-bbbbbbbb"
    );
    assert_eq!(
        f.fake.bad(),
        0,
        "a form with no secret and no Authorization"
    );
    let sent = f.fake.last("token").unwrap();
    assert_eq!(
        sent.params,
        json!({"grant_type": "refresh_token", "refresh_token": REF2, "client_id": CLIENT,
            "scope": SCOPES})
    );
    // The refresh goes to the connection's own tenant, not the app's.
    assert!(
        sent.path.starts_with(&format!("/{TENANT}/")),
        "{}",
        sent.path
    );
}

#[tokio::test]
async fn an_answer_without_a_new_refresh_token_keeps_the_old_one() {
    let f = fx(true).await;
    f.fake.reply(
        "token",
        Reply::ok(json!({"access_token": NEW_ACCESS, "expires_in": 3599})),
    );
    let c = due(&f).await;
    f.teams.fresh(&f.cx(NOW), c.id).await.unwrap();
    let (access, refresh, _) = stored(&f, c.id).await;
    assert_eq!((access.as_str(), refresh.as_str()), (NEW_ACCESS, REFRESH));
    // An answer with no access token, or an unusable one, stores nothing.
    for body in [
        json!({"expires_in": 3599}),
        json!({"access_token": "short", "expires_in": 3599}),
    ] {
        let g = fx(true).await;
        g.fake.reply("token", Reply::ok(body));
        let c = due(&g).await;
        let e = g
            .teams
            .fresh(&g.cx(NOW), c.id)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            matches!(e, CallError::Upstream(200) | CallError::Internal(_)),
            "{e:?}"
        );
        assert_eq!(stored(&g, c.id).await.0, ACCESS);
    }
}

#[tokio::test]
async fn an_id_token_for_another_tenant_is_refused_and_stores_nothing() {
    let f = fx(true).await;
    f.fake.reply(
        "token",
        Reply::ok(
            json!({"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH,
            "expires_in": 3599, "id_token": id_token(CLIENT, OTHER_TENANT)}),
        ),
    );
    let c = due(&f).await;
    let e = f
        .teams
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(e, CallError::Internal(_)), "{e:?}");
    assert_eq!(stored(&f, c.id).await.1, REFRESH);
}

#[tokio::test]
async fn only_invalid_grant_condemns_a_refresh_token() {
    let f = fx(true).await;
    let c = due(&f).await;
    let wrong_secret = Reply::http(
        401,
        json!({"error": "invalid_client", "error_codes": [7000215],
            "error_description": "AADSTS7000215: Invalid client secret provided."}),
    );
    let cases = [
        (Reply::entra(400, "invalid_grant"), CallError::AuthFailed),
        (Reply::entra(401, "invalid_grant"), CallError::AuthFailed),
        (wrong_secret, CallError::AppConfig),
        (Reply::entra(400, "invalid_client"), CallError::AppConfig),
        (
            Reply::entra(400, "unauthorized_client"),
            CallError::AppConfig,
        ),
        (Reply::entra(400, "invalid_scope"), CallError::AppConfig),
        (
            Reply::entra(400, "interaction_required"),
            CallError::InteractionRequired,
        ),
        (
            Reply::entra(400, "consent_required"),
            CallError::InteractionRequired,
        ),
        (
            Reply::entra(400, "login_required"),
            CallError::InteractionRequired,
        ),
        // The request being wrong in some other way is no verdict.
        (
            Reply::entra(400, "invalid_request"),
            CallError::BadRequest(400),
        ),
        // An edge or a proxy answering 401 or 403 says nothing about THIS credential.
        (Reply::http(401, json!({})), CallError::Forbidden),
        (Reply::http(403, json!("<html>")), CallError::Forbidden),
        (
            Reply::http(429, json!({})),
            CallError::RateLimited { retry_after: None },
        ),
        (Reply::http(503, json!({})), CallError::Upstream(503)),
        // A 5xx that carries invalid_grant is still Microsoft's outage.
        (Reply::entra(500, "invalid_grant"), CallError::Upstream(500)),
        (Reply::http(200, json!({})), CallError::Upstream(200)),
    ];
    for (reply, want) in cases {
        f.fake.reply("token", reply.clone());
        let got = f.teams.fresh(&f.cx(NOW), c.id).await.map(|_| ());
        assert_eq!(got, Err(want.clone()), "{} {}", reply.status, reply.body);
        if want != CallError::AuthFailed {
            assert!(
                want.health()
                    .is_none_or(|(s, _)| s != UpstreamStatus::AuthFailed),
                "{want:?}"
            );
        }
    }
    assert_eq!(
        stored(&f, c.id).await.1,
        REFRESH,
        "a failed refresh leaves the credential as it was"
    );
    assert_eq!(f.fake.bad(), 0);
}

#[tokio::test]
async fn without_an_app_an_expired_token_cannot_be_renewed() {
    let f = fx(false).await;
    f.fake.rotating();
    let c = due(&f).await;
    let e = f
        .teams
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::OAuthNotConfigured);
    // No app configured says nothing about the credential: no health signal, a plain code.
    assert_eq!((e.health(), e.code()), (None, "not_configured"));
    assert_eq!(f.fake.count("token"), 0);
    let live = f.connect("live", &material(ACCESS, REFRESH, 3600)).await;
    f.teams.fresh(&f.cx(NOW), live.id).await.unwrap();
}

async fn suspect(f: &Fx, id: i64) {
    let signal = Signal::Upstream {
        status: UpstreamStatus::AuthFailed,
        retry_after: None,
        reset_at: None,
    };
    health::signal(&f.pool, 1, id, signal, NOW).await.unwrap();
}

#[tokio::test]
async fn a_renewal_does_not_clear_a_pending_auth_failure() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = due(&f).await;
    suspect(&f, c.id).await;
    assert_eq!(
        get(&f.pool, 1, c.id).await.unwrap().state_reason.as_deref(),
        Some("auth_suspected")
    );
    f.teams.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(served.load(Ordering::SeqCst), 1);
    let after = get(&f.pool, 1, c.id).await.unwrap();
    assert_eq!(
        after.state_reason.as_deref(),
        Some("auth_suspected"),
        "only a test clears it"
    );
    assert_ne!(after.status, "active");
}

#[tokio::test]
async fn a_caller_that_is_dropped_mid_renewal_cannot_lose_the_rotated_token() {
    let f = fx(true).await;
    f.fake.rotating();
    let c = due(&f).await;
    let cx = f.cx(NOW);
    let dropped = tokio::time::timeout(Duration::from_millis(40), f.teams.fresh(&cx, c.id)).await;
    assert!(
        dropped.is_err(),
        "the caller gave up while the token endpoint was answering"
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        stored(&f, c.id).await.1,
        REF2,
        "the rotated refresh token was sealed"
    );
}

#[tokio::test]
async fn the_lock_map_does_not_grow_with_every_connection_renewed() {
    let f = fx(true).await;
    f.fake.reply(
        "token",
        Reply::ok(
            json!({"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH, "expires_in": 3599}),
        ),
    );
    for name in ["a1", "b1", "c1", "d1"] {
        let c = f.connect(name, &material(ACCESS, REFRESH, 10)).await;
        f.teams.fresh(&f.cx(NOW), c.id).await.unwrap();
    }
    assert!(f.teams.locks.lock().unwrap().len() <= 1);
}

#[tokio::test]
async fn a_renewal_microsoft_refuses_is_a_conclusive_rejection_and_a_failure_is_not() {
    let f = fx(true).await;
    f.fake.reply("token", Reply::entra(400, "invalid_grant"));
    let c = due(&f).await;
    let t = f.teams.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(
        (t.status.as_str(), t.state_reason.as_deref()),
        ("disabled", Some("auth_failed"))
    );
    for reply in [
        Reply::http(503, json!({})),
        Reply::entra(400, "invalid_client"),
        Reply::entra(400, "interaction_required"),
        Reply::http(429, json!({})),
    ] {
        let g = fx(true).await;
        g.fake.reply("token", reply.clone());
        let c = due(&g).await;
        let t = g.teams.test_connection(&g.cx(NOW), c.id).await.unwrap();
        assert_eq!(t.status, "active", "{} {}", reply.status, reply.body);
    }
    let g = fx(true).await;
    g.fake.rotating();
    let c = due(&g).await;
    let t = g.teams.test_connection(&g.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.identity, Some(format!("{USER} in {TENANT}")));
    let sent = g.fake.last("me").unwrap();
    assert_eq!(
        sent.auth,
        Some(format!("Bearer {ACC2}")),
        "tested with the renewed token"
    );
}

#[tokio::test]
async fn a_wrong_client_id_disables_no_connection_and_a_corrected_one_renews() {
    let f = fx(true).await;
    // Microsoft only knows the NEW client id.
    f.fake.on("token", |s| {
        if s.params["client_id"] == "new-client-5f3a" {
            Reply::ok(json!({"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH, "expires_in": 3599}))
        } else {
            Reply::entra(400, "unauthorized_client")
        }
    });
    let c = due(&f).await;
    let t = f.teams.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.status, "active", "{:?}", t.state_reason);
    assert_ne!(t.state_reason.as_deref(), Some("auth_failed"));
    let e = f
        .teams
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!((e.clone(), e.health()), (CallError::AppConfig, None));
    assert!(
        f.teams
            .set_app(TeamsApp::new("new-client-5f3a", "organizations"))
    );
    f.teams.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(stored(&f, c.id).await.1, NEW_REFRESH);
    assert_eq!(
        f.fake.last("token").unwrap().params["refresh_token"],
        REFRESH
    );
}

#[tokio::test]
async fn a_credential_a_person_stores_meanwhile_wins_over_a_renewal() {
    let f = fx(true).await;
    f.fake.rotating();
    let c = due(&f).await;
    let (t, pool, sealer) = (f.teams.clone(), f.pool.clone(), f.sealer.clone());
    let renewing = tokio::spawn(async move {
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now: NOW,
        };
        let cx = Ctx {
            pool: &pool,
            sealer: &sealer,
            who,
        };
        t.fresh(&cx, c.id).await
    });
    // While the token endpoint is still answering (it takes 150 ms), a person signs in again.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let theirs = material(NEW_ACCESS, NEW_REFRESH, 3600);
    secret::replace(&f.pool, &f.sealer, c.id, &theirs, f.cx(NOW).who)
        .await
        .unwrap();
    let got = renewing.await.unwrap().unwrap();
    assert_eq!(
        unpack(&got).unwrap().secrets()[0],
        NEW_ACCESS,
        "the renewal hands back what is stored now"
    );
    let (access, refresh, _) = stored(&f, c.id).await;
    assert_eq!(
        (access.as_str(), refresh.as_str()),
        (NEW_ACCESS, NEW_REFRESH)
    );
}

#[tokio::test]
async fn a_verdict_about_an_old_credential_cannot_settle_a_new_one() {
    let f = fx(true).await;
    // The old refresh token is refused, slowly.
    f.fake
        .on("token", |_| Reply::entra(400, "invalid_grant").delayed(200));
    let c = due(&f).await;
    let (t, pool, sealer, id) = (f.teams.clone(), f.pool.clone(), f.sealer.clone(), c.id);
    let testing = tokio::spawn(async move {
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now: NOW,
        };
        let cx = Ctx {
            pool: &pool,
            sealer: &sealer,
            who,
        };
        t.test_connection(&cx, id).await
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    let theirs = material(NEW_ACCESS, NEW_REFRESH, 3600);
    secret::replace(&f.pool, &f.sealer, c.id, &theirs, f.cx(NOW).who)
        .await
        .unwrap();
    let t = testing.await.unwrap().unwrap();
    assert_ne!(
        t.status, "disabled",
        "the refusal was about the credential that was replaced"
    );
    let now = get(&f.pool, 1, c.id).await.unwrap();
    assert_ne!(now.state_reason.as_deref(), Some("auth_failed"));
}
