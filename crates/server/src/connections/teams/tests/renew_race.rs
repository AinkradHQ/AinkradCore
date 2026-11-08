//! Renewing against a person who signs in meanwhile, a verdict about an old credential, and an app
//! pinned to another tenant.

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::*;
use crate::connections::teams::{CallError, unpack};
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
    f.fake.on("token", |_| Reply::dead_grant().delayed(200));
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

#[tokio::test]
async fn an_app_pinned_to_another_tenant_renews_nothing_and_signals_nothing() {
    let f = fx(true).await;
    let served = f.fake.rotating();
    let c = due(&f).await;
    // The app is narrowed to a tenant that is not the connection's.
    assert!(f.teams.set_app(TeamsApp::new(CLIENT, OTHER_TENANT)));
    let e = f
        .teams
        .fresh(&f.cx(NOW), c.id)
        .await
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e, CallError::TenantNotAllowed);
    assert_eq!((e.health(), e.code()), (None, "tenant_not_allowed"));
    assert_eq!(served.load(Ordering::SeqCst), 0);
    assert_eq!(f.fake.count("token"), 0, "no request at all");
    let t = f.teams.test_connection(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(t.status, "active", "no verdict: {:?}", t.state_reason);
    // Pinned to its own tenant, or not pinned, it renews.
    assert!(f.teams.set_app(TeamsApp::new(CLIENT, TENANT)));
    f.teams.fresh(&f.cx(NOW), c.id).await.unwrap();
    assert_eq!(served.load(Ordering::SeqCst), 1);
}
