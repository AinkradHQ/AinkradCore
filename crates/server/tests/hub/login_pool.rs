//! Subscription sign-in (KAN-441 L1): the pool rule, the one way to make a subscription account,
//! and the step-up on the routes that start a sign-in and send its code.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::api::v1::scopes::{declared, declared_destructive};
use ainkrad_core_server::store::secrets::Error;
use ainkrad_core_server::store::{accounts, pools};

use super::login::{TOKEN, W, refusal, up};

#[test]
fn a_sign_in_start_and_code_need_a_step_up_and_a_read_or_cancel_does_not() {
    for t in [
        "/api/v1/accounts/logins",
        "/api/v1/accounts/logins/{id}/code",
    ] {
        assert!(declared_destructive("POST", t), "{t}");
        assert_eq!(declared("POST", t), Some("admin"));
    }
    for (m, t) in [
        ("GET", "/api/v1/accounts/logins/{id}"),
        ("DELETE", "/api/v1/accounts/logins/{id}"),
    ] {
        assert!(!declared_destructive(m, t), "{m} {t}");
        assert_eq!(declared(m, t), Some("admin"));
    }
}

async fn mk(w: &W, label: &str, provider: &str, value: &str) -> Result<accounts::Account, Error> {
    let runners = [w.runner.clone()];
    let new = accounts::NewAccount {
        provider,
        label,
        value,
        runners: &runners,
        cap: None,
    };
    let sealer = w.core.app.secrets.as_deref().unwrap();
    let now = w.core.app.clock.now();
    accounts::create_by(
        &w.core.app.pool,
        sealer,
        &new,
        "subscription",
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
}

#[tokio::test]
async fn a_subscription_account_is_alone_in_its_pool_and_its_token_has_its_own_shape() {
    let w = up("login-pool", true, true).await;
    let (pool, now) = (&w.core.app.pool, w.core.app.clock.now());
    let a = mk(&w, "sub-a", "claude-sub", TOKEN).await.unwrap();
    let b = mk(
        &w,
        "sub-b",
        "claude-sub",
        "sk-ant-oat01-TESTONLYsecondtokenvalue123456",
    )
    .await
    .unwrap();
    // Only an `sk-ant-oat01-` token is a subscription's.
    let api = "sk-ant-api03-TESTONLYapikeyvalue0123456789abcdef";
    let bad = mk(&w, "sub-c", "claude-sub", api).await;
    assert_eq!(refusal(bad).0, "bad_request");
    let claude = pools::create(
        pool,
        "claude-subs",
        "claude-sub",
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    let with_a = pools::add_member(pool, claude.id, a.id, &w.runner, AuditActor::System, &now)
        .await
        .unwrap();
    assert_eq!(with_a.members, [a.id]);
    let r = pools::add_member(pool, claude.id, b.id, &w.runner, AuditActor::System, &now).await;
    assert_eq!(refusal(r).0, "subscription_pool_alone");
    // No other provider's account joins it either (its provider differs).
    let key = mk(
        &w,
        "api-key",
        "anthropic",
        "throwaway-account-value-one-5a91c3",
    )
    .await
    .unwrap();
    let r = pools::add_member(pool, claude.id, key.id, &w.runner, AuditActor::System, &now).await;
    assert!(r.is_err());
    // A second subscription has its own pool; a pool of one subscription is not bound to an agent.
    let second = pools::create(
        pool,
        "claude-subs-b",
        "claude-sub",
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    pools::add_member(pool, second.id, b.id, &w.runner, AuditActor::System, &now)
        .await
        .unwrap();
    let r = pools::bind(
        pool,
        "agent-1",
        claude.id,
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await;
    assert_eq!(refusal(r).0, "bad_request");
    // The API-key providers' pools are as before.
    let anthropic = pools::create(
        pool,
        "main",
        "anthropic",
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    pools::add_member(
        pool,
        anthropic.id,
        key.id,
        &w.runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
}
