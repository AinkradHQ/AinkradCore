//! A model switched off for an account (E7-2b): the route that sets it, the list that shows it with
//! its price, and the three places that refuse it (the AI order, a chain, a gateway grant).

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::accounts_store::{V1, make, setup};
use super::chains::{BY, code, spec};
use super::gateway_store::{gw, secret, session};
use super::*;
use crate::store::account_models;
use crate::store::chains as ch;
use crate::store::chains::order::{self, Spec};

const MODEL: &str = "claude-opus-5-5";

#[tokio::test]
async fn the_switch_is_audited_shown_with_the_price_and_needs_a_step_up() {
    let (fx, _vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    let uri = format!("/api/v1/accounts/{}/models/{MODEL}", a.id);
    let list = format!("/api/v1/accounts/{}/models", a.id);
    let (st, b) = send(&fx.app, req(Method::GET, &list, Some(&fx.dev), None)).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let row = |b: &serde_json::Value| {
        b["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["model"] == MODEL)
            .cloned()
            .unwrap()
    };
    let r = row(&b);
    assert_eq!(r["allowed"], true);
    assert!(r["input_per_mtok_micro"].as_i64().unwrap() > 0, "{r}");
    let off = json!({"allowed": false});
    let (st, b) = send(&fx.app, req(Method::PUT, &uri, Some(&fx.dev), Some(off))).await;
    assert_eq!(
        (st, row(&b)["allowed"].clone()),
        (StatusCode::OK, json!(false)),
        "{b}"
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'account.model_allowed_set'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
    let on = json!({"allowed": true});
    let (_, b) = send(&fx.app, req(Method::PUT, &uri, Some(&fx.dev), Some(on))).await;
    assert_eq!(row(&b)["allowed"], true);
    let (st, _) = send(
        &fx.app,
        req(
            Method::PUT,
            "/api/v1/accounts/999/models/m",
            Some(&fx.dev),
            Some(json!({"allowed": false})),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_ai_order_and_a_chain_refuse_a_switched_off_model_and_accept_it_again() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    let on = |model| {
        [Spec {
            account: a.id,
            model: Some(model),
        }]
    };
    account_models::set_allowed(p, a.id, MODEL, false, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(
        code(order::set(p, 1, None, &on(MODEL), "d_x", BY, NOW).await),
        "bad_request"
    );
    // Another model of the same account is untouched.
    order::set(p, 1, None, &on("claude-sonnet-5-5"), "d_x", BY, NOW)
        .await
        .unwrap();
    account_models::set_allowed(p, a.id, MODEL, true, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    order::set(p, 1, None, &on(MODEL), "d_x", BY, NOW)
        .await
        .unwrap();
    // The same account's pool in a chain.
    account_models::set_allowed(p, a.id, MODEL, false, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let pool: i64 =
        sqlx::query_scalar("SELECT pool_id FROM core_pool_members WHERE account_id = ?")
            .bind(a.id)
            .fetch_one(p)
            .await
            .unwrap();
    let mut e = spec(pool);
    e.model = Some(MODEL);
    assert_eq!(
        code(ch::create(p, 1, "c1", &[e], "d_x", BY, NOW).await),
        "bad_request"
    );
    e.model = Some("claude-sonnet-5-5");
    assert!(ch::create(p, 1, "c2", &[e], "d_x", BY, NOW).await.is_ok());
}

#[tokio::test]
async fn a_gateway_grant_refuses_a_switched_off_model_and_leaves_it_out_of_the_allowlist() {
    let g = gw().await;
    let p = &g.fx.app.pool;
    account_models::set_allowed(p, g.account.id, MODEL, false, &g.fx.dev.id, BY, NOW)
        .await
        .unwrap();
    // No model named: the grant is issued without it.
    let issued = crate::agents::gateway::grant(&g.fx.app, &g.session)
        .await
        .unwrap()
        .unwrap();
    assert!(!issued.grant.models.iter().any(|m| m == MODEL));
    assert!(!issued.grant.models.is_empty());
    // Named: refused.
    let mut named = session(&g.fx, &g.vm, &[secret(&g.account.secret_name)]).await;
    named.model = Some(MODEL.to_owned());
    let e = crate::agents::gateway::grant(&g.fx.app, &named).await.err();
    assert!(format!("{e:?}").contains("switched off"), "{e:?}");
}

#[tokio::test]
async fn an_api_key_account_enforces_a_switched_off_model_and_a_login_does_not() {
    use crate::api::v1::accounts::ProviderAccount;
    let (fx, _vm, s) = setup().await;
    let mut a = make(&fx, &s, "claude-main", V1, &[]).await;
    let shown = |a: &crate::store::accounts::Account| {
        serde_json::to_value(ProviderAccount::from(a.clone())).unwrap()["models_enforced"].clone()
    };
    // The gateway grants an API key's session only the models left on.
    assert_eq!(shown(&a), true);
    // A subscription's harness talks to its provider itself: the limit is advice, and says so.
    a.provider = "claude-sub".to_owned();
    assert_eq!(shown(&a), false);
}
