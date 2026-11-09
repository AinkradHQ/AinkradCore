//! Review follow-ups for the account store: the general secrets routes leave account keys
//! alone, a missing broker secret never strands an account, a pasted key is trimmed, and an
//! account id (so its secret name) is never reused.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::accounts_store::{V1, V2, code, make, setup};
use super::*;
use crate::store::accounts as acc;
use crate::store::secrets as st;

async fn route(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(&fx.dev), body)).await
}

#[tokio::test]
async fn the_general_secrets_routes_refuse_account_names() {
    let (mut fx, _vm, s) = setup().await;
    fx.app.secrets = Some(Arc::new(crate::ops::secretbox::SecretBox::new(&[7; 32])));
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    let uri = format!("/api/v1/secrets/{}", a.secret_name);
    let bad = StatusCode::BAD_REQUEST;
    // Squatting the next account's name, re-keying behind the account's back, deleting its key.
    let next = format!("acct.anthropic.{}", a.id + 1);
    let r = route(
        &fx,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": next, "value": V2}),
    )
    .await;
    assert_eq!(
        (r.0, r.1["code"].as_str()),
        (bad, Some("bad_request")),
        "{}",
        r.1
    );
    let r = route(&fx, Method::PUT, &uri, json!({"value": V2})).await;
    assert_eq!(r.0, bad, "{}", r.1);
    let r = route(&fx, Method::DELETE, &uri, Value::Null).await;
    assert_eq!(r.0, bad, "{}", r.1);
    // Nothing moved: the account, its key (version 1) and its audit trail are as they were.
    assert_eq!(acc::get(&fx.app.pool, a.id).await.unwrap(), a);
    let secrets = st::list(&fx.app.pool).await.unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].version, 1);
    // Other names still go through the general routes.
    let r = route(
        &fx,
        Method::POST,
        "/api/v1/secrets",
        json!({"name": "git.token", "value": V2}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
}

#[tokio::test]
async fn a_missing_broker_secret_does_not_strand_the_account() {
    let (fx, vm, s) = setup().await;
    let p = &fx.app.pool;
    let by = (&fx.dev.id, super::super::BY);
    // Re-key: the secret is gone (a stripped restore), so the new key creates it.
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    sqlx::query("DELETE FROM core_secrets")
        .execute(p)
        .await
        .unwrap();
    let b = acc::replace_secret(
        p,
        &s,
        a.id,
        V2,
        Some(std::slice::from_ref(&vm.id)),
        by.0,
        by.1,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        (b.masked_tail.as_str(), b.runners),
        (&V2[V2.len() - 4..], vec![vm.id])
    );
    assert_eq!(st::list(p).await.unwrap().len(), 1);
    // Delete: the secret is gone again, and the account still goes, label freed.
    sqlx::query("DELETE FROM core_secrets")
        .execute(p)
        .await
        .unwrap();
    acc::delete(p, a.id, by.0, by.1).await.unwrap();
    assert!(acc::list(p).await.unwrap().is_empty());
    make(&fx, &s, "claude-main", V1, &[]).await;
}

#[tokio::test]
async fn a_pasted_key_is_trimmed_before_it_is_sealed_and_its_tail_cut() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "claude-main", &format!("{V1}\n"), &[]).await;
    assert_eq!(a.masked_tail, &V1[V1.len() - 4..]);
    let size: i64 = sqlx::query_scalar("SELECT size FROM core_secrets")
        .fetch_one(p)
        .await
        .unwrap();
    assert_eq!(size, V1.len() as i64);
    let b = acc::replace_secret(
        p,
        &s,
        a.id,
        &format!("  {V2}\r\n"),
        None,
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(b.masked_tail, &V2[V2.len() - 4..]);
    let size: i64 = sqlx::query_scalar("SELECT size FROM core_secrets")
        .fetch_one(p)
        .await
        .unwrap();
    assert_eq!(size, V2.len() as i64);
}

#[tokio::test]
async fn an_account_id_and_its_secret_name_are_never_reused() {
    let (fx, _vm, s) = setup().await;
    let p = &fx.app.pool;
    let a = make(&fx, &s, "one", V1, &[]).await;
    acc::delete(p, a.id, &fx.dev.id, super::super::BY)
        .await
        .unwrap();
    let b = make(&fx, &s, "two", V1, &[]).await;
    assert!(b.id > a.id, "{} then {}", a.id, b.id);
    assert_ne!(a.secret_name, b.secret_name);
    assert_eq!(code(acc::get(p, a.id).await), "not_found");
}
