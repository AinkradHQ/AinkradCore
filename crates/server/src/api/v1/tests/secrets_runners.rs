//! `secrets::set_runners_in`: a secret's own runner scope changes alone (no new version, no
//! value), only to active runners, with the old leases dropped and one audit row per change.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::secrets::{V1, broker, call, create, lease, redeem, runner, set};
use super::*;
use crate::store::secrets as st;
use ainkrad_core::settings::Key;

async fn set_scope(fx: &Fx, name: &str, runners: &[String]) -> Result<bool, st::Error> {
    let mut tx = crate::store::begin_write(&fx.app.pool).await.unwrap();
    let r = st::set_runners_in(&mut tx, name, runners, "d_test", super::super::BY, NOW).await;
    if r.is_ok() {
        tx.commit().await.unwrap();
    }
    r
}

async fn changes(fx: &Fx) -> Vec<serde_json::Value> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'secret.runners_changed' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    rows.iter()
        .map(|r| serde_json::from_str(r).unwrap())
        .collect()
}

fn refusal(r: Result<bool, st::Error>) -> String {
    match r {
        Err(st::Error::Refused { code, .. }) => code.to_owned(),
        other => format!("not a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn the_scope_changes_alone_and_an_equal_set_writes_nothing() {
    let (fx, vm) = broker().await;
    let r2 = runner(&fx, "vm2").await;
    assert_eq!(
        create(&fx, "git.token", V1, &[&vm.id]).await.0,
        StatusCode::OK
    );
    let mut both = vec![vm.id.clone(), r2.id.clone()];
    both.sort();
    // Reversed on purpose: the stored list is sorted.
    let reversed: Vec<String> = both.iter().rev().cloned().collect();
    assert!(set_scope(&fx, "git.token", &reversed).await.unwrap());
    let listed = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/secrets",
        serde_json::Value::Null,
    )
    .await;
    let s = &listed.1.as_array().unwrap()[0];
    assert_eq!(s["runners"], json!(both));
    assert_eq!(s["version"], 1, "no new version");
    // The same set in another order is no change: no write, no audit row.
    assert!(!set_scope(&fx, "git.token", &both).await.unwrap());
    let rows = changes(&fx).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "git.token");
    assert_eq!(rows[0]["runners"], json!(both));
    assert_eq!(rows[0]["leases_revoked"], 0);
    assert_eq!(rows[0]["by_device"], "d_test");
    // The value is as it was: a lease under the new scope redeems it.
    let l = lease(&fx, "git.token", &r2.id, Some(30)).await;
    assert_eq!(redeem(&fx, &r2, &l.1).await.1["value"], V1);
}

#[tokio::test]
async fn a_changed_scope_drops_the_outstanding_leases() {
    let (fx, vm) = broker().await;
    let r2 = runner(&fx, "vm2").await;
    create(&fx, "git.token", V1, &[&vm.id, &r2.id]).await;
    let l = lease(&fx, "git.token", &vm.id, Some(30)).await;
    assert_eq!(l.0, StatusCode::OK);
    assert!(
        set_scope(&fx, "git.token", std::slice::from_ref(&r2.id))
            .await
            .unwrap()
    );
    assert_eq!(changes(&fx).await[0]["leases_revoked"], 1);
    // The runner that was taken off the scope can no longer redeem what it was granted.
    assert_eq!(redeem(&fx, &vm, &l.1).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        lease(&fx, "git.token", &vm.id, None).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn narrowing_works_with_the_broker_off() {
    let (fx, vm) = broker().await;
    create(&fx, "git.token", V1, &[&vm.id]).await;
    set(&fx, Key::SecretsMode, 0).await;
    assert!(set_scope(&fx, "git.token", &[]).await.unwrap());
    assert_eq!(changes(&fx).await.len(), 1);
}

#[tokio::test]
async fn a_missing_secret_a_non_runner_and_a_repeat_are_refused_and_change_nothing() {
    let (fx, vm) = broker().await;
    create(&fx, "git.token", V1, &[&vm.id]).await;
    assert_eq!(refusal(set_scope(&fx, "no.such", &[]).await), "not_found");
    let unknown = ["d_not-a-runner".to_owned()];
    assert_eq!(
        refusal(set_scope(&fx, "git.token", &unknown).await),
        "bad_request"
    );
    let twice = [vm.id.clone(), vm.id.clone()];
    assert_eq!(
        refusal(set_scope(&fx, "git.token", &twice).await),
        "bad_request"
    );
    // A revoked runner is not an active runner.
    let gone = runner(&fx, "gone").await;
    sqlx::query("UPDATE core_devices SET revoked_at = ? WHERE id = ?")
        .bind(NOW)
        .bind(&gone.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        refusal(set_scope(&fx, "git.token", std::slice::from_ref(&gone.id)).await),
        "bad_request"
    );
    assert!(changes(&fx).await.is_empty());
    let runners: String =
        sqlx::query_scalar("SELECT runners FROM core_secrets WHERE name = 'git.token'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(runners, json!([vm.id]).to_string());
}
