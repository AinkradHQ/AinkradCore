//! `claude` in a terminal signs in with the opener's accounts (0.10.5): the first Claude plan of the
//! AI order that can take work is leased as env to the runner hosting the terminal, and only to it;
//! an API-key account and a turned-off plan are skipped; nothing usable is a plain `no_account`;
//! each use is listed with the account's sessions, marked as a terminal. Fake tokens only.

use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::accounts as acc;
use crate::store::chains::order;

const BY: ainkrad_core::audit::AuditActor = super::super::BY;
const TOKEN: &str = "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop";

async fn setup() -> (Fx, TestDevice) {
    let mut fx = fx().await;
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    for k in [Key::SecretsMode, Key::SecretsProviderAccounts] {
        crate::store::settings::set(&fx.app.pool, k, Scope::Server, "1", BY, NOW)
            .await
            .unwrap();
    }
    let vm = super::secrets::runner(&fx, "vm").await;
    (fx, vm)
}

async fn account(fx: &Fx, vm: &TestDevice, provider: &str, value: &str) -> acc::Account {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let label = format!(
        "{provider}-{}",
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let runners = [vm.id.clone()];
    let new = acc::NewAccount {
        provider,
        label: &label,
        value,
        runners: &runners,
        cap: None,
        display_name: None,
    };
    let method = if provider == "claude-sub" {
        "subscription"
    } else {
        "api_key"
    };
    let sealer = fx.app.secrets.clone().unwrap();
    acc::create_by(&fx.app.pool, &sealer, &new, method, &fx.dev.id, BY, NOW)
        .await
        .unwrap_or_else(|e| panic!("{label}: {e}"))
}

async fn set_order(fx: &Fx, ids: &[i64]) {
    let specs: Vec<order::Spec<'_>> = ids
        .iter()
        .map(|&account| order::Spec {
            account,
            model: None,
        })
        .collect();
    order::set(&fx.app.pool, 1, None, &specs, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
}

async fn terminal(fx: &Fx, id: &str, runner: &str, status: &str) {
    sqlx::query(
        "INSERT INTO core_terminals (id, runner, status, rows, cols, opened_by, created_at, \
         last_activity) VALUES (?, ?, ?, 24, 80, ?, ?, 0)",
    )
    .bind(id)
    .bind(runner)
    .bind(status)
    .bind(&fx.dev.id)
    .bind(NOW)
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

async fn ask(fx: &Fx, dev: &TestDevice, id: &str, tool: &str) -> (StatusCode, Value) {
    let uri = format!("/api/v1/runner/terminals/{id}/account");
    send(
        &fx.app,
        req(Method::POST, &uri, Some(dev), Some(json!({"tool": tool}))),
    )
    .await
}

#[tokio::test]
async fn the_first_usable_plan_is_leased_to_the_terminals_runner_and_listed() {
    let (fx, vm) = setup().await;
    let key = account(&fx, &vm, "anthropic", "throwaway-acct-value-one-5a91c3").await;
    let off = account(&fx, &vm, "claude-sub", TOKEN).await;
    let plan = account(&fx, &vm, "claude-sub", TOKEN).await;
    set_order(&fx, &[key.id, off.id, plan.id]).await;
    acc::set_state(
        &fx.app.pool,
        off.id,
        "disabled",
        None,
        None,
        &fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap();
    terminal(&fx, "t_one", &vm.id, "running").await;
    let (st, v) = ask(&fx, &vm, "t_one", "claude").await;
    assert_eq!(st, StatusCode::OK, "{v}");
    assert_eq!(
        v["account"], plan.id,
        "the API key and the turned-off plan are skipped"
    );
    assert_eq!(v["var"], "CLAUDE_CODE_OAUTH_TOKEN");
    assert!(!v.to_string().contains(TOKEN), "a lease, never the token");
    // The runner redeems it like any lease: the plan's own token, under the account's name.
    let r = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/secret-leases/redeem",
            Some(&vm),
            Some(json!({"lease": v["lease"]})),
        ),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        (&r.1["value"], &r.1["name"]),
        (&json!(TOKEN), &json!(plan.secret_name))
    );
    let uri = format!("/api/v1/accounts/{}/sessions", plan.id);
    let (st, list) = send(&fx.app, req(Method::GET, &uri, Some(&fx.dev), None)).await;
    assert_eq!(st, StatusCode::OK, "{list}");
    assert_eq!(list[0]["terminal"], "t_one", "{list}");
    assert_eq!(list[0]["title"], "claude in a terminal");
}

#[tokio::test]
async fn only_the_hosting_runner_of_a_running_terminal_may_ask() {
    let (fx, vm) = setup().await;
    let other = super::secrets::runner(&fx, "other").await;
    let plan = account(&fx, &vm, "claude-sub", TOKEN).await;
    set_order(&fx, &[plan.id]).await;
    terminal(&fx, "t_live", &vm.id, "running").await;
    terminal(&fx, "t_done", &vm.id, "exited").await;
    assert_eq!(
        ask(&fx, &other, "t_live", "claude").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ask(&fx, &vm, "t_done", "claude").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ask(&fx, &vm, "t_none", "claude").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ask(&fx, &vm, "t_live", "codex").await.0,
        StatusCode::BAD_REQUEST
    );
    // A device that is not a runner, even one holding every scope, is never answered.
    assert_eq!(
        ask(&fx, &fx.dev, "t_live", "claude").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(ask(&fx, &vm, "t_live", "claude").await.0, StatusCode::OK);
}

#[tokio::test]
async fn nothing_usable_is_one_plain_line() {
    let (fx, vm) = setup().await;
    terminal(&fx, "t_x", &vm.id, "running").await;
    let (st, v) = ask(&fx, &vm, "t_x", "claude").await;
    assert_eq!(
        (st, &v["code"]),
        (StatusCode::NOT_FOUND, &json!("no_account")),
        "{v}"
    );
    assert!(
        v["message"].as_str().unwrap().contains("No Claude plan"),
        "{v}"
    );
    let key = account(&fx, &vm, "anthropic", "throwaway-acct-value-one-5a91c3").await;
    set_order(&fx, &[key.id]).await;
    let (st, v) = ask(&fx, &vm, "t_x", "claude").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert!(v["message"].as_str().unwrap().contains("API keys"), "{v}");
}
