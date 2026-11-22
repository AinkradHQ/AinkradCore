//! The account details page's data (0.10.4): one account's daily series, its latest sessions
//! (title, model, runner, tokens, dollars for an admin, where a failed-over one moved) and the
//! last check in detail.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::accounts_store::{V1, V2, make, setup};
use super::*;
use crate::store::account_keys;
use crate::store::agents::{self as store, NewSession};
use crate::store::costs::{self, NewCost};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str) -> (StatusCode, Value) {
    send(&fx.app, req(m, uri, Some(dev), None)).await
}

async fn cost(fx: &Fx, account: i64, key: &str, tokens: i64) {
    let c = NewCost {
        session: "s1",
        epoch: 0,
        account_id: Some(account),
        legacy_account_id: None,
        provider: "anthropic",
        harness: "claude",
        model: "claude-x",
        input_tokens: tokens,
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: None,
        approximate: false,
        subjects: &[],
        idempotency_key: key,
        occurred_at: NOW,
    };
    costs::record(&fx.app.pool, &c, NOW).await.unwrap();
}

#[tokio::test]
async fn the_series_narrows_to_one_account() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let b = make(&fx, &s, "side", V2, std::slice::from_ref(&vm.id)).await;
    cost(&fx, a.id, "a1", 300).await;
    cost(&fx, b.id, "b1", 7).await;
    let all = call(&fx, &fx.dev, Method::GET, "/api/v1/costs/series")
        .await
        .1;
    assert_eq!(all[0]["total_tokens"], 307, "{all}");
    let uri = format!("/api/v1/costs/series?days=7&account={}", b.id);
    let (st, one) = call(&fx, &fx.dev, Method::GET, &uri).await;
    assert_eq!(st, StatusCode::OK, "{one}");
    assert_eq!(one.as_array().unwrap().len(), 1, "{one}");
    assert_eq!(
        (&one[0]["provider"], &one[0]["total_tokens"]),
        (&json!("anthropic"), &json!(7))
    );
    let none = call(
        &fx,
        &fx.dev,
        Method::GET,
        "/api/v1/costs/series?account=999",
    )
    .await;
    assert_eq!(none, (StatusCode::OK, json!([])));
}

async fn session(fx: &Fx, runner: &str, account: i64, prompt: &str) -> String {
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: Some(prompt),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let s = store::create_owned(&fx.app.pool, &new, None, BY, NOW)
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET account_id = ? WHERE id = ?")
        .bind(account)
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    s.id
}

#[tokio::test]
async fn an_accounts_latest_sessions_name_their_model_runner_and_where_they_moved() {
    let (fx, vm, s) = setup().await;
    let phone = fx.enroll("phone", &["read"]).await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let b = make(&fx, &s, "side", V2, std::slice::from_ref(&vm.id)).await;
    let first = session(&fx, &vm.id, a.id, "Fix the flaky test\nand more").await;
    let second = session(&fx, &vm.id, a.id, "Second").await;
    sqlx::query(
        "UPDATE core_agent_sessions SET title = 'Named', harness_model = 'claude-opus-4-5', \
         tokens_in = 100, tokens_out = 20, cache_read = 3, cost_usd_micros = 4200, \
         state = 'ended', ended_at = created_at WHERE id = ?",
    )
    .bind(&second)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    // The second failed over to account b: its successor is b's session.
    let next = session(&fx, &vm.id, b.id, "Second").await;
    sqlx::query("UPDATE core_agent_sessions SET failover_of = ? WHERE id = ?")
        .bind(&second)
        .bind(&next)
        .execute(&fx.app.pool)
        .await
        .unwrap();

    let uri = format!("/api/v1/accounts/{}/sessions", a.id);
    let (st, got) = call(&fx, &fx.dev, Method::GET, &uri).await;
    assert_eq!(st, StatusCode::OK, "{got}");
    let rows = got.as_array().unwrap();
    assert_eq!(rows.len(), 2, "only this account's, {got}");
    let s0 = &rows[0];
    assert_eq!(s0["session_id"], json!(second), "newest first");
    assert_eq!(
        (&s0["title"], &s0["model"], &s0["tokens"], &s0["usd_micros"]),
        (
            &json!("Named"),
            &json!("claude-opus-4-5"),
            &json!(123),
            &json!(4200)
        )
    );
    assert_eq!(
        (&s0["runner_id"], &s0["runner_name"]),
        (&json!(vm.id), &json!("vm"))
    );
    assert_eq!(s0["moved_to_account"], json!(b.id.to_string()));
    assert!(s0["ended_at"].is_string(), "{s0}");
    let s1 = &rows[1];
    assert_eq!(s1["session_id"], json!(first));
    assert_eq!(
        s1["title"], "Fix the flaky test",
        "the first line when untitled"
    );
    for absent in ["model", "usd_micros", "ended_at", "moved_to_account"] {
        assert!(s1.get(absent).is_none(), "{absent}: {s1}");
    }

    // `limit`, the read scope (no dollars for it), 404.
    let (_, one) = call(&fx, &fx.dev, Method::GET, &format!("{uri}?limit=1")).await;
    assert_eq!(one.as_array().unwrap().len(), 1);
    let (st, read) = call(&fx, &phone, Method::GET, &uri).await;
    assert_eq!(st, StatusCode::OK, "{read}");
    assert!(read[0].get("usd_micros").is_none(), "{read}");
    let (st, _) = call(&fx, &fx.dev, Method::GET, "/api/v1/accounts/999/sessions").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_last_check_shows_its_runner_time_and_answer() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let uri = format!("/api/v1/accounts/{}", a.id);
    let (_, never) = call(&fx, &fx.dev, Method::GET, &uri).await;
    assert!(never.get("last_check").is_none(), "{never}");

    account_keys::record_test(&fx.app.pool, a.id, "ok", 3200, &vm.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let (_, ok) = call(&fx, &fx.dev, Method::GET, &uri).await;
    let c = &ok["last_check"];
    assert_eq!(
        (
            &c["ok"],
            &c["runner_id"],
            &c["runner_name"],
            &c["answer_ms"]
        ),
        (&json!(true), &json!(vm.id), &json!("vm"), &json!(3200)),
        "{ok}"
    );
    assert!(c["at"].is_string() && c.get("detail").is_none(), "{c}");

    // A failed test that never answered: not ok, the word, no answer time.
    account_keys::record_test(&fx.app.pool, a.id, "failed", 0, &vm.id, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    let (_, bad) = call(&fx, &fx.dev, Method::GET, &uri).await;
    let c = &bad["last_check"];
    assert_eq!((&c["ok"], &c["detail"]), (&json!(false), &json!("failed")));
    assert!(c.get("answer_ms").is_none(), "{c}");
}

/// A Claude plan has no key to list its models: it gets the shipped Anthropic models and every model
/// its sessions were seen running, marked as included in the plan, and the switch still works.
#[tokio::test]
async fn a_plan_account_lists_its_models_as_included_and_they_can_be_switched_off() {
    use ainkrad_core::settings::{Key, Scope};
    let (fx, vm, s) = setup().await;
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsProviderAccounts,
        Scope::Server,
        "1",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let new = crate::store::accounts::NewAccount {
        provider: "claude-sub",
        label: "claude-me",
        value: "sk-ant-oat01-TESTONLY0123456789abcdefghijklmnop",
        runners: std::slice::from_ref(&vm.id),
        cap: None,
        display_name: None,
    };
    let a = crate::store::accounts::create_by(
        &fx.app.pool,
        &s,
        &new,
        "subscription",
        &fx.dev.id,
        BY,
        NOW,
    )
    .await
    .unwrap();
    let id = session(&fx, &vm.id, a.id, "hi").await;
    sqlx::query("UPDATE core_agent_sessions SET harness_model = 'claude-fable-9' WHERE id = ?")
        .bind(&id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let uri = format!("/api/v1/accounts/{}/models", a.id);
    let (st, b) = call(&fx, &fx.dev, Method::GET, &uri).await;
    assert_eq!(st, StatusCode::OK, "{b}");
    assert_eq!(
        b["models"],
        json!([
            "claude-opus-5-5",
            "claude-sonnet-5-5",
            "claude-haiku-5-5",
            "claude-fable-9"
        ])
    );
    assert_eq!(
        (&b["billing"], &b["models_enforced"]),
        (&json!("plan"), &json!(false))
    );
    let items = b["items"].as_array().unwrap();
    assert_eq!(items.len(), 4, "{b}");
    assert!(
        items
            .iter()
            .all(|r| r["allowed"] == true && r.get("input_per_mtok_micro").is_none())
    );

    let off = format!("{uri}/claude-opus-5-5");
    let (st, b) = send(
        &fx.app,
        req(
            Method::PUT,
            &off,
            Some(&fx.dev),
            Some(json!({"allowed": false})),
        ),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{b}");
    let opus = b["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["model"] == "claude-opus-5-5");
    assert_eq!(opus.unwrap()["allowed"], false, "{b}");

    // An API-key account is metered and enforced.
    let k = make(&fx, &s, "main", V1, std::slice::from_ref(&vm.id)).await;
    let (_, b) = call(
        &fx,
        &fx.dev,
        Method::GET,
        &format!("/api/v1/accounts/{}/models", k.id),
    )
    .await;
    assert_eq!(
        (&b["billing"], &b["models_enforced"]),
        (&json!("metered"), &json!(true))
    );
}

/// The ChatGPT plan's ids come from Core data only: the runner's Codex default and the shipped
/// OpenAI Codex rows. Other providers get none here.
#[test]
fn the_codex_plan_lists_the_runner_default_and_the_shipped_codex_models() {
    use crate::store::account_models::plan_models;
    assert_eq!(plan_models("codex-sub"), ["gpt-5.6-luna", "gpt-5.3-codex"]);
    assert!(plan_models("anthropic").is_empty() && plan_models("opencode-sub").is_empty());
}
