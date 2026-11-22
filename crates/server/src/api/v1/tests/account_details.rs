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
