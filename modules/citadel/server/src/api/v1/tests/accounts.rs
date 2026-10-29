//! The account pool (E15.1): add, assign, unassign, disable; refusals; no token in or out.

use serde_json::json;

use super::*;

#[tokio::test]
async fn the_admin_adds_assigns_and_disables_accounts() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let new = json!({"harness": "claude", "label": "claude-work",
                     "credential_ref": "claude-work.token", "billing": "subscription"});
    let created = fx.ok_post("/api/v1/accounts", new.clone()).await;
    assert_eq!(created["status"], "active");
    assert_eq!(created["credential_env"], "CLAUDE_CODE_OAUTH_TOKEN");
    assert_eq!(created["config_dir"], "accounts/claude-work");
    assert_eq!(created["company_ids"], json!([]));
    let (status, _) = fx.post("/api/v1/accounts", new).await;
    assert_eq!(status, StatusCode::CONFLICT, "label taken");
    let bad = json!({"harness": "claude", "label": "x", "credential_ref": "/etc/passwd"});
    let (status, body) = fx.post("/api/v1/accounts", bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let id = created["id"].as_i64().unwrap();
    let uri = format!("/api/v1/accounts/{id}/companies/{}", a.company.0);
    let (status, assigned) = send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(assigned["company_ids"], json!([a.company.0]));
    let missing = format!("/api/v1/accounts/{id}/companies/999");
    let (status, _) = send(&fx.app, req(Method::PUT, &missing, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, gone) = send(&fx.app, req(Method::DELETE, &uri, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(gone["company_ids"], json!([]));

    let status_uri = format!("/api/v1/accounts/{id}/status");
    let off = fx
        .ok_post(
            &status_uri,
            json!({"status": "disabled", "reason": "rotating"}),
        )
        .await;
    assert_eq!(off["status"], "disabled");
    assert_eq!(off["status_reason"], "rotating");
    let (status, _) = fx.post(&status_uri, json!({"status": "limited"})).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "limited is the server's to set"
    );
    let list = fx.ok("/api/v1/accounts").await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE entity_kind = 'account' AND actor_kind = 'user'",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(audited, 4, "created, assigned, unassigned, disabled");
}

#[tokio::test]
async fn limits_are_set_and_usage_is_reported_per_account_and_company() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let new = json!({"harness": "claude", "label": "claude-1"});
    let id = fx.ok_post("/api/v1/accounts", new).await["id"]
        .as_i64()
        .unwrap();
    let uri = format!("/api/v1/accounts/{id}/companies/{}", a.company.0);
    send(&fx.app, req(Method::PUT, &uri, Some(&fx.key), None)).await;
    let limits = format!("/api/v1/accounts/{id}/limits");
    let set = fx
        .ok_post(
            &limits,
            json!({"window_secs": 18000, "unit": "tokens", "max": 1000}),
        )
        .await;
    assert_eq!(set["warn_percent"], 80);
    let (status, _) = fx
        .post(
            &limits,
            json!({"window_secs": 0, "unit": "tokens", "max": 1000}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let usage = fx.ok("/api/v1/accounts/usage").await;
    assert_eq!(usage[0]["account"]["label"], "claude-1");
    assert_eq!(usage[0]["limits"][0]["used"], 0);
    assert_eq!(usage[0]["limits"][0]["limit"]["max"], 1000);
    let mine = format!("/api/v1/companies/{}/account-usage", a.company.0);
    assert_eq!(fx.ok(&mine).await, json!([]), "nothing used yet");

    let clear = format!("/api/v1/accounts/{id}/limits/tokens/18000");
    let (status, _) = send(&fx.app, req(Method::DELETE, &clear, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&fx.app, req(Method::DELETE, &clear, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_agents_fallback_chain_is_read_and_replaced_and_runs_show_their_model() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/fallbacks", a.agent.0);
    assert_eq!(fx.ok(&uri).await, json!([]));
    let chain = json!([{"harness": "codex", "model": "gpt-x"},
                       {"harness": "claude", "model": "claude-haiku"}]);
    let put = |body: Value| req(Method::PUT, &uri, Some(&fx.key), Some(body));
    let (status, set) = send(&fx.app, put(chain.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(set, chain);
    assert_eq!(fx.ok(&uri).await, chain);
    let twice = json!([{"harness": "codex", "model": "x"}, {"harness": "codex", "model": "x"}]);
    let (status, _) = send(&fx.app, put(twice)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(&fx.app, put(json!([]))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fx.ok(&uri).await, json!([]), "empty clears it");
    let missing = req(
        Method::PUT,
        "/api/v1/agents/999/fallbacks",
        Some(&fx.key),
        Some(json!([])),
    );
    assert_eq!(send(&fx.app, missing).await.0, StatusCode::NOT_FOUND);

    let run = fx.ok(&format!("/api/v1/runs/{}", a.run.id.0)).await;
    let agent = fx.ok(&format!("/api/v1/agents/{}", a.agent.0)).await;
    assert_eq!(
        run["model_used"], agent["model"],
        "the agent's own, no fallback"
    );
    assert!(run["fallback_reason"].is_null());
}

#[tokio::test]
async fn an_account_is_deleted_unless_runs_use_it_or_the_ledger_names_it() {
    let fx = fx().await;
    let pool = &fx.app.pool;
    let a = seed(pool, "A", "AAA", ProjectMode::Kanban).await;
    let make = |label: &str| json!({"harness": "opencode", "label": label});
    let del = |id: i64| {
        send(
            &fx.app,
            req(
                Method::DELETE,
                &format!("/api/v1/accounts/{id}"),
                Some(&fx.key),
                None,
            ),
        )
    };

    // An unused account goes, with its assignment; the audit row says who and which.
    let unused = fx.ok_post("/api/v1/accounts", make("unused")).await["id"]
        .as_i64()
        .unwrap();
    let assign = format!("/api/v1/accounts/{unused}/companies/{}", a.company.0);
    send(&fx.app, req(Method::PUT, &assign, Some(&fx.key), None)).await;
    let (status, body) = del(unused).await;
    assert_eq!(
        (status, &body["id"]),
        (StatusCode::OK, &json!(unused)),
        "{body}"
    );
    assert_eq!(del(unused).await.0, StatusCode::NOT_FOUND);
    let row: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'account.deleted' AND actor_kind = 'user'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        row.contains("\"unused\"") && row.contains(&a.company.0.to_string()),
        "{row}"
    );

    // Live runs on it: conflict. Once they end it has history: still a conflict, the ledger
    // keeps its name.
    let used = fx.ok_post("/api/v1/accounts", make("used")).await["id"]
        .as_i64()
        .unwrap();
    let assign = format!("/api/v1/accounts/{used}/companies/{}", a.company.0);
    send(&fx.app, req(Method::PUT, &assign, Some(&fx.key), None)).await;
    sqlx::query("UPDATE runs SET account_id = ? WHERE id = ?")
        .bind(used)
        .bind(a.run.id.0)
        .execute(pool)
        .await
        .unwrap();
    let (status, body) = del(used).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("live runs"),
        "{body}"
    );
    let ended = citadel_core::exec::RunEvent::Cancel {
        reason: "done".to_owned(),
    };
    let by = AuditActor::Runner(a.runner);
    crate::store::exec::transition_run(pool, a.run.id, by, &ended, NOW)
        .await
        .unwrap();
    let (status, body) = del(used).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("history"),
        "{body}"
    );
    assert_eq!(fx.ok("/api/v1/accounts").await.as_array().unwrap().len(), 1);
}
