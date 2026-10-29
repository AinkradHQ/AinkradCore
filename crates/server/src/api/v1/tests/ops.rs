//! Operations settings (API minor 18): chain presets, roles, agent stats, notifications and
//! device pairing.

use ainkrad_core::work::ProjectMode;
use serde_json::json;

use super::*;

async fn put(fx: &Fx, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::PUT, uri, Some(&fx.key), Some(body))).await
}

async fn delete(fx: &Fx, uri: &str) -> (StatusCode, Value) {
    send(&fx.app, req(Method::DELETE, uri, Some(&fx.key), None)).await
}

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn chain_presets_replace_an_agents_fallbacks_and_the_default_fills_in() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let list = format!("/api/v1/companies/{}/chain-presets", a.company.0);
    let fast = json!({"name": "Fast", "color": "#3b82f6", "description": "cheap first",
        "entries": [{"harness": "claude", "model": "haiku"},
                    {"harness": "codex", "model": "mini"}]});
    let made = fx.ok_post(&list, fast.clone()).await;
    assert_eq!(made["entries"][1]["model"], "mini");
    assert_eq!(made["is_default"], false);
    assert_eq!(
        fx.post(&list, fast).await.0,
        StatusCode::CONFLICT,
        "a name once"
    );
    let bad = json!({"name": "X", "color": "blue", "entries": []});
    assert_eq!(fx.post(&list, bad).await.0, StatusCode::BAD_REQUEST);
    let pin = json!({"name": "Pinned", "entries": [{"harness": "claude", "model": "opus", "account_id": 99}]});
    assert_eq!(
        fx.post(&list, pin).await.0,
        StatusCode::BAD_REQUEST,
        "not in the pool"
    );

    // The agent uses it in place of its own fallbacks; clearing it brings them back.
    let id = made["id"].as_i64().unwrap();
    let agent = a.agent.0;
    let own = json!([{"harness": "codex", "model": "own"}]);
    assert_eq!(
        put(&fx, &format!("/api/v1/agents/{agent}/fallbacks"), own)
            .await
            .0,
        StatusCode::OK
    );
    let chain = format!("/api/v1/agents/{agent}/chain");
    let (status, got) = put(&fx, &chain, json!({"preset_id": id})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        (&got["preset_id"], got["entries"].as_array().unwrap().len()),
        (&json!(id), 2)
    );
    assert_eq!(
        fx.ok(&format!("/api/v1/agents/{agent}")).await["chain_preset_id"],
        id
    );
    let route = crate::store::org::fallbacks_for_test(&fx.app.pool, a.agent).await;
    assert_eq!(route, ["haiku", "mini"]);
    let (_, got) = put(
        &fx,
        &chain,
        json!({"entries": [{"harness": "codex", "model": "own"}]}),
    )
    .await;
    assert_eq!(
        (&got["preset_id"], &got["entries"][0]["model"]),
        (&Value::Null, &json!("own"))
    );
    assert_eq!(put(&fx, &chain, json!({})).await.0, StatusCode::BAD_REQUEST);
    let both = json!({"preset_id": id, "entries": []});
    assert_eq!(put(&fx, &chain, both).await.0, StatusCode::BAD_REQUEST);
    let other = format!("/api/v1/agents/{}/chain", b.agent.0);
    let (status, _) = put(&fx, &other, json!({"preset_id": id})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "another company's preset");

    // The company default serves an agent with no chain of its own.
    let default = json!({"name": "House", "is_default": true,
        "entries": [{"harness": "agy", "model": "pro"}]});
    let house = fx.ok_post(&list, default).await;
    assert_eq!(house["is_default"], true);
    let (_, got) = put(&fx, &chain, json!({"entries": []})).await;
    assert_eq!(got["entries"][0]["model"], "pro");
    let (_, changed) = put(
        &fx,
        &format!("/api/v1/chain-presets/{id}"),
        json!({"name": "Fast", "is_default": true, "entries": []}),
    )
    .await;
    assert_eq!(changed["is_default"], true);
    let all = fx.ok(&list).await;
    let defaults = all
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["is_default"] == true)
        .count();
    assert_eq!(defaults, 1, "one default per company");

    // Deleting a preset sets its agents free.
    let (status, _) = put(&fx, &chain, json!({"preset_id": id})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        delete(&fx, &format!("/api/v1/chain-presets/{id}")).await.0,
        StatusCode::OK
    );
    assert_eq!(
        fx.ok(&format!("/api/v1/agents/{agent}")).await["chain_preset_id"],
        Value::Null
    );
    assert_eq!(
        delete(&fx, &format!("/api/v1/chain-presets/{id}")).await.0,
        StatusCode::NOT_FOUND
    );
    for action in [
        "chain_preset.created",
        "chain_preset.updated",
        "chain_preset.deleted",
        "agent.chain_set",
    ] {
        assert!(audited(&fx, action).await >= 1, "{action}");
    }
    // Company scope: B's header does not see A's preset.
    let scoped = req(
        Method::PUT,
        &format!("/api/v1/chain-presets/{}", house["id"]),
        Some(&fx.key),
        Some(json!({"name": "x", "entries": []})),
    );
    let (mut parts, body) = scoped.into_parts();
    parts.headers.insert(
        "x-citadel-company",
        b.company.0.to_string().parse().unwrap(),
    );
    let (status, _) = send(&fx.app, Request::from_parts(parts, body)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn roles_are_created_replaced_and_deleted_in_their_company() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let list = format!("/api/v1/companies/{}/roles", a.company.0);
    let qa = json!({"name": "QA", "purpose": "finds bugs", "icon": "bug", "harness": "claude",
        "model": "sonnet", "budget_tokens": 40_000_000, "skills": ["testing"],
        "instructions": "Be thorough."});
    let made = fx.ok_post(&list, qa.clone()).await;
    assert_eq!(
        (&made["harness"], &made["budget_tokens"], &made["skills"]),
        (&json!("claude"), &json!(40_000_000), &json!(["testing"]))
    );
    assert_eq!(fx.post(&list, qa).await.0, StatusCode::CONFLICT);
    let bad = json!({"name": "X", "budget_tokens": -1});
    assert_eq!(fx.post(&list, bad).await.0, StatusCode::BAD_REQUEST);
    let bare = fx.ok_post(&list, json!({"name": "Bare"})).await;
    assert_eq!(
        (&bare["harness"], &bare["skills"]),
        (&Value::Null, &json!([]))
    );

    let uri = format!("/api/v1/roles/{}", made["id"]);
    let (status, got) = put(&fx, &uri, json!({"name": "QA lead", "skills": []})).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        (&got["name"], &got["harness"]),
        (&json!("QA lead"), &Value::Null)
    );
    assert_eq!(fx.ok(&list).await.as_array().unwrap().len(), 2);
    assert_eq!(delete(&fx, &uri).await.0, StatusCode::OK);
    assert_eq!(delete(&fx, &uri).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        put(&fx, &uri, json!({"name": "x"})).await.0,
        StatusCode::NOT_FOUND
    );
    for action in ["role.created", "role.updated", "role.deleted"] {
        assert!(audited(&fx, action).await >= 1, "{action}");
    }
}

#[tokio::test]
async fn an_agents_stats_and_queued_wakes_come_from_its_runs() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/agents/{}/stats", a.agent.0);
    // The fixture's run is stamped by the real clock; pin it to the test's.
    sqlx::query("UPDATE runs SET started_at = ?, queued_at = ?")
        .bind(NOW)
        .bind(NOW)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let s = fx.ok(&uri).await;
    assert_eq!(s["runs_by_day"].as_array().unwrap().len(), 7);
    assert_eq!(s["runs_by_day"][6], json!({"day": "2026-10-22", "runs": 1}));
    assert_eq!(s["success_by_week"].as_array().unwrap().len(), 8);
    assert_eq!(s["success_by_week"][7]["week"], "2026-10-19");
    assert_eq!(s["success_by_week"][7]["runs"], 0, "the run is still live");
    let heat = s["heatmap"].as_array().unwrap();
    assert_eq!((heat.len(), heat[0].as_array().unwrap().len()), (7, 6));
    // 2026-10-22 is a Thursday (row 3); the run started at 10:00 UTC (slot 2).
    assert_eq!(heat[3][2], 1);
    assert_eq!(s["avg_cost_micros"], Value::Null);
    assert_eq!(s["daily_spend"].as_array().unwrap().len(), 22);
    assert_eq!(
        fx.get("/api/v1/agents/999/stats").await.0,
        StatusCode::NOT_FOUND
    );

    let by = AuditActor::Runner(a.runner);
    crate::store::exec::transition_run(
        &fx.app.pool,
        a.run.id,
        by,
        &ainkrad_core::exec::RunEvent::Succeed,
        NOW,
    )
    .await
    .unwrap();
    let s = fx.ok(&uri).await;
    assert_eq!(s["success_by_week"][7]["runs"], 1);
    assert_eq!(s["success_by_week"][7]["succeeded"], 1);

    let agent = fx.ok(&format!("/api/v1/agents/{}", a.agent.0)).await;
    let before = agent["queued_wakes"].as_i64().unwrap();
    let wake = ainkrad_core::exec::NewWakeRequest {
        agent_id: a.agent,
        issue_id: None,
        source: ainkrad_core::exec::WakeSource::Assignment,
        reason: "again".to_owned(),
        idempotency_key: "queued-1".to_owned(),
        not_before: None,
    };
    crate::store::exec::enqueue_wake(&fx.app.pool, &wake)
        .await
        .unwrap();
    let agent = fx.ok(&format!("/api/v1/agents/{}", a.agent.0)).await;
    assert_eq!(agent["queued_wakes"].as_i64().unwrap(), before + 1);
}

#[tokio::test]
async fn notification_preferences_default_change_and_test() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/notifications", a.company.0);
    let cell = |n: &Value, event: &str, channel: &str| {
        n["matrix"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["event"] == event && c["channel"] == channel)
            .map(|c| c["on"].clone())
    };
    let n = fx.ok(&uri).await;
    assert_eq!(n["matrix"].as_array().unwrap().len(), 24);
    assert_eq!(cell(&n, "approval_waiting", "push"), Some(json!(true)));
    assert_eq!(cell(&n, "run_finished", "push"), Some(json!(false)));
    assert_eq!(
        n["quiet"],
        json!({"start": 1320, "end": 420, "on": false, "breakthrough": "stalled"})
    );

    let change = json!({"matrix": [{"event": "run_finished", "channel": "email", "on": true},
                                   {"event": "approval_waiting", "channel": "push", "on": false}],
                        "quiet_on": true, "quiet_start": 1380, "breakthrough": "nothing"});
    let (status, n) = put(&fx, &uri, change).await;
    assert_eq!(status, StatusCode::OK, "{n}");
    assert_eq!(cell(&n, "run_finished", "email"), Some(json!(true)));
    assert_eq!(cell(&n, "approval_waiting", "push"), Some(json!(false)));
    assert_eq!(
        n["quiet"],
        json!({"start": 1380, "end": 420, "on": true, "breakthrough": "nothing"})
    );
    for bad in [
        json!({"matrix": [{"event": "nope", "channel": "push", "on": true}]}),
        json!({"matrix": [{"event": "issue_stuck", "channel": "fax", "on": true}]}),
        json!({"quiet_start": 1440}),
        json!({"breakthrough": "everything"}),
    ] {
        assert_eq!(put(&fx, &uri, bad).await.0, StatusCode::BAD_REQUEST);
    }
    let sent = fx.ok_post(&format!("{uri}/test"), json!({})).await;
    assert!(sent["seq"].as_i64().unwrap() > 0);
    assert_eq!(audited(&fx, "notifications.test").await, 1);
    assert_eq!(audited(&fx, "notifications.updated").await, 1);
}

async fn pair(fx: &Fx, code: &str) -> (StatusCode, Value) {
    let body = json!({"code": code, "name": "iPad"});
    send(
        &fx.app,
        req(Method::POST, "/api/v1/devices/pair", None, Some(body)),
    )
    .await
}

#[tokio::test]
async fn a_device_pairs_once_with_a_code_and_wrong_codes_are_limited() {
    let mut fx = fx().await;
    let (_, started) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/devices/pairing",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    let code = started["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 6);
    assert_eq!(started["expires_at"], "2026-10-22T10:05:00.000Z");
    let (status, got) = pair(&fx, &code.to_lowercase()).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let key = got["key"].as_str().unwrap().to_owned();
    assert_eq!(got["device"]["name"], "iPad");
    let (status, _) = send(
        &fx.app,
        req(Method::GET, "/api/v1/devices", Some(&key), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the new key works");
    assert_eq!(
        pair(&fx, &code).await.0,
        StatusCode::NOT_FOUND,
        "a code works once"
    );
    assert_eq!(pair(&fx, "ZZZZZZ").await.0, StatusCode::NOT_FOUND);
    assert_eq!(audited(&fx, "device.paired").await, 1);
    assert_eq!(audited(&fx, "device.pairing_started").await, 1);

    // Expired.
    let (_, started) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/devices/pairing",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    *fx.clock.0.lock().unwrap() = "2026-10-22T10:06:00.000Z".to_owned();
    assert_eq!(
        pair(&fx, started["code"].as_str().unwrap()).await.0,
        StatusCode::NOT_FOUND
    );

    // Wrong codes run out: then 429, even for a right one.
    fx.app.limits = Arc::new(Limits {
        failures: Limiter::new(2, 0.001),
        requests: Limiter::new(1000, 1.0),
    });
    *fx.clock.0.lock().unwrap() = NOW.to_owned();
    let (_, started) = send(
        &fx.app,
        req(
            Method::POST,
            "/api/v1/devices/pairing",
            Some(&fx.key),
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(pair(&fx, "AAAAAA").await.0, StatusCode::NOT_FOUND);
    assert_eq!(pair(&fx, "BBBBBB").await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        pair(&fx, started["code"].as_str().unwrap()).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}
