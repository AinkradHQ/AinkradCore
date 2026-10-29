//! Settings (E15.17): listed with bounds, value and source; set, refused with the reason,
//! reset to what it inherits, and the history of changes. The rate limits read them.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::*;

impl Fx {
    async fn put(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        send(
            &self.app,
            req(Method::PUT, uri, Some(&self.key), Some(body)),
        )
        .await
    }

    async fn delete(&self, uri: &str) -> (StatusCode, Value) {
        send(&self.app, req(Method::DELETE, uri, Some(&self.key), None)).await
    }
}

#[tokio::test]
async fn settings_are_listed_set_refused_reset_and_their_history_read() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let (company, project) = (
        format!("company:{}", a.company.0),
        format!("project:{}", a.project.0),
    );
    let all = fx.ok("/api/v1/settings").await;
    let cap = all
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["key"] == "run.token_cap")
        .unwrap()
        .clone();
    assert_eq!(
        cap,
        json!({"key": "run.token_cap", "unit": "tokens", "default": 2_000_000, "min": 1000,
               "max": 100_000_000, "scopes": ["server", "company", "project"],
               "value": 2_000_000, "source": null, "description": cap["description"]})
    );
    let at_project = fx.ok(&format!("/api/v1/settings/{project}")).await;
    assert!(
        at_project
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["key"] != "lease.ttl_secs")
    );

    let uri = |scope: &str| format!("/api/v1/settings/{scope}/run.token_cap");
    let set = fx.put(&uri(&company), json!({"value": 50_000})).await;
    assert_eq!(set.0, StatusCode::OK, "{}", set.1);
    let set = fx.put(&uri(&project), json!({"value": 5_000})).await.1;
    assert_eq!(
        (&set["value"], &set["source"]),
        (&json!(5000), &json!(project))
    );
    let refused = [
        (
            uri(&project),
            json!({"value": 5}),
            StatusCode::BAD_REQUEST,
            "out_of_bounds",
        ),
        (
            uri(&project),
            json!({"value": "5000"}),
            StatusCode::BAD_REQUEST,
            "not_integer",
        ),
        (
            uri("runner:1"),
            json!({"value": 5000}),
            StatusCode::BAD_REQUEST,
            "wrong_scope",
        ),
        (
            uri("project:999"),
            json!({"value": 5000}),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            uri("team:1"),
            json!({"value": 5000}),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "/api/v1/settings/server/no.such".to_owned(),
            json!({"value": 1}),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ];
    for (u, body, status, code) in refused {
        let (got, err) = fx.put(&u, body).await;
        assert_eq!(
            (got, err["code"].as_str()),
            (status, Some(code)),
            "{u}: {err}"
        );
    }
    let reset = fx.delete(&uri(&project)).await.1;
    assert_eq!(
        (&reset["value"], &reset["source"]),
        (&json!(50000), &json!(company))
    );
    let history = fx.ok(&format!("{}/history", uri(&project))).await;
    assert_eq!(
        history,
        json!([
            {"seq": history[0]["seq"], "at": NOW, "actor": {"kind": "user", "user_id": 1},
             "scope": project, "old": 5000, "new": null},
            {"seq": history[1]["seq"], "at": NOW, "actor": {"kind": "user", "user_id": 1},
             "scope": project, "old": null, "new": 5000},
        ])
    );
    let got = fx.ok(&uri(&project)).await;
    assert_eq!(got["value"], 50000);
}

#[tokio::test]
async fn the_rate_limits_are_read_from_settings() {
    use ainkrad_core::settings::{Key, Scope};
    let fx = fx().await;
    let pool = &fx.app.pool;
    let by = super::super::BY;
    crate::store::settings::set(pool, Key::ApiRequestBurst, Scope::Server, "10", by, NOW)
        .await
        .unwrap();
    crate::store::settings::set(pool, Key::ApiAuthFailureBurst, Scope::Server, "3", by, NOW)
        .await
        .unwrap();
    let limits = Limits::from_settings(pool).await.unwrap();
    assert_eq!((limits.requests.burst, limits.failures.burst), (10.0, 3.0));
    assert_eq!(limits.requests.per_sec, 20.0, "the default 1200 a minute");
    let defaults = Limits::default();
    assert_eq!(
        (defaults.requests.burst, defaults.failures.burst),
        (120.0, 10.0)
    );
    assert!((defaults.failures.per_sec - 1.0 / 6.0).abs() < 1e-9);
}

#[tokio::test]
async fn the_prototype_keys_are_set_where_they_are_allowed() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let company = format!("company:{}", a.company.0);
    let project = format!("project:{}", a.project.0);
    let account = fx
        .ok_post(
            "/api/v1/accounts",
            json!({"harness": "opencode", "label": "oc"}),
        )
        .await["id"]
        .as_i64()
        .unwrap();
    let account = format!("account:{account}");
    let at = |scope: &str, key: &str| format!("/api/v1/settings/{scope}/{key}");

    let warn = "cost.daily_warn_usd_micros";
    for scope in ["server", &company] {
        let (status, got) = fx.put(&at(scope, warn), json!({"value": 25_000_000})).await;
        assert_eq!(
            (status, &got["value"]),
            (StatusCode::OK, &json!(25_000_000)),
            "{scope}"
        );
    }
    assert_eq!(
        fx.put(&at(&project, warn), json!({"value": 1})).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fx.put(&at(&company, warn), json!({"value": -1})).await.0,
        StatusCode::BAD_REQUEST
    );

    let wip = "agent.wip_max";
    for scope in ["server", &company, &project] {
        let (status, got) = fx.put(&at(scope, wip), json!({"value": 3})).await;
        assert_eq!(
            (status, &got["value"]),
            (StatusCode::OK, &json!(3)),
            "{scope}"
        );
    }
    assert_eq!(
        fx.put(&at(&account, wip), json!({"value": 3})).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        fx.put(&at(&company, wip), json!({"value": 101})).await.0,
        StatusCode::BAD_REQUEST
    );

    // `account.at_limit` is also an account's own.
    let limit = "account.at_limit";
    let (status, got) = fx.put(&at(&account, limit), json!({"value": 1})).await;
    assert_eq!(
        (status, &got["value"], &got["source"]),
        (StatusCode::OK, &json!(1), &json!(account))
    );
    assert_eq!(
        fx.put(&at(&company, limit), json!({"value": 1})).await.0,
        StatusCode::OK
    );
    assert_eq!(
        fx.put(&at(&project, limit), json!({"value": 1})).await.0,
        StatusCode::BAD_REQUEST
    );
}
