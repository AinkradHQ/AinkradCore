//! An account's free-text name: given at create, changed by `PUT /accounts/{id}/name`, audited
//! `account.renamed`, checked at the boundary (trimmed, at most 64 characters, no control characters).

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::accounts_api::{call, setup};
use super::*;

const V: &str = "throwaway-name-value-0c41ab9e";

async fn audit(fx: &Fx, action: &str) -> Vec<Value> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = ? ORDER BY seq")
            .bind(action)
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    rows.iter()
        .map(|d| serde_json::from_str(d).unwrap())
        .collect()
}

#[tokio::test]
async fn a_name_is_given_at_create_changed_cleared_and_audited() {
    let (fx, vm, phone) = setup().await;
    let body = json!({"provider": "anthropic", "label": "claude-work", "value": V,
                      "runners": [vm.id], "display_name": "  Work Claude "});
    let (s, made) = call(&fx, &fx.dev, Method::POST, "/api/v1/accounts", body).await;
    assert_eq!(s, StatusCode::OK, "{made}");
    assert_eq!(made["account"]["display_name"], "Work Claude", "trimmed");
    assert_eq!(
        audit(&fx, "account.created").await[0]["display_name"],
        "Work Claude"
    );
    let id = made["account"]["id"].as_i64().unwrap();
    let uri = format!("/api/v1/accounts/{id}/name");

    let (s, a) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &uri,
        json!({"display_name": "Google Gemini EU"}),
    )
    .await;
    assert_eq!(
        (s, &a["display_name"]),
        (StatusCode::OK, &json!("Google Gemini EU")),
        "{a}"
    );
    let (_, list) = call(&fx, &phone, Method::GET, "/api/v1/accounts", Value::Null).await;
    assert_eq!(
        list[0]["display_name"], "Google Gemini EU",
        "a read device sees the name"
    );
    let renamed = audit(&fx, "account.renamed").await;
    assert_eq!(
        (&renamed[0]["from"], &renamed[0]["to"], &renamed[0]["label"]),
        (
            &json!("Work Claude"),
            &json!("Google Gemini EU"),
            &json!("claude-work")
        )
    );

    // `null` and blank both clear it: the field is then absent and clients show the provider.
    for clear in [
        json!({"display_name": null}),
        json!({"display_name": "   "}),
    ] {
        let (s, a) = call(&fx, &fx.dev, Method::PUT, &uri, clear).await;
        assert_eq!(s, StatusCode::OK, "{a}");
        assert!(a.get("display_name").is_none(), "{a}");
    }
    assert_eq!(audit(&fx, "account.renamed").await.len(), 3);

    // A read device may not rename; an unknown account is 404.
    let (s, _) = call(&fx, &phone, Method::PUT, &uri, json!({"display_name": "x"})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        "/api/v1/accounts/999/name",
        json!({"display_name": "x"}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_bad_name_is_refused_at_create_and_at_rename() {
    let (fx, vm, _) = setup().await;
    let long = "N".repeat(65);
    for bad in [long.as_str(), "Work\nClaude", "tab\there"] {
        let body = json!({"provider": "anthropic", "label": "claude-bad", "value": V,
                          "runners": [vm.id], "display_name": bad});
        let (s, b) = call(&fx, &fx.dev, Method::POST, "/api/v1/accounts", body).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_request")),
            "{b}"
        );
    }
    let (_, list) = call(&fx, &fx.dev, Method::GET, "/api/v1/accounts", Value::Null).await;
    assert_eq!(list, json!([]), "nothing was stored");

    let body =
        json!({"provider": "anthropic", "label": "claude-ok", "value": V, "runners": [vm.id]});
    let (_, made) = call(&fx, &fx.dev, Method::POST, "/api/v1/accounts", body).await;
    assert!(
        made["account"].get("display_name").is_none(),
        "no name: {made}"
    );
    let uri = format!("/api/v1/accounts/{}/name", made["account"]["id"]);
    for bad in [
        json!({"display_name": long}),
        json!({"display_name": "a\u{7}b"}),
        json!({"name": "x"}),
    ] {
        let (s, b) = call(&fx, &fx.dev, Method::PUT, &uri, bad).await;
        assert_eq!(
            (s, b["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("bad_request")),
            "{b}"
        );
    }
    // 64 characters of any script are fine.
    let (s, a) = call(
        &fx,
        &fx.dev,
        Method::PUT,
        &uri,
        json!({"display_name": "é".repeat(64)}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert!(audit(&fx, "account.renamed").await.len() == 1);
}
