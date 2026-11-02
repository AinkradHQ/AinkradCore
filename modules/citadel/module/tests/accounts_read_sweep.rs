//! KAN-445: no GET a read-only device can make, anywhere in the Citadel contract, names an
//! account's broker secret, its runners, its config dir or its delivery. The usage report has its
//! own guard (`accounts_usage_scope.rs`); this sweeps every other `read` route, with every `{id}`
//! tried as the company and as the account, so a route added later cannot open the same hole.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::json;

const SECRET: &str = "claude-main";

#[tokio::test]
async fn no_read_route_names_an_accounts_secret_runners_config_dir_or_delivery() {
    let fx = fx().await;
    let phone = enroll(&fx.app, "phone", &["read"], true).await;
    sqlx::query(
        "INSERT INTO core_secrets (name, owner, runners, delivery, version, key_id, sealed, size, \
         created_at, updated_at) VALUES (?, ?, '[\"runner-1\"]', 'file', 1, '0123456789abcdef', ?, 5, 'now', 'now')",
    )
    .bind(SECRET)
    .bind(&fx.dev.id)
    .bind(b"x".as_slice())
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let body = json!({"harness": "claude", "label": "main", "secret_name": SECRET,
                      "config_dir": "accounts/main"});
    let (s, account) = call(&fx, Some(&fx.dev), Method::POST, "/accounts", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{account}");
    let account = account["id"].as_i64().unwrap();
    let (s, company) = call(
        &fx,
        Some(&fx.dev),
        Method::POST,
        "/companies",
        Some(json!({"name": "A"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{company}");
    let company = company["id"].as_i64().unwrap();
    let (s, v) = call(
        &fx,
        Some(&fx.dev),
        Method::PUT,
        &format!("/accounts/{account}/companies/{company}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let spec: serde_json::Value =
        serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[
            std::sync::Arc::new(citadel_module::Citadel::default()),
        ]))
        .unwrap();
    let (mut served, mut seen) = (0, 0);
    for (path, item) in spec["paths"].as_object().unwrap() {
        let Some(rel) = path.strip_prefix("/modules/citadel/v1") else {
            continue;
        };
        let Some(op) = item.get("get") else { continue };
        if op["x-ainkrad-scope"].as_str() != Some("read") {
            continue;
        }
        for id in [company, account] {
            let uri = rel.replace("{id}", &id.to_string());
            if uri.contains('{') {
                continue;
            }
            let (s, body) = call(&fx, Some(&phone), Method::GET, &uri, None).await;
            assert!(!s.is_server_error(), "{uri}: {s}");
            served += usize::from(s == StatusCode::OK);
            seen += 1;
            let text = body.to_string();
            for leak in [
                SECRET,
                "runner-1",
                "accounts/main",
                "TOPSECRET",
                "\"secret_name\"",
            ] {
                assert!(!text.contains(leak), "GET {uri} leaks {leak}: {text}");
            }
        }
    }
    assert!(
        seen >= 20 && served >= 10,
        "{served} served of {seen} reads"
    );
}
