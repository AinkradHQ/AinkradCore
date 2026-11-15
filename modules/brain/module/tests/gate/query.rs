//! The server refuses a query name a module does not declare in `Module::query_names`. The Inbox
//! shipped broken because no test sent its names through that guard.

use ainkrad_core_server::api::v1::{QUERY, scopes::module_query_ok};
use ainkrad_core_server::module::Module;
use axum::http::{Method, StatusCode};
use brain_module::Brain;
use std::sync::Arc;

use super::common::*;

/// Every query name the App sends on Brain routes (AinkradCoreApp `Packages/Features/.../Brain`).
const APP_NAMES: &[&str] = &["q", "room", "mode", "status", "limit", "after"];

#[tokio::test]
async fn every_query_name_the_app_sends_passes_the_guard_and_an_unknown_one_does_not() {
    let fx = fx().await;
    let path = "/rooms/nope/inbox";
    for n in APP_NAMES {
        let (st, v) = call(&fx, &fx.admin, Method::GET, &format!("{path}?{n}=1"), None).await;
        let why = v["message"].as_str().unwrap_or_default();
        assert!(
            !(st == StatusCode::BAD_REQUEST && why.contains("not allowed")),
            "`{n}` was refused: {v}"
        );
    }
    let (st, v) = call(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("{path}?bogus=1"),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("not allowed"),
        "{v}"
    );
}

#[test]
fn every_query_parameter_the_openapi_declares_is_allowed() {
    let path = format!("{}/../api/openapi.core.json", env!("CARGO_MANIFEST_DIR"));
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Brain::default())];
    let mut refused = vec![];
    for (route, ops) in doc["paths"].as_object().unwrap() {
        for op in ops.as_object().unwrap().values() {
            for p in op["parameters"].as_array().into_iter().flatten() {
                let name = p["name"].as_str().unwrap();
                if p["in"] == "query"
                    && !QUERY.contains(&name)
                    && !module_query_ok(&modules, "/modules/brain/v1/x", &format!("{name}=1"))
                {
                    refused.push(format!("{route}: {name}"));
                }
            }
        }
    }
    assert!(refused.is_empty(), "not in query_names: {refused:?}");
}
