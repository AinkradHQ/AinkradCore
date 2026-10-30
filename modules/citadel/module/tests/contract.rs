//! The module's routes in the Core contract: `json_for` with Citadel merges its paths under
//! `/modules/citadel/v1`, each with the scope the gate enforces. `modules/citadel/api/openapi.core.json`
//! is that merged contract, committed; `make contract` regenerates it
//! (`cargo run --example contract`), and this test fails while it is stale.

use std::sync::Arc;

use ainkrad_core_server::api::v1::spec::json_for;
use ainkrad_core_server::module::Module;
use citadel_module::Citadel;
use serde_json::Value;

fn merged() -> String {
    json_for(&[Arc::new(Citadel) as Arc<dyn Module>])
}

#[test]
fn module_paths_are_in_the_contract_with_scopes_and_destructive_marks() {
    let spec: Value = serde_json::from_str(&merged()).unwrap();
    let p = &spec["paths"];
    let op = |path: &str, m: &str| p[format!("/modules/citadel/v1{path}")][m].clone();
    assert_eq!(op("/companies", "get")["x-ainkrad-scope"], "read");
    assert_eq!(op("/companies", "post")["x-ainkrad-scope"], "admin");
    assert_eq!(
        op("/departments/{id}", "delete")["x-ainkrad-destructive"],
        true
    );
    assert!(
        op("/departments/{id}", "put")
            .get("x-ainkrad-destructive")
            .is_none()
    );
    assert_eq!(
        op("/companies", "get")["operationId"],
        "citadelListCompanies"
    );
    assert!(spec["components"]["schemas"]["Company"].is_object());
    // The platform's own paths are untouched.
    assert_eq!(p["/api/v1/me"]["get"]["x-ainkrad-scope"], "read");
}

#[test]
fn the_committed_merged_contract_is_current() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../api/openapi.core.json");
    let current = merged();
    if std::env::var_os("UPDATE_CONTRACT").is_some() {
        std::fs::write(path, &current).unwrap();
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        committed == current,
        "modules/citadel/api/openapi.core.json is stale: run `make contract`"
    );
}
