//! The mounted router and the OpenAPI document must list the same operations (re-audit M-02).
//! Every classification test walks the document, so a handler mounted with `.route(..)` but
//! with no `#[utoipa::path]` would otherwise get the module default (`admin`, no step-up) unseen.
//! Paths: the `.route("..")` literals under `src/api` against the document. Methods: a probe of
//! the live router, which answers 405 for exactly the methods a path does not mount.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use ainkrad_core_server::module::Module;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use citadel_module::Citadel;
use tower::ServiceExt;
use common::*;
use serde_json::{Value, json};

fn literals(dir: &Path, out: &mut BTreeSet<String>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            literals(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let text = std::fs::read_to_string(&p).unwrap();
            // Test modules at the end of a file are not the router.
            let text = text.split("#[cfg(test)]").next().unwrap();
            for part in text.split(".route(").skip(1) {
                let rest = part.trim_start().strip_prefix('"').unwrap_or_else(|| {
                    panic!(
                        "{}: a `.route(` whose first argument is not a literal",
                        p.display()
                    )
                });
                out.insert(rest.split('"').next().unwrap().to_owned());
            }
        }
    }
}

fn documented() -> Vec<(String, Vec<Method>)> {
    let spec: Value = serde_json::from_str(&ainkrad_core_server::api::v1::spec::json_for(&[
        std::sync::Arc::new(citadel_module::Citadel::default()),
    ]))
    .unwrap();
    spec["paths"]
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(p, item)| {
            let rel = p.strip_prefix("/modules/citadel/v1")?;
            let methods = item
                .as_object()
                .unwrap()
                .keys()
                .filter_map(|m| m.to_uppercase().parse().ok())
                .collect();
            Some((rel.to_owned(), methods))
        })
        .collect()
}

#[test]
fn the_router_mounts_exactly_the_documented_paths() {
    let mut mounted = BTreeSet::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    literals(&root, &mut mounted);
    let docs: BTreeSet<String> = documented().into_iter().map(|(p, _)| p).collect();
    let undocumented: Vec<_> = mounted.difference(&docs).collect();
    let unmounted: Vec<_> = docs.difference(&mounted).collect();
    assert!(
        undocumented.is_empty(),
        "routes mounted without a #[utoipa::path]: {undocumented:?}"
    );
    assert!(
        unmounted.is_empty(),
        "documented paths the router does not mount: {unmounted:?}"
    );
}

#[tokio::test]
async fn each_path_answers_405_for_exactly_the_undocumented_methods() {
    // The module's router alone (no gate, so no rate limit): 405 is the method router's answer.
    let fx = fx().await;
    let router = Citadel::default().routes().with_state(fx.app.clone());
    for (path, methods) in documented() {
        let uri = path
            .replace("{unit}", "tokens")
            .replace("{window_secs}", "60");
        let uri = uri
            .split('/')
            .map(|s| if s.starts_with('{') { "1" } else { s })
            .collect::<Vec<_>>()
            .join("/");
        for m in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            let body = (m != Method::GET && m != Method::DELETE).then(|| json!({}));
            let mut req = Request::builder().method(m.clone()).uri(&uri);
            let bytes = body.map(|b| b.to_string()).unwrap_or_default();
            if !bytes.is_empty() {
                req = req.header("content-type", "application/json");
            }
            let s = router.clone().oneshot(req.body(Body::from(bytes)).unwrap()).await.unwrap().status();
            assert_eq!(
                s == StatusCode::METHOD_NOT_ALLOWED,
                !methods.contains(&m),
                "{m} {path}: {s}"
            );
        }
    }
}
