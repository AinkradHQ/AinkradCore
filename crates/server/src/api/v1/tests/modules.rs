//! A toy module loads through `Module` (E1-02.2) and sits behind the client gate.

use std::sync::Arc;

use axum::Router;
use axum::http::{Method, StatusCode};
use axum::routing::get;

use super::{fx, req, send};
use crate::api::App;
use crate::module::Module;

struct Ops;

impl Module for Ops {
    fn id(&self) -> &'static str {
        "ops"
    }

    fn routes(&self) -> Router<App> {
        Router::new().route("/ping", get(|| async { "pong" }))
    }
}

const PING: &str = "/modules/ops/v1/ping";

#[tokio::test]
async fn a_mounted_module_answers_behind_the_signature() {
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Ops) as Arc<dyn Module>]);

    let res = send(&fx.app, req(Method::GET, PING, Some(&fx.dev), None)).await;
    assert_eq!(res.0, StatusCode::OK);

    let stranger = fx.stranger();
    let (status, _) = send(&fx.app, req(Method::GET, PING, Some(&stranger), None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the gate covers module routes"
    );
}

#[tokio::test]
async fn an_unmounted_module_has_no_routes_and_no_scope() {
    let fx = fx().await;
    let (status, _) = send(&fx.app, req(Method::GET, PING, Some(&fx.dev), None)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "no module, no declared scope"
    );
}

/// A terminal module: opening a terminal is destructive (E1-09.3's "done when", spec §8).
struct Term;

impl Module for Term {
    fn id(&self) -> &'static str {
        "term"
    }

    fn routes(&self) -> Router<App> {
        let open = axum::routing::post(|| async { "opened" });
        Router::new()
            .route("/terminals/{id}/open", open)
            .route("/terminals", get(|| async { "[]" }))
    }

    fn scope(&self) -> &'static str {
        "terminal"
    }

    fn destructive(&self) -> &'static [(&'static str, &'static str)] {
        &[("POST", "/terminals/{id}/open")]
    }
}

#[tokio::test]
async fn an_unelevated_terminal_open_is_refused_and_an_elevated_one_passes() {
    let mut fx = fx().await;
    fx.app.modules = Arc::from([Arc::new(Term) as Arc<dyn Module>]);
    let mac = super::stepup::plain(&fx, "mac", &super::ALL, true).await;
    let open = "/modules/term/v1/terminals/t1/open";
    let (status, body) = send(&fx.app, req(Method::POST, open, Some(&mac), None)).await;
    assert_eq!(
        (status, &body["code"]),
        (
            StatusCode::FORBIDDEN,
            &serde_json::json!("step_up_required")
        )
    );
    let list = "/modules/term/v1/terminals";
    let (status, _) = send(&fx.app, req(Method::GET, list, Some(&mac), None)).await;
    assert_eq!(status, StatusCode::OK, "a read needs no step-up");
    assert_eq!(super::stepup::step_up(&fx, &mac).await.0, StatusCode::OK);
    let (status, _) = send(&fx.app, req(Method::POST, open, Some(&mac), None)).await;
    assert_eq!(status, StatusCode::OK);
    // A device without the module's scope is refused before elevation is even asked.
    let phone = fx.enroll("phone", &["read"]).await;
    let (status, body) = send(&fx.app, req(Method::POST, open, Some(&phone), None)).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &serde_json::json!("forbidden_scope"))
    );
}
