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
async fn an_unmounted_module_has_no_routes() {
    let fx = fx().await;
    let (status, _) = send(&fx.app, req(Method::GET, PING, Some(&fx.dev), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
